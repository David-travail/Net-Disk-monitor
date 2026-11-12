//! Moteur NetDiskMonitor : surveille les disques et la table ARP, puis expose
//! l'état et les commandes de configuration au client sur une connexion TCP locale.
//!
//! Fonctions :
//! - `main` : initialise l'état, lance les surveillances et accepte les clients.
//! - `load_config` : charge `config.toml` ou le crée avec les valeurs par défaut.
//! - `validate_config` : vérifie que les intervalles et le seuil sont valides.
//! - `monitor_disks` : actualise périodiquement les informations des disques.
//! - `monitor_network` : actualise les appareils ARP et signale les nouveaux appareils.
//! - `read_network_devices` : lit la table ARP de la plateforme.
//! - `parse_arp_table` : convertit le texte ARP en appareils.
//! - `is_mac_address` : valide le format d'une adresse MAC.
//! - `handle_client` : traite une requête JSON et écrit sa réponse.
//! - `parses_linux_and_windows_arp_entries` : teste l'analyse de lignes ARP.

use common::{
    Config, DeviceDetails, DiskDetails, LargeFileDetails, MessageClientToEngine,
    MessageEngineToClient,
};
use std::{collections::HashSet, error::Error, net::IpAddr, path::Path, time::Duration};
use sysinfo::Disks;
#[cfg(target_os = "linux")]
use tokio::fs;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{watch, RwLock},
    time::sleep,
};

const CONFIG_PATH: &str = "config.toml";

#[derive(Default)]
struct Snapshot {
    disks: Vec<DiskDetails>,
    devices: Vec<DeviceDetails>,
    large_files: Vec<LargeFileDetails>,
}

struct EngineState {
    snapshot: RwLock<Snapshot>,
    config: watch::Sender<Config>,
    http_client: reqwest::Client,
}

#[tokio::main]
/// Démarre les tâches de surveillance et le serveur TCP local.
///
/// Entrées : arguments de ligne de commande ignorés.
/// Sortie : `Ok(())` en cas d'arrêt normal, ou une erreur si le serveur ne peut pas démarrer.
async fn main() -> Result<(), Box<dyn Error>> {
    let config = load_config()?;
    let listen_address = config.adresse_ecoute_moteur.clone();
    let (config_tx, _) = watch::channel(config);
    let state = std::sync::Arc::new(EngineState {
        snapshot: RwLock::new(Snapshot::default()),
        config: config_tx,
        http_client: reqwest::Client::builder().build()?,
    });

    tokio::spawn(monitor_disks(state.clone()));
    tokio::spawn(monitor_network(state.clone()));

    let listener = TcpListener::bind(&listen_address).await?;
    println!("Moteur NetDiskMonitor en écoute sur {listen_address}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_client(stream, state).await {
                        eprintln!("Erreur de communication avec le client : {error}");
                    }
                });
            }
            Err(error) => eprintln!("Impossible d'accepter une connexion : {error}"),
        }
    }
}

/// Charge la configuration depuis `config.toml`, ou crée ce fichier avec les intervalles par défaut.
///
/// Entrées : aucune ; le chemin du fichier est défini par `CONFIG_PATH`.
/// Sortie : configuration validée, ou erreur explicite de lecture, d'écriture ou de syntaxe.
fn load_config() -> Result<Config, Box<dyn Error>> {
    let contents = match std::fs::read_to_string(CONFIG_PATH) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let defaults = Config::default();
            let contents = toml::to_string_pretty(&defaults)?;
            std::fs::write(CONFIG_PATH, &contents)?;
            contents
        }
        Err(error) => return Err(error.into()),
    };

    let config: Config = toml::from_str(&contents)?;
    validate_config(&config)?;
    Ok(config)
}

/// Vérifie les valeurs de configuration avant leur utilisation par les tâches.
///
/// Entrées : `config`, configuration à examiner.
/// Sortie : `Ok(())` si elle est valide, sinon une erreur indiquant le réglage invalide.
fn validate_config(config: &Config) -> Result<(), Box<dyn Error>> {
    config.validate().map_err(Into::into)
}

/// Actualise l'état des partitions selon la configuration courante.
///
/// Entrées : `state`, état partagé contenant la configuration et l'instantané du moteur.
/// Sortie : aucune ; la tâche s'exécute jusqu'à la fermeture du canal de configuration.
async fn monitor_disks(state: std::sync::Arc<EngineState>) {
    let mut config_rx = state.config.subscribe();
    let mut alerted_disks = HashSet::new();
    let mut unconfigured_alerts = HashSet::new();

    loop {
        let config = config_rx.borrow().clone();
        if config.activer_surveillance_disque {
            let disks: Vec<DiskDetails> = Disks::new_with_refreshed_list()
                .iter()
                .map(|disk| {
                    let total_bytes = disk.total_space();
                    DiskDetails {
                        name: disk.mount_point().to_string_lossy().into_owned(),
                        total_bytes,
                        used_bytes: total_bytes.saturating_sub(disk.available_space()),
                    }
                })
                .collect();
            let current_disk_names: HashSet<_> =
                disks.iter().map(|disk| disk.name.clone()).collect();
            for disk in &disks {
                let percent = if disk.total_bytes == 0 {
                    0.0
                } else {
                    disk.used_bytes as f64 / disk.total_bytes as f64 * 100.0
                };
                if percent >= f64::from(config.seuil_alerte_disque_pourcentage) {
                    if config.jeton_bot_telegram.is_empty()
                        || config.identifiant_chat_telegram.is_empty()
                    {
                        if unconfigured_alerts.insert(disk.name.clone()) {
                            eprintln!(
                                "[Telegram] Seuil disque atteint sur {} ({percent:.1} %), mais Telegram n'est pas configuré.",
                                disk.name
                            );
                        }
                    } else if !alerted_disks.contains(&disk.name) {
                        match send_telegram_alert(&state.http_client, &config, disk, percent).await
                        {
                            Ok(()) => {
                                alerted_disks.insert(disk.name.clone());
                                unconfigured_alerts.remove(&disk.name);
                            }
                            Err(error) => {
                                eprintln!(
                                    "[Telegram] Échec d'envoi de l'alerte pour {} : {error}",
                                    disk.name
                                );
                            }
                        }
                    }
                } else {
                    alerted_disks.remove(&disk.name);
                    unconfigured_alerts.remove(&disk.name);
                }
            }
            alerted_disks.retain(|name| current_disk_names.contains(name));
            unconfigured_alerts.retain(|name| current_disk_names.contains(name));
            state.snapshot.write().await.disks = disks;
        } else {
            state.snapshot.write().await.disks.clear();
            alerted_disks.clear();
            unconfigured_alerts.clear();
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(config.intervalle_scrutation_disque_secondes.max(1))) => {}
            result = config_rx.changed() => {
                if result.is_err() {
                    return;
                }
            }
        }
    }
}

/// Envoie une seule alerte de franchissement du seuil au bot Telegram configuré.
async fn send_telegram_alert(
    client: &reqwest::Client,
    config: &Config,
    disk: &DiskDetails,
    percent: f64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        config.jeton_bot_telegram
    );
    let text = format!(
        "Alerte NetDiskMonitor : le disque {} est occupé à {:.1} % (seuil : {:.1} %).",
        disk.name, percent, config.seuil_alerte_disque_pourcentage
    );
    tokio::time::timeout(
        Duration::from_secs(config.delai_http_telegram_secondes),
        async {
            client
                .post(url)
                .json(&serde_json::json!({
                    "chat_id": config.identifiant_chat_telegram,
                    "text": text,
                }))
                .send()
                .await
                .map_err(|error| error.without_url())?
                .error_for_status()
                .map_err(|error| error.without_url())?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        },
    )
    .await
    .map_err(|_| "Délai d'attente Telegram dépassé")??;
    Ok(())
}

/// Recherche les plus gros fichiers des volumes disponibles sans suivre les liens symboliques.
fn scan_large_files(
    minimum_size_bytes: u64,
    maximum_files: usize,
) -> Result<Vec<LargeFileDetails>, Box<dyn Error + Send + Sync>> {
    let disks = Disks::new_with_refreshed_list();
    let mut files = Vec::new();
    let mut scanned_roots = 0;

    for disk in disks.iter() {
        let root = disk.mount_point();
        let previous_count = scanned_roots;
        visit_directory(root, minimum_size_bytes, &mut files, &mut scanned_roots);
        if scanned_roots == previous_count {
            eprintln!("[Analyse] Impossible de lire le volume {}", root.display());
        }
    }

    if scanned_roots == 0 {
        return Err("Aucun volume n'a pu être analysé.".into());
    }

    files.sort_unstable_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    let mut unique_paths = HashSet::new();
    files.retain(|file| unique_paths.insert(file.path.clone()));
    files.truncate(maximum_files);
    Ok(files)
}

fn visit_directory(
    path: &Path,
    minimum_size_bytes: u64,
    files: &mut Vec<LargeFileDetails>,
    scanned_roots: &mut usize,
) {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => {
            *scanned_roots += 1;
            entries
        }
        Err(error) => {
            eprintln!(
                "[Analyse] Lecture impossible de {} : {error}",
                path.display()
            );
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!(
                    "[Analyse] Entrée illisible dans {} : {error}",
                    path.display()
                );
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                eprintln!(
                    "[Analyse] Type inaccessible pour {} : {error}",
                    entry.path().display()
                );
                continue;
            }
        };

        if file_type.is_dir() {
            visit_directory(&entry.path(), minimum_size_bytes, files, scanned_roots);
        } else if file_type.is_file() {
            match entry.metadata() {
                Ok(metadata) if metadata.len() >= minimum_size_bytes => {
                    files.push(LargeFileDetails {
                        path: entry.path().to_string_lossy().into_owned(),
                        size_bytes: metadata.len(),
                    });
                }
                Ok(_) => {}
                Err(error) => eprintln!(
                    "[Analyse] Métadonnées inaccessibles pour {} : {error}",
                    entry.path().display()
                ),
            }
        }
    }
}

/// Supprime uniquement les fichiers réguliers présents dans le dernier résultat d'analyse.
async fn delete_selected_files(
    state: &std::sync::Arc<EngineState>,
    paths: Vec<String>,
) -> MessageEngineToClient {
    let maximum_files = state.config.borrow().nombre_max_fichiers_volumineux;
    if paths.is_empty() || paths.len() > maximum_files {
        return MessageEngineToClient::FilesDeleted {
            success: false,
            message: format!(
                "Sélection invalide : choisissez entre 1 et {maximum_files} fichiers."
            ),
        };
    }

    let candidates: HashSet<_> = state
        .snapshot
        .read()
        .await
        .large_files
        .iter()
        .map(|file| file.path.clone())
        .collect();
    let mut unique_paths = HashSet::new();
    let mut deleted_paths = Vec::new();
    let mut errors = Vec::new();

    for path in paths {
        if !unique_paths.insert(path.clone()) {
            continue;
        }
        if !candidates.contains(&path) || !Path::new(&path).is_absolute() {
            errors.push(format!(
                "{path} : fichier absent du dernier résultat d'analyse"
            ));
            continue;
        }

        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if let Err(error) = std::fs::remove_file(&path) {
                    errors.push(format!("{path} : {error}"));
                } else {
                    deleted_paths.push(path);
                }
            }
            Ok(_) => errors.push(format!("{path} : ce n'est pas un fichier régulier")),
            Err(error) => errors.push(format!("{path} : {error}")),
        }
    }

    if !deleted_paths.is_empty() {
        let deleted: HashSet<_> = deleted_paths.iter().cloned().collect();
        state
            .snapshot
            .write()
            .await
            .large_files
            .retain(|file| !deleted.contains(&file.path));
    }
    for error in &errors {
        eprintln!("[Suppression] {error}");
    }

    let success = errors.is_empty() && !deleted_paths.is_empty();
    let message = if errors.is_empty() {
        format!("{} fichier(s) supprimé(s).", deleted_paths.len())
    } else {
        format!(
            "{} fichier(s) supprimé(s), {} échec(s) : {}",
            deleted_paths.len(),
            errors.len(),
            errors
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        )
    };
    MessageEngineToClient::FilesDeleted { success, message }
}

/// Actualise les appareils présents dans la table ARP à l'intervalle configuré.
///
/// Entrées : `state`, état partagé contenant la configuration et l'instantané du moteur.
/// Sortie : aucune ; les erreurs de lecture sont journalisées et la tâche continue.
async fn monitor_network(state: std::sync::Arc<EngineState>) {
    let mut config_rx = state.config.subscribe();

    loop {
        let config = config_rx.borrow().clone();
        if config.activer_surveillance_reseau {
            match read_network_devices().await {
                Ok(devices) => {
                    let mut snapshot = state.snapshot.write().await;
                    let known: HashSet<_> = snapshot
                        .devices
                        .iter()
                        .map(|device| (device.ip.clone(), device.mac.clone()))
                        .collect();
                    for device in &devices {
                        if !known.contains(&(device.ip.clone(), device.mac.clone())) {
                            println!("[Réseau] Appareil détecté : {} ({})", device.ip, device.mac);
                        }
                    }
                    snapshot.devices = devices;
                }
                Err(error) => eprintln!("[Réseau] Échec de lecture des appareils : {error}"),
            }
        } else {
            state.snapshot.write().await.devices.clear();
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(config.intervalle_scrutation_reseau_secondes.max(1))) => {}
            result = config_rx.changed() => {
                if result.is_err() {
                    return;
                }
            }
        }
    }
}

/// Lit les entrées ARP depuis la source spécifique au système d'exploitation.
///
/// Entrées : aucune.
/// Sortie : liste d'appareils détectés ou erreur de lecture, de décodage ou de plateforme.
async fn read_network_devices() -> Result<Vec<DeviceDetails>, Box<dyn Error + Send + Sync>> {
    #[cfg(target_os = "windows")]
    let arp_table = {
        let output = tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await?;
        if !output.status.success() {
            return Err(format!("arp -a a échoué avec le statut {}", output.status).into());
        }
        String::from_utf8(output.stdout)?
    };

    #[cfg(target_os = "linux")]
    let arp_table = fs::read_to_string("/proc/net/arp").await?;

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let arp_table: String =
        return Err("La lecture ARP n'est pas prise en charge sur cet OS.".into());

    Ok(parse_arp_table(&arp_table))
}

/// Analyse des lignes d'une table ARP et conserve les paires IP/MAC valides.
///
/// Entrées : `contents`, texte brut de la table ARP.
/// Sortie : appareils extraits, avec nom d'hôte absent lorsque la table n'en fournit pas.
fn parse_arp_table(contents: &str) -> Vec<DeviceDetails> {
    let mut devices = Vec::new();
    for line in contents.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let ip = fields.iter().find_map(|field| field.parse::<IpAddr>().ok());
        let mac = fields.iter().find(|field| is_mac_address(field));

        if let (Some(ip), Some(mac)) = (ip, mac) {
            if !ip.is_unspecified() && !ip.is_multicast() {
                devices.push(DeviceDetails {
                    ip: ip.to_string(),
                    mac: mac.to_ascii_lowercase().replace('-', ":"),
                    hostname: None,
                });
            }
        }
    }
    devices
}

/// Vérifie qu'une chaîne représente une adresse MAC composée de six octets hexadécimaux.
///
/// Entrées : `value`, adresse candidate séparée par `:` ou `-`.
/// Sortie : `true` si le format est valide, sinon `false`.
fn is_mac_address(value: &str) -> bool {
    let separator = if value.contains(':') { ':' } else { '-' };
    let parts: Vec<_> = value.split(separator).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Lit une requête JSON du client, l'exécute et renvoie une réponse JSON sur la connexion.
///
/// Entrées : `stream`, connexion TCP du client ; `state`, état partagé du moteur.
/// Sortie : `Ok(())` après l'envoi de la réponse, ou une erreur d'entrée/sortie ou de sérialisation.
async fn handle_client(
    stream: TcpStream,
    state: std::sync::Arc<EngineState>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let response = match serde_json::from_str::<MessageClientToEngine>(&line) {
        Ok(MessageClientToEngine::GetStatus) => {
            let snapshot = state.snapshot.read().await;
            MessageEngineToClient::StatusSnapshot {
                disk_info: snapshot.disks.clone(),
                connected_devices: snapshot.devices.clone(),
                seuil_alerte_disque_pourcentage: state
                    .config
                    .borrow()
                    .seuil_alerte_disque_pourcentage,
            }
        }
        Ok(MessageClientToEngine::ScanLargeFiles) => {
            let config = state.config.borrow().clone();
            let minimum_size_bytes = config.taille_min_fichier_volumineux_mio * 1024 * 1024;
            let maximum_files = config.nombre_max_fichiers_volumineux;
            match tokio::task::spawn_blocking(move || {
                scan_large_files(minimum_size_bytes, maximum_files)
            })
            .await
            {
                Ok(Ok(files)) => {
                    state.snapshot.write().await.large_files = files.clone();
                    MessageEngineToClient::LargeFilesSnapshot { files }
                }
                Ok(Err(error)) => MessageEngineToClient::ActionResult {
                    success: false,
                    message: format!("Échec de l'analyse des disques : {error}"),
                },
                Err(error) => MessageEngineToClient::ActionResult {
                    success: false,
                    message: format!("La tâche d'analyse a échoué : {error}"),
                },
            }
        }
        Ok(MessageClientToEngine::UpdateConfig(config)) => match validate_config(&config) {
            Ok(()) => {
                state.config.send_replace(config);
                MessageEngineToClient::ActionResult {
                    success: true,
                    message: "Configuration mise à jour.".into(),
                }
            }
            Err(error) => MessageEngineToClient::ActionResult {
                success: false,
                message: format!("Configuration invalide : {error}"),
            },
        },
        Ok(MessageClientToEngine::DeleteFiles { paths }) => {
            delete_selected_files(&state, paths).await
        }
        Err(error) => MessageEngineToClient::ActionResult {
            success: false,
            message: format!("Requête JSON invalide : {error}"),
        },
    };

    let mut encoded = serde_json::to_vec(&response)?;
    encoded.push(b'\n');
    write_half.write_all(&encoded).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{delete_selected_files, parse_arp_table, validate_config, EngineState, Snapshot};
    use common::{Config, LargeFileDetails, MessageEngineToClient};
    use std::{sync::Arc, time::SystemTime};
    use tokio::sync::{watch, RwLock};

    #[test]
    /// Vérifie que le fichier de paramètres ne doit préciser que les intervalles de scrutation.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si les intervalles ou valeurs par défaut sont incorrects.
    fn config_file_contains_all_settings_and_validates() {
        let config: Config =
            toml::from_str(include_str!("../../config.toml")).expect("parse config file");

        assert_eq!(config.intervalle_scrutation_disque_secondes, 60);
        assert_eq!(config.intervalle_scrutation_reseau_secondes, 30);
        assert_eq!(config.seuil_alerte_disque_pourcentage, 85.0);
        assert_eq!(config.taille_min_fichier_volumineux_mio, 100);
        assert_eq!(config.nombre_max_fichiers_volumineux, 100);
        assert_eq!(config.intervalle_actualisation_ihm_secondes, 3);
        assert!(config.activer_surveillance_disque);
        assert!(config.activer_surveillance_reseau);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn generated_default_config_contains_all_settings() {
        let serialized = toml::to_string_pretty(&Config::default()).expect("serialize defaults");
        let config: Config = toml::from_str(&serialized).expect("parse generated defaults");

        assert!(config.validate().is_ok());
        assert_eq!(config.seuil_alerte_disque_pourcentage, 85.0);
        assert_eq!(config.nombre_max_fichiers_volumineux, 100);
        assert_eq!(config.adresse_ecoute_moteur, "127.0.0.1:7878");
    }

    #[test]
    /// Vérifie qu'une configuration avec un intervalle nul est rejetée.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si la configuration invalide est acceptée.
    fn rejects_zero_polling_interval() {
        let config = Config {
            intervalle_scrutation_disque_secondes: 0,
            ..Config::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    /// Vérifie qu'un seuil hors de la plage de pourcentage est rejeté.
    fn rejects_invalid_disk_threshold() {
        let config = Config {
            seuil_alerte_disque_pourcentage: 101.0,
            ..Config::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[tokio::test]
    /// Vérifie que le moteur supprime les candidats sélectionnés, mais refuse les autres chemins.
    async fn deletes_only_files_from_the_latest_scan() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "net-disk-monitor-delete-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create test directory");
        let candidate_path = directory.join("candidate.bin");
        let other_path = directory.join("other.bin");
        std::fs::write(&candidate_path, b"candidate").expect("create candidate");
        std::fs::write(&other_path, b"other").expect("create other file");

        let (config, _) = watch::channel(Config::default());
        let state = Arc::new(EngineState {
            snapshot: RwLock::new(Snapshot {
                large_files: vec![LargeFileDetails {
                    path: candidate_path.to_string_lossy().into_owned(),
                    size_bytes: 100,
                }],
                ..Snapshot::default()
            }),
            config,
            http_client: reqwest::Client::new(),
        });
        let response = delete_selected_files(
            &state,
            vec![
                candidate_path.to_string_lossy().into_owned(),
                other_path.to_string_lossy().into_owned(),
            ],
        )
        .await;

        assert!(matches!(
            response,
            MessageEngineToClient::FilesDeleted { success: false, .. }
        ));
        assert!(!candidate_path.exists());
        assert!(other_path.exists());
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    /// Vérifie que les formats ARP courants sous Linux et Windows sont reconnus.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si les appareils analysés ne correspondent pas aux attentes.
    fn parses_linux_and_windows_arp_entries() {
        let contents = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.10     0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0
  192.168.1.11          aa-bb-cc-dd-ee-00     dynamic
";

        let devices = parse_arp_table(contents);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].ip, "192.168.1.10");
        assert_eq!(devices[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(devices[1].ip, "192.168.1.11");
    }
}
