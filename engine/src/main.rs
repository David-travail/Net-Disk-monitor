//! Moteur NetDiskMonitor : surveille les disques et la table ARP, puis expose
//! l'état et les commandes de configuration au client sur une connexion TCP locale.
//!
//! Fonctions :
//! - `main` : initialise l'état, lance les surveillances et accepte les clients.
//! - `load_config` : charge `config.toml` ou le crée avec les valeurs par défaut.
//! - `validate_config` : vérifie que les intervalles et le seuil sont valides.
//! - `monitor_disks` : actualise périodiquement les informations des disques.
//! - `monitor_network` : suit les appareils et journalise connexions/déconnexions.
//! - `resolve_hostname` : retrouve le nom d'une machine (mDNS puis DNS inverse).
//! - `mdns_reverse_lookup` : interroge un appareil en mDNS pour obtenir son nom.
//! - `load_aliases` / `save_aliases` : lisent et écrivent `noms_appareils.toml`.
//! - `set_device_alias` : associe un nom personnalisé à une adresse MAC.
//! - `log_network_event` : écrit un événement dans `network_events.log` et le renvoie.
//! - `run_macos_arp` : exécute `arp` sous macOS.
//! - `keep_confirmed_macos_entries` : écarte les entrées ARP macOS expirées.
//! - `lan_ipv4_networks` : liste les réseaux locaux (hors VPN et interfaces virtuelles).
//! - `subnet_hosts` : calcule les adresses à balayer d'un sous-réseau.
//! - `read_network_devices` : balaye les réseaux locaux puis lit la table ARP.
//! - `normalize_mac` : normalise une adresse MAC.
//! - `parse_arp_table` : convertit le texte ARP en appareils.
//! - `send_telegram_message` : envoie un message au chat Telegram configuré.
//! - `spawn_new_device_alert` : alerte Telegram à l'arrivée d'un appareil inconnu.
//! - `set_monitoring` : active ou désactive les surveillances à chaud.
//! - `handle_client` : traite une requête JSON et écrit sa réponse.
//! - `parses_linux_and_windows_arp_entries` : teste l'analyse de lignes ARP.

use common::{
    Config, DeviceDetails, DiskDetails, LargeFileDetails, MessageClientToEngine,
    MessageEngineToClient, NetworkEventDetails, NetworkEventKind, MAX_ALIAS_CHARS,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::Path,
    time::Duration,
};
use sysinfo::Disks;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{watch, RwLock},
    time::sleep,
};

const CONFIG_PATH: &str = "config.toml";
/// Fichier des noms personnalisés d'appareils (adresse MAC -> nom).
const ALIASES_PATH: &str = "noms_appareils.toml";
/// Délai maximal accordé à un client pour envoyer sa requête.
const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Taille maximale d'une requête JSON reçue d'un client.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
struct Snapshot {
    disks: Vec<DiskDetails>,
    devices: Vec<DeviceDetails>,
    large_files: Vec<LargeFileDetails>,
    /// Derniers mouvements réseau, limités à `MAX_NETWORK_EVENTS`.
    events: Vec<NetworkEventDetails>,
}

/// Nombre maximal de mouvements réseau conservés pour l'IHM.
const MAX_NETWORK_EVENTS: usize = 100;

struct EngineState {
    snapshot: RwLock<Snapshot>,
    config: watch::Sender<Config>,
    http_client: reqwest::Client,
    /// Noms personnalisés, indexés par adresse MAC normalisée.
    aliases: RwLock<HashMap<String, String>>,
}

/// Contenu de `noms_appareils.toml`.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct AliasFile {
    #[serde(default)]
    noms: BTreeMap<String, String>,
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
        aliases: RwLock::new(load_aliases()),
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

/// Charge les noms personnalisés depuis `noms_appareils.toml`.
///
/// Sortie : table MAC -> nom ; vide si le fichier est absent ou illisible (erreur signalée).
fn load_aliases() -> HashMap<String, String> {
    let contents = match std::fs::read_to_string(ALIASES_PATH) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(error) => {
            eprintln!("[Noms] Lecture de {ALIASES_PATH} impossible : {error}");
            return HashMap::new();
        }
    };
    match toml::from_str::<AliasFile>(&contents) {
        Ok(file) => file
            .noms
            .into_iter()
            .filter_map(|(mac, alias)| {
                let alias = alias.trim().to_owned();
                Some((normalize_mac(&mac)?, alias)).filter(|(_, alias)| !alias.is_empty())
            })
            .collect(),
        Err(error) => {
            eprintln!("[Noms] Fichier {ALIASES_PATH} invalide : {error}");
            HashMap::new()
        }
    }
}

/// Enregistre les noms personnalisés dans `noms_appareils.toml` (écriture puis renommage).
fn save_aliases(aliases: &HashMap<String, String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let file = AliasFile {
        noms: aliases
            .iter()
            .map(|(mac, alias)| (mac.clone(), alias.clone()))
            .collect(),
    };
    let contents = format!(
        "# Noms personnalises des appareils du reseau local (adresse MAC = nom).\n{}",
        toml::to_string_pretty(&file)?
    );
    let temporary = format!("{ALIASES_PATH}.tmp");
    std::fs::write(&temporary, contents)?;
    std::fs::rename(&temporary, ALIASES_PATH)?;
    Ok(())
}

/// Vérifie et nettoie un nom personnalisé saisi dans l'IHM.
///
/// Sortie : le nom sans espaces superflus (vide pour une suppression), ou un message d'erreur.
fn clean_alias(alias: &str) -> Result<String, String> {
    let alias = alias.trim();
    if alias.chars().count() > MAX_ALIAS_CHARS {
        return Err(format!(
            "Le nom ne doit pas dépasser {MAX_ALIAS_CHARS} caractères."
        ));
    }
    if alias.chars().any(char::is_control) {
        return Err("Le nom ne doit pas contenir de caractère de contrôle.".to_owned());
    }
    Ok(alias.to_owned())
}

/// Associe (ou retire, si `alias` est vide) un nom personnalisé à une adresse MAC,
/// puis enregistre la table dans `noms_appareils.toml`.
async fn set_device_alias(
    state: &EngineState,
    mac: &str,
    alias: &str,
    persist: bool,
) -> MessageEngineToClient {
    let failure = |message: String| MessageEngineToClient::ActionResult {
        success: false,
        message,
    };
    let Some(mac) = normalize_mac(mac) else {
        return failure(format!("Adresse MAC invalide : {mac}"));
    };
    let alias = match clean_alias(alias) {
        Ok(alias) => alias,
        Err(message) => return failure(message),
    };

    let mut aliases = state.aliases.write().await;
    let previous = if alias.is_empty() {
        aliases.remove(&mac)
    } else {
        aliases.insert(mac.clone(), alias.clone())
    };
    if persist {
        if let Err(error) = save_aliases(&aliases) {
            // Restaure l'état précédent pour rester cohérent avec le fichier.
            match previous {
                Some(previous) => aliases.insert(mac.clone(), previous),
                None => aliases.remove(&mac),
            };
            return failure(format!(
                "Enregistrement de {ALIASES_PATH} impossible : {error}"
            ));
        }
    }
    drop(aliases);

    let message = if alias.is_empty() {
        format!("Nom personnalisé retiré pour {mac}.")
    } else {
        format!("{mac} s'appelle désormais « {alias} ».")
    };
    println!("[Noms] {message}");
    MessageEngineToClient::ActionResult {
        success: true,
        message,
    }
}

/// Applique les noms personnalisés courants à une liste d'appareils.
fn apply_aliases<'a>(
    devices: impl Iterator<Item = &'a mut DeviceDetails>,
    aliases: &HashMap<String, String>,
) {
    for device in devices {
        device.alias = aliases.get(&device.mac).cloned();
    }
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
                    if !telegram_configured(&config) {
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
    let text = format!(
        "Alerte NetDiskMonitor : le disque {} est occupé à {:.1} % (seuil : {:.1} %).",
        disk.name, percent, config.seuil_alerte_disque_pourcentage
    );
    send_telegram_message(client, config, text).await
}

/// Indique si les identifiants Telegram sont renseignés.
fn telegram_configured(config: &Config) -> bool {
    !config.jeton_bot_telegram.is_empty() && !config.identifiant_chat_telegram.is_empty()
}

/// Envoie un message texte au chat Telegram configuré, avec le délai HTTP configuré.
async fn send_telegram_message(
    client: &reqwest::Client,
    config: &Config,
    text: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        config.jeton_bot_telegram
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
///
/// Un même fichier peut être accessible par plusieurs chemins (sous macOS, `/` et
/// `/System/Volumes/Data`) : sous Unix, les dossiers et fichiers sont identifiés par leur
/// couple (périphérique, inode) pour n'être parcourus et listés qu'une fois.
fn scan_large_files(
    minimum_size_bytes: u64,
    maximum_files: usize,
) -> Result<Vec<LargeFileDetails>, Box<dyn Error + Send + Sync>> {
    let disks = Disks::new_with_refreshed_list();
    let mut scan = LargeFileScan {
        minimum_size_bytes,
        ..LargeFileScan::default()
    };
    let mut readable_roots = 0;

    for disk in disks.iter() {
        let root = disk.mount_point();
        match std::fs::metadata(root) {
            Ok(metadata) if !scan.first_visit(&metadata) => {
                // Volume déjà parcouru par un autre chemin.
                readable_roots += 1;
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!(
                    "[Analyse] Impossible de lire le volume {} : {error}",
                    root.display()
                );
                continue;
            }
        }
        if scan.visit_directory(root) {
            readable_roots += 1;
        } else {
            eprintln!("[Analyse] Impossible de lire le volume {}", root.display());
        }
    }

    if readable_roots == 0 {
        return Err("Aucun volume n'a pu être analysé.".into());
    }

    let mut files = scan.files;
    files.sort_unstable_by(|left, right| right.size_bytes.cmp(&left.size_bytes));
    let mut unique_paths = HashSet::new();
    files.retain(|file| unique_paths.insert(file.path.clone()));
    files.truncate(maximum_files);
    Ok(files)
}

/// État d'une analyse des fichiers volumineux.
#[derive(Default)]
struct LargeFileScan {
    minimum_size_bytes: u64,
    files: Vec<LargeFileDetails>,
    /// Dossiers déjà parcourus, identifiés par (périphérique, inode).
    visited_directories: HashSet<(u64, u64)>,
    /// Fichiers déjà retenus, identifiés par (périphérique, inode).
    seen_files: HashSet<(u64, u64)>,
}

/// Identité physique d'un fichier ou dossier (Unix uniquement).
#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

/// Identité physique d'un fichier ou dossier : indisponible hors Unix.
#[cfg(not(unix))]
fn file_identity(_metadata: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

impl LargeFileScan {
    /// Indique si le dossier décrit par `metadata` n'a pas encore été parcouru, et le note.
    fn first_visit(&mut self, metadata: &std::fs::Metadata) -> bool {
        file_identity(metadata).map_or(true, |key| self.visited_directories.insert(key))
    }

    /// Parcourt récursivement un dossier.
    ///
    /// Sortie : `true` si le dossier a pu être lu.
    fn visit_directory(&mut self, path: &Path) -> bool {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!(
                    "[Analyse] Lecture impossible de {} : {error}",
                    path.display()
                );
                return false;
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
            if !file_type.is_dir() && !file_type.is_file() {
                continue;
            }
            // `DirEntry::metadata` ne suit pas les liens symboliques.
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    eprintln!(
                        "[Analyse] Métadonnées inaccessibles pour {} : {error}",
                        entry.path().display()
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                if self.first_visit(&metadata) {
                    self.visit_directory(&entry.path());
                }
            } else if metadata.len() >= self.minimum_size_bytes
                && file_identity(&metadata).map_or(true, |key| self.seen_files.insert(key))
            {
                self.files.push(LargeFileDetails {
                    path: entry.path().to_string_lossy().into_owned(),
                    size_bytes: metadata.len(),
                });
            }
        }
        true
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

/// Actualise les appareils du réseau local à l'intervalle configuré et journalise
/// les connexions et déconnexions dans `network_events.log`.
///
/// Entrées : `state`, état partagé contenant la configuration et l'instantané du moteur.
/// Sortie : aucune ; les erreurs de lecture sont journalisées et la tâche continue.
async fn monitor_network(state: std::sync::Arc<EngineState>) {
    let mut config_rx = state.config.subscribe();
    // MAC -> (dernier état connu, nombre de scans consécutifs manqués)
    let mut tracked: HashMap<String, (DeviceDetails, u8)> = HashMap::new();
    let mut first_scan = true;
    let mut scan_no: u64 = 0;
    // MAC -> numéro du dernier scan où la résolution du nom a été tentée
    let mut last_attempt: HashMap<String, u64> = HashMap::new();
    // Toutes les MAC vues depuis le démarrage : seules les autres déclenchent une alerte.
    let mut ever_seen: HashSet<String> = HashSet::new();

    loop {
        let config = config_rx.borrow().clone();
        let cycle_start = tokio::time::Instant::now();
        if config.activer_surveillance_reseau {
            match read_network_devices().await {
                Ok(mut found) => {
                    scan_no += 1;

                    // Conserve le nom déjà connu d'un appareil.
                    for device in found.iter_mut() {
                        if device.hostname.is_none() {
                            if let Some((known, _)) = tracked.get(&device.mac) {
                                device.hostname = known.hostname.clone();
                            }
                        }
                    }

                    // Résout en parallèle les noms manquants (nouvel appareil, puis
                    // une nouvelle tentative tous les 10 scans).
                    let mut tasks = tokio::task::JoinSet::new();
                    for (index, device) in found.iter().enumerate() {
                        let retry = last_attempt
                            .get(&device.mac)
                            .map_or(true, |last| scan_no - *last >= 10);
                        if device.hostname.is_none() && retry {
                            last_attempt.insert(device.mac.clone(), scan_no);
                            let ip = device.ip.clone();
                            tasks.spawn(async move { (index, resolve_hostname(&ip).await) });
                        }
                    }
                    while let Some(result) = tasks.join_next().await {
                        if let Ok((index, Some(name))) = result {
                            found[index].hostname = Some(name);
                        }
                    }

                    apply_aliases(found.iter_mut(), &*state.aliases.read().await);

                    println!(
                        "[{}] [Réseau] Scan terminé : {} appareil(s)",
                        chrono::Local::now().format("%H:%M:%S"),
                        found.len()
                    );

                    let mut seen = HashSet::new();
                    let mut events = Vec::new();
                    for device in found {
                        seen.insert(device.mac.clone());
                        match tracked.get_mut(&device.mac) {
                            Some(entry) => {
                                entry.0 = device;
                                entry.1 = 0;
                            }
                            None => {
                                let kind = if first_scan {
                                    NetworkEventKind::Present
                                } else {
                                    NetworkEventKind::Connexion
                                };
                                events.push(log_network_event(kind, &device));
                                let is_new = ever_seen.insert(device.mac.clone());
                                if is_new
                                    && !first_scan
                                    && config.alerte_nouvel_appareil_telegram
                                    && telegram_configured(&config)
                                {
                                    spawn_new_device_alert(&state, &config, &device);
                                }
                                tracked.insert(device.mac.clone(), (device, 0));
                            }
                        }
                    }

                    let mut gone = Vec::new();
                    for (mac, (_, missed)) in tracked.iter_mut() {
                        if !seen.contains(mac) {
                            *missed += 1;
                            if *missed >= config.scans_manques_avant_deconnexion {
                                gone.push(mac.clone());
                            }
                        }
                    }
                    for mac in gone {
                        if let Some((device, _)) = tracked.remove(&mac) {
                            events.push(log_network_event(NetworkEventKind::Deconnexion, &device));
                        }
                    }

                    first_scan = false;
                    let mut devices: Vec<DeviceDetails> = tracked
                        .values()
                        .map(|(device, missed)| DeviceDetails {
                            scans_manques: *missed,
                            ..device.clone()
                        })
                        .collect();
                    devices.sort_by_key(|device| device.ip.parse::<Ipv4Addr>().ok());
                    let mut snapshot = state.snapshot.write().await;
                    snapshot.devices = devices;
                    snapshot.events.extend(events);
                    let excess = snapshot.events.len().saturating_sub(MAX_NETWORK_EVENTS);
                    snapshot.events.drain(..excess);
                }
                Err(error) => eprintln!("[Réseau] Échec de lecture des appareils : {error}"),
            }
        } else {
            tracked.clear();
            last_attempt.clear();
            ever_seen.clear();
            first_scan = true;
            state.snapshot.write().await.devices.clear();
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(config.intervalle_scrutation_reseau_secondes.max(1)).saturating_sub(cycle_start.elapsed())) => {}
            result = config_rx.changed() => {
                if result.is_err() {
                    return;
                }
            }
        }
    }
}

/// Envoie en arrière-plan l'alerte Telegram d'un nouvel appareil, sans bloquer le scan.
fn spawn_new_device_alert(
    state: &std::sync::Arc<EngineState>,
    config: &Config,
    device: &DeviceDetails,
) {
    let client = state.http_client.clone();
    let config = config.clone();
    let text = format!(
        "NetDiskMonitor : nouvel appareil sur le réseau local : {} ({}) {}",
        device.ip,
        device.mac,
        device.display_name().unwrap_or("nom inconnu")
    );
    let mac = device.mac.clone();
    tokio::spawn(async move {
        if let Err(error) = send_telegram_message(&client, &config, text).await {
            eprintln!("[Telegram] Échec de l'alerte nouvel appareil {mac} : {error}");
        }
    });
}

/// Résout le nom d'une machine à partir de son adresse IP : d'abord en interrogeant
/// directement l'appareil en mDNS (Bonjour/Avahi), puis par DNS inverse.
///
/// Entrées : `ip`, adresse IPv4 au format texte.
/// Sortie : le nom, ou `None` si aucune méthode n'aboutit (3 secondes au plus).
async fn resolve_hostname(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    if let IpAddr::V4(v4) = addr {
        if let Some(name) = mdns_reverse_lookup(v4).await {
            return Some(name);
        }
    }
    let name = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr)),
    )
    .await
    .ok()?
    .ok()?
    .ok()?;

    if name.is_empty() || name == addr.to_string() {
        None
    } else {
        Some(name)
    }
}

/// Délai d'attente d'une réponse mDNS.
const MDNS_TIMEOUT: Duration = Duration::from_secs(1);

/// Demande son nom à un appareil par une requête mDNS « unicast » (PTR sur
/// `d.c.b.a.in-addr.arpa`, envoyée au port 5353 de l'appareil).
///
/// Sortie : le nom sans le suffixe `.local`, ou `None` sans réponse exploitable.
async fn mdns_reverse_lookup(ip: Ipv4Addr) -> Option<String> {
    let id = (std::process::id() as u16) ^ u16::from_be_bytes([ip.octets()[2], ip.octets()[3]]);
    let query = build_ptr_query(ip, id);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket
        .send_to(&query, SocketAddrV4::new(ip, 5353))
        .await
        .ok()?;

    let mut buffer = [0u8; 1500];
    let deadline = tokio::time::Instant::now() + MDNS_TIMEOUT;
    loop {
        let (length, from) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        if from.ip() != IpAddr::V4(ip) {
            continue;
        }
        if let Some(name) = parse_ptr_response(&buffer[..length], id) {
            let name = name.trim_end_matches('.');
            let name = name.strip_suffix(".local").unwrap_or(name);
            return Some(name.to_owned()).filter(|name| !name.is_empty());
        }
    }
}

/// Construit une requête DNS PTR pour l'adresse inverse de `ip`.
fn build_ptr_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    // Indicateurs à 0 (requête standard), 1 question, aucune autre section.
    packet.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let octets = ip.octets();
    let mut labels: Vec<String> = octets.iter().rev().map(u8::to_string).collect();
    labels.push("in-addr".to_owned());
    labels.push("arpa".to_owned());
    for label in labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 12, 0, 1]); // type PTR, classe IN
    packet
}

/// Extrait le nom de la première réponse PTR d'un paquet DNS dont l'identifiant vaut `id`.
fn parse_ptr_response(packet: &[u8], id: u16) -> Option<String> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        return None;
    }
    let is_response = packet[2] & 0x80 != 0;
    let questions = u16::from_be_bytes([packet[4], packet[5]]);
    let answers = u16::from_be_bytes([packet[6], packet[7]]);
    if !is_response || answers == 0 {
        return None;
    }

    let mut offset = 12;
    for _ in 0..questions {
        offset = read_dns_name(packet, offset)?.1 + 4;
    }
    for _ in 0..answers {
        let (_, after_name) = read_dns_name(packet, offset)?;
        let header = packet.get(after_name..after_name + 10)?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let data_length = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data_start = after_name + 10;
        if record_type == 12 {
            return read_dns_name(packet, data_start).map(|(name, _)| name);
        }
        offset = data_start + data_length;
    }
    None
}

/// Lit un nom DNS (avec pointeurs de compression) à partir de `offset`.
///
/// Sortie : le nom pointé (`a.b.c.`) et la position qui suit le nom dans le paquet.
fn read_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    for _ in 0..64 {
        let length = *packet.get(offset)? as usize;
        if length == 0 {
            return Some((name, end.unwrap_or(offset + 1)));
        }
        if length & 0xC0 == 0xC0 {
            let pointer = ((length & 0x3F) << 8) | *packet.get(offset + 1)? as usize;
            end.get_or_insert(offset + 2);
            offset = pointer;
            continue;
        }
        let label = packet.get(offset + 1..offset + 1 + length)?;
        name.push_str(&String::from_utf8_lossy(label));
        name.push('.');
        offset += 1 + length;
    }
    None
}

/// Ajoute un événement horodaté à `network_events.log` et l'affiche dans la console.
///
/// Entrées : `kind`, nature du mouvement ; `device`, appareil concerné.
/// Sortie : l'événement horodaté, à transmettre à l'IHM ; les erreurs d'écriture du journal
/// sont signalées sur la sortie d'erreur.
fn log_network_event(kind: NetworkEventKind, device: &DeviceDetails) -> NetworkEventDetails {
    use std::io::Write;

    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let timestamp = chrono::DateTime::<chrono::Local>::from(now)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let label = kind.as_str();
    let name = device.display_name().unwrap_or("-");
    println!(
        "[{timestamp}] [Réseau] {label} : {} ({}) {name}",
        device.ip, device.mac
    );

    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("network_events.log")
        .and_then(|mut file| {
            writeln!(
                file,
                "{secs} [{timestamp}] {label} {} {} {name}",
                device.ip, device.mac
            )
        });
    if let Err(error) = result {
        eprintln!("[Réseau] Écriture du journal impossible : {error}");
    }

    NetworkEventDetails {
        timestamp,
        kind,
        device: device.clone(),
    }
}

/// Détermine l'adresse IPv4 de la route par défaut sans envoyer de paquet.
///
/// Sert de solution de secours : avec un VPN actif, cette adresse est celle du tunnel.
async fn default_route_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("8.8.8.8:80").await.ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

/// Indique si une interface est virtuelle (VPN, tunnel, conteneur, machine virtuelle).
fn is_virtual_interface(name: &str) -> bool {
    const PREFIXES: [&str; 13] = [
        "utun", "tun", "tap", "wg", "ppp", "ipsec", "docker", "br-", "veth", "virbr", "vmnet",
        "vboxnet", "awdl",
    ];
    let name = name.to_ascii_lowercase();
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Liste les réseaux locaux IPv4 à balayer : interfaces physiques avec adresse de diffusion,
/// hors boucle locale, lien-local, VPN et interfaces virtuelles.
///
/// Sortie : couples (adresse locale, masque).
fn lan_ipv4_networks() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let interfaces = match get_if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            eprintln!("[Réseau] Liste des interfaces indisponible : {error}");
            return Vec::new();
        }
    };
    let mut networks = Vec::new();
    for interface in interfaces {
        if let get_if_addrs::IfAddr::V4(addr) = &interface.addr {
            if !addr.ip.is_loopback()
                && !addr.ip.is_link_local()
                && addr.broadcast.is_some()
                && !is_virtual_interface(&interface.name)
                && !networks.iter().any(|(ip, _)| *ip == addr.ip)
            {
                networks.push((addr.ip, addr.netmask));
            }
        }
    }
    networks
}

/// Adresses d'hôtes du sous-réseau de `ip`, hors `ip` elle-même.
///
/// Les masques plus larges qu'un /24 sont ramenés au /24 contenant `ip`, pour limiter
/// le balayage à 254 adresses.
fn subnet_hosts(ip: Ipv4Addr, netmask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mask = u32::from(netmask).max(0xFFFF_FF00);
    let network = u32::from(ip) & mask;
    let broadcast = network | !mask;
    ((network + 1)..broadcast)
        .map(Ipv4Addr::from)
        .filter(|host| *host != ip)
        .collect()
}

/// Balayage actif des réseaux locaux pour peupler la table ARP, même avec des appareils
/// qui n'ont jamais parlé à cette machine.
///
/// Sur macOS, utilise `/sbin/ping` (binaire système) ; ailleurs, un paquet UDP par adresse.
async fn sweep_hosts(hosts: Vec<Ipv4Addr>) {
    if cfg!(target_os = "macos") {
        ping_sweep(hosts).await;
    } else {
        udp_sweep(hosts).await;
    }
}

/// Envoie un ping à chaque adresse, 128 à la fois.
async fn ping_sweep(hosts: Vec<Ipv4Addr>) {
    let mut failures = Vec::new();

    for chunk in hosts.chunks(128) {
        let mut tasks = tokio::task::JoinSet::new();
        for &host in chunk {
            let ip = host.to_string();
            tasks.spawn(async move {
                tokio::process::Command::new("/sbin/ping")
                    .args(["-c", "1", "-t", "1", ip.as_str()])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => failures.push(error.to_string()),
                Err(error) => failures.push(error.to_string()),
            }
        }
    }
    if let Some(first) = failures.first() {
        eprintln!(
            "[Réseau] {} ping(s) n'ont pas pu être lancés (ex. : {first})",
            failures.len()
        );
    }
    sleep(Duration::from_millis(500)).await;
}

/// Envoie un petit paquet UDP à chaque adresse pour forcer l'ARP.
async fn udp_sweep(hosts: Vec<Ipv4Addr>) {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        for host in hosts {
            let _ = socket.send_to(&[0u8], SocketAddrV4::new(host, 9)).await;
        }
    }
    sleep(Duration::from_millis(1500)).await;
}

/// Balaye le réseau local puis lit les entrées ARP de la plateforme.
///
/// Entrées : aucune.
/// Sortie : liste d'appareils détectés (hors cette machine) ou erreur de lecture.
async fn read_network_devices() -> Result<Vec<DeviceDetails>, Box<dyn Error + Send + Sync>> {
    let mut networks = lan_ipv4_networks();
    if networks.is_empty() {
        let local = default_route_ipv4()
            .await
            .ok_or("Adresse IP locale introuvable")?;
        networks.push((local, Ipv4Addr::new(255, 255, 255, 0)));
    }
    let local_ips: HashSet<String> = networks.iter().map(|(ip, _)| ip.to_string()).collect();
    let hosts = networks
        .iter()
        .flat_map(|(ip, netmask)| subnet_hosts(*ip, *netmask))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    sweep_hosts(hosts).await;

    let arp_table: String = if cfg!(target_os = "windows") {
        let output = tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await?;

        if !output.status.success() {
            return Err(format!("arp -a a échoué avec le statut {}", output.status).into());
        }

        // La console Windows n'utilise pas forcément UTF-8 ; seules les IP/MAC (ASCII) importent.
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/net/arp")?
    } else if cfg!(target_os = "macos") {
        // macOS conserve jusqu'à 20 min les entrées expirées : `-x` indique si l'appareil
        // a réellement répondu, ce qui permet d'écarter ceux qui sont partis.
        match run_macos_arp("-anx").await {
            Ok(table) if table.contains("Expire(I)") => keep_confirmed_macos_entries(&table),
            Ok(_) | Err(_) => run_macos_arp("-an").await?,
        }
    } else {
        return Err("La lecture ARP n'est pas prise en charge sur cet OS.".into());
    };

    if arp_table.trim().is_empty() {
        eprintln!("[Réseau] La table ARP lue est vide.");
    }

    let mut devices = parse_arp_table(&arp_table);
    devices.retain(|device| !local_ips.contains(&device.ip));
    Ok(devices)
}

/// Exécute `/usr/sbin/arp` avec les options données (macOS) et renvoie sa sortie texte.
async fn run_macos_arp(options: &'static str) -> Result<String, Box<dyn Error + Send + Sync>> {
    // Lancé via `/bin/sh` et un thread bloquant (comme un terminal le ferait).
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("/usr/sbin/arp {options}"))
            .stdin(std::process::Stdio::null())
            .output()
    })
    .await??;

    if !output.status.success() {
        return Err(format!(
            "arp {options} a échoué avec le statut {} : {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    if output.stdout.is_empty() {
        eprintln!(
            "[Réseau] arp {options} a renvoyé 0 octet (statut {}, stderr : {})",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Conserve les lignes de `arp -anx` (macOS) dont l'échéance de réception `Expire(I)`
/// n'est pas `expired` : l'appareil a répondu récemment (ARP ou ping).
///
/// Colonnes : Neighbor, Linklayer Address, Expire(O), Expire(I), Netif, ...
/// Les entrées statiques (`(none)`) sont conservées.
fn keep_confirmed_macos_entries(table: &str) -> String {
    table
        .lines()
        .filter(|line| line.split_whitespace().nth(3) != Some("expired"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Analyse les lignes d'une table ARP et conserve les paires IP/MAC valides.
///
/// Exclut les entrées incomplètes, le broadcast, le multicast, le lien-local (169.254.x.x)
/// et normalise les MAC en minuscules sur deux chiffres par octet.
fn parse_arp_table(contents: &str) -> Vec<DeviceDetails> {
    let mut devices = Vec::new();

    for line in contents.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();

        // macOS entoure les adresses IP de parenthèses :
        // ? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0
        let ip = fields.iter().find_map(|field| {
            field
                .trim_matches(|c| c == '(' || c == ')')
                .parse::<IpAddr>()
                .ok()
        });

        let mac = fields.iter().find_map(|field| normalize_mac(field));

        if let (Some(ip), Some(mac)) = (ip, mac) {
            let link_local = matches!(ip, IpAddr::V4(v4) if v4.is_link_local());
            let ignored_mac = mac == "ff:ff:ff:ff:ff:ff"
                || mac == "00:00:00:00:00:00"
                || mac.starts_with("01:00:5e")
                || mac.starts_with("33:33");
            if !ip.is_unspecified() && !ip.is_multicast() && !link_local && !ignored_mac {
                devices.push(DeviceDetails {
                    ip: ip.to_string(),
                    mac,
                    hostname: None,
                    scans_manques: 0,
                    alias: None,
                });
            }
        }
    }

    devices
}

/// Normalise une adresse MAC (`:` ou `-`, octets de 1 ou 2 chiffres) en `aa:bb:cc:dd:ee:ff`.
///
/// Sortie : `None` si le format est invalide.
fn normalize_mac(value: &str) -> Option<String> {
    let separator = if value.contains(':') { ':' } else { '-' };
    let parts: Vec<&str> = value.split(separator).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::with_capacity(6);
    for part in parts {
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", part.to_ascii_lowercase()));
    }
    Some(out.join(":"))
}

/// Active ou désactive à chaud les surveillances ; les tâches concernées sont réveillées
/// immédiatement par le canal de configuration. `config.toml` n'est pas modifié.
fn set_monitoring(state: &EngineState, disque: bool, reseau: bool) -> MessageEngineToClient {
    state.config.send_if_modified(|config| {
        let changed = config.activer_surveillance_disque != disque
            || config.activer_surveillance_reseau != reseau;
        config.activer_surveillance_disque = disque;
        config.activer_surveillance_reseau = reseau;
        changed
    });
    let label = |enabled: bool| if enabled { "activée" } else { "désactivée" };
    println!(
        "[Configuration] Surveillance disque {}, surveillance réseau {}",
        label(disque),
        label(reseau)
    );
    MessageEngineToClient::ActionResult {
        success: true,
        message: format!(
            "Surveillance disque {}, surveillance réseau {}.",
            label(disque),
            label(reseau)
        ),
    }
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
    let mut reader = BufReader::new(read_half).take(MAX_REQUEST_BYTES);
    let mut line = String::new();
    tokio::time::timeout(CLIENT_REQUEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| "Délai d'attente de la requête client dépassé")??;

    let response = match serde_json::from_str::<MessageClientToEngine>(&line) {
        Ok(MessageClientToEngine::GetStatus) => {
            let snapshot = state.snapshot.read().await;
            let aliases = state.aliases.read().await;
            let mut devices = snapshot.devices.clone();
            apply_aliases(devices.iter_mut(), &aliases);
            let mut events = snapshot.events.clone();
            apply_aliases(events.iter_mut().map(|event| &mut event.device), &aliases);
            let (threshold, disk_enabled, network_enabled) = {
                let config = state.config.borrow();
                (
                    config.seuil_alerte_disque_pourcentage,
                    config.activer_surveillance_disque,
                    config.activer_surveillance_reseau,
                )
            };
            MessageEngineToClient::StatusSnapshot {
                disk_info: snapshot.disks.clone(),
                connected_devices: devices,
                network_events: events,
                seuil_alerte_disque_pourcentage: threshold,
                surveillance_disque_active: disk_enabled,
                surveillance_reseau_active: network_enabled,
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
        Ok(MessageClientToEngine::SetMonitoring { disque, reseau }) => {
            set_monitoring(&state, disque, reseau)
        }
        Ok(MessageClientToEngine::SetDeviceAlias { mac, alias }) => {
            set_device_alias(&state, &mac, &alias, true).await
        }
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
    use super::{
        build_ptr_query, clean_alias, delete_selected_files, is_virtual_interface,
        keep_confirmed_macos_entries, normalize_mac, parse_arp_table, parse_ptr_response,
        set_device_alias, set_monitoring, subnet_hosts, validate_config, EngineState, Snapshot,
    };
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
            aliases: RwLock::new(Default::default()),
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
    /// Vérifie que l'activation à chaud modifie la configuration et notifie les tâches.
    fn toggles_monitoring_at_runtime() {
        let (config, mut receiver) = watch::channel(Config::default());
        let state = EngineState {
            snapshot: RwLock::new(Snapshot::default()),
            config,
            http_client: reqwest::Client::new(),
            aliases: RwLock::new(Default::default()),
        };
        receiver.mark_unchanged();

        let response = set_monitoring(&state, false, true);

        assert!(matches!(
            response,
            MessageEngineToClient::ActionResult { success: true, .. }
        ));
        assert!(receiver.has_changed().expect("channel open"));
        let current = receiver.borrow_and_update().clone();
        assert!(!current.activer_surveillance_disque);
        assert!(current.activer_surveillance_reseau);

        set_monitoring(&state, false, true);
        assert!(!receiver.has_changed().expect("channel open"));
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

    #[test]
    fn parses_macos_arp_entries() {
        let arp = "
    ? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    ? (192.168.1.20) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
    ";

        let devices = parse_arp_table(arp);

        assert_eq!(devices.len(), 2);

        assert!(devices
            .iter()
            .any(|device| { device.ip == "192.168.1.10" && device.mac == "aa:bb:cc:dd:ee:ff" }));

        assert!(devices
            .iter()
            .any(|device| { device.ip == "192.168.1.20" && device.mac == "11:22:33:44:55:66" }));
    }

    #[test]
    /// Vérifie que les entrées macOS expirées (appareil parti) sont écartées.
    fn ignores_expired_macos_arp_entries() {
        let arp = "\
Neighbor                Linklayer Address Expire(O) Expire(I)          Netif Refs Prbs RSSI
192.168.1.1             2c:cf:67:71:85:77 2m56s     2m56s          en0    1 none unknown
192.168.1.63            (incomplete)      58s       expired        en0    1    4 unknown
192.168.1.161           28:6b:35:b2:d2:70 1m52s     expired        en0    2    1 unknown
192.168.1.187           6:79:79:bb:d8:34  expired   expired        en0    1 none unknown
192.168.1.200           aa:bb:cc:dd:ee:ff (none)    (none)         en0
";
        let devices = parse_arp_table(&keep_confirmed_macos_entries(arp));
        let ips: Vec<_> = devices.iter().map(|device| device.ip.as_str()).collect();
        assert_eq!(ips, ["192.168.1.1", "192.168.1.200"]);
    }

    #[test]
    /// Vérifie le calcul des hôtes à balayer et l'exclusion des interfaces VPN/virtuelles.
    fn computes_sweep_targets() {
        use std::net::Ipv4Addr;
        let local = Ipv4Addr::new(192, 168, 1, 171);
        let hosts = subnet_hosts(local, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(hosts.len(), 253);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!hosts.contains(&local));

        // Un /16 est ramené au /24 de l'adresse locale.
        assert_eq!(
            subnet_hosts(Ipv4Addr::new(10, 0, 5, 9), Ipv4Addr::new(255, 255, 0, 0)).len(),
            253
        );
        // Un /25 n'est pas élargi.
        assert_eq!(
            subnet_hosts(
                Ipv4Addr::new(10, 0, 5, 9),
                Ipv4Addr::new(255, 255, 255, 128)
            )
            .len(),
            125
        );

        assert!(is_virtual_interface("utun4"));
        assert!(is_virtual_interface("docker0"));
        assert!(!is_virtual_interface("en0"));
        assert!(!is_virtual_interface("wlan0"));
    }

    #[test]
    /// Vérifie la construction d'une requête PTR et la lecture d'une réponse compressée.
    fn builds_and_parses_mdns_ptr_messages() {
        use std::net::Ipv4Addr;
        let query = build_ptr_query(Ipv4Addr::new(192, 168, 1, 1), 0x1234);
        let question = &query[12..];
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(question[0] as usize, 1);
        assert!(query.ends_with(&[4, b'a', b'r', b'p', b'a', 0, 0, 12, 0, 1]));

        // Réponse : en-tête, question recopiée, réponse dont le nom pointe sur la question.
        let mut response = vec![0x12, 0x34, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        response.extend_from_slice(question);
        let target = b"\x08Myrtille\x05local\x00";
        response.extend_from_slice(&[0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 10, 0]);
        response.push(target.len() as u8);
        response.extend_from_slice(target);

        assert_eq!(
            parse_ptr_response(&response, 0x1234).as_deref(),
            Some("Myrtille.local.")
        );
        assert_eq!(parse_ptr_response(&response, 0x9999), None);
        assert_eq!(parse_ptr_response(&response[..20], 0x1234), None);
    }

    #[tokio::test]
    /// Vérifie l'ajout, la validation et la suppression d'un nom personnalisé.
    async fn sets_and_removes_device_aliases() {
        let (config, _) = watch::channel(Config::default());
        let state = EngineState {
            snapshot: RwLock::new(Snapshot::default()),
            config,
            http_client: reqwest::Client::new(),
            aliases: RwLock::new(Default::default()),
        };

        let response =
            set_device_alias(&state, "EC-71-DB-9D-67-DA", "  Caméra entrée ", false).await;
        assert!(matches!(
            response,
            MessageEngineToClient::ActionResult { success: true, .. }
        ));
        assert_eq!(
            state
                .aliases
                .read()
                .await
                .get("ec:71:db:9d:67:da")
                .map(String::as_str),
            Some("Caméra entrée")
        );

        let response = set_device_alias(&state, "pas-une-mac", "x", false).await;
        assert!(matches!(
            response,
            MessageEngineToClient::ActionResult { success: false, .. }
        ));
        assert!(clean_alias(&"x".repeat(65)).is_err());
        assert!(clean_alias("a\nb").is_err());

        set_device_alias(&state, "ec:71:db:9d:67:da", "", false).await;
        assert!(state.aliases.read().await.is_empty());
    }

    #[cfg(unix)]
    #[test]
    /// Vérifie qu'un fichier atteint par deux chemins (lien dur) n'est listé qu'une fois.
    fn lists_each_large_file_once() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "net-disk-monitor-scan-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(directory.join("sub")).expect("create test directories");
        std::fs::write(directory.join("big.bin"), vec![0u8; 2048]).expect("create big file");
        std::fs::hard_link(directory.join("big.bin"), directory.join("sub/same.bin"))
            .expect("create hard link");
        std::fs::write(directory.join("small.bin"), b"x").expect("create small file");

        let mut scan = super::LargeFileScan {
            minimum_size_bytes: 1024,
            ..Default::default()
        };
        assert!(scan.visit_directory(&directory));
        assert!(!scan.visit_directory(&directory.join("absent")));
        assert_eq!(scan.files.len(), 1);
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[test]
    fn normalizes_mac_addresses() {
        assert_eq!(
            normalize_mac("6:79:79:bb:d8:34").as_deref(),
            Some("06:79:79:bb:d8:34")
        );
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-0F").as_deref(),
            Some("aa:bb:cc:dd:ee:0f")
        );
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(normalize_mac("1:2:3"), None);
    }

    #[test]
    fn ignores_incomplete_broadcast_multicast_and_link_local() {
        let arp = "
? (169.254.106.34) at 28:6b:35:b2:d2:70 on en0 [ethernet]
? (192.168.1.10) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.187) at 6:79:79:bb:d8:34 on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
";
        let devices = parse_arp_table(arp);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip, "192.168.1.187");
        assert_eq!(devices[0].mac, "06:79:79:bb:d8:34");
    }
}
