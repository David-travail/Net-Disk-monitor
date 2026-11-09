//! Interface graphique du client NetDiskMonitor.
//!
//! Elle interroge le moteur TCP local périodiquement et affiche l'occupation
//! des disques et les appareils du réseau dans une fenêtre eframe/egui.
//!
//! Fonctions :
//! - `NetDiskMonitorApp::new` : crée l'état de l'interface.
//! - `NetDiskMonitorApp::receive_updates` : applique les réponses reçues du moteur.
//! - `NetDiskMonitorApp::update` : dessine et actualise la fenêtre.
//! - `main` : démarre la collecte réseau et ouvre la fenêtre graphique.
//! - `start_status_polling` : exécute les demandes d'état périodiques en arrière-plan.
//! - `request_engine` : transmet une requête au moteur via TCP.
//! - `format_bytes` : convertit une taille en unité lisible.
//! - `formats_disk_sizes_in_human_readable_units` : teste le formatage des tailles.

use common::{
    DeviceDetails, DiskDetails, LargeFileDetails, MessageClientToEngine, MessageEngineToClient,
};
use eframe::egui;
use std::{
    collections::HashSet,
    sync::mpsc::{self, Receiver},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::mpsc::{self as tokio_mpsc, UnboundedSender},
};

const ENGINE_ADDR: &str = "127.0.0.1:7878";
const REFRESH_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Default)]
struct MonitorData {
    disks: Vec<DiskDetails>,
    devices: Vec<DeviceDetails>,
    large_files: Vec<LargeFileDetails>,
    selected_paths: HashSet<String>,
    last_error: Option<String>,
    status_message: Option<(bool, String)>,
    is_working: bool,
    has_scanned: bool,
    was_over_threshold: bool,
    threshold_percent: f32,
    confirm_deletion: bool,
}

struct NetDiskMonitorApp {
    updates: Receiver<Result<MessageEngineToClient, String>>,
    requests: UnboundedSender<MessageClientToEngine>,
    data: MonitorData,
}

impl NetDiskMonitorApp {
    /// Crée l'interface avec le canal de réception des réponses du moteur.
    ///
    /// Entrées : `updates`, récepteur des résultats des demandes de statut.
    /// Sortie : instance de l'application avec des données d'affichage initialement vides.
    fn new(
        updates: Receiver<Result<MessageEngineToClient, String>>,
        requests: UnboundedSender<MessageClientToEngine>,
    ) -> Self {
        Self {
            updates,
            requests,
            data: MonitorData::default(),
        }
    }

    /// Vide les réponses en attente et met à jour les données visibles.
    ///
    /// Entrées : `self`, état de l'interface ; `context`, contexte egui à réveiller.
    /// Sortie : aucune ; les erreurs reçues sont conservées pour affichage.
    fn receive_updates(&mut self, context: &egui::Context) {
        while let Ok(update) = self.updates.try_recv() {
            match update {
                Ok(MessageEngineToClient::StatusSnapshot {
                    disk_info,
                    connected_devices,
                    seuil_alerte_disque_pourcentage,
                }) => {
                    self.data.disks = disk_info;
                    self.data.devices = connected_devices;
                    self.data.last_error = None;
                    self.data.threshold_percent = seuil_alerte_disque_pourcentage;
                    let over_threshold = self.data.disks.iter().any(|disk| {
                        disk.total_bytes > 0
                            && disk.used_bytes as f64 / disk.total_bytes as f64 * 100.0
                                >= f64::from(seuil_alerte_disque_pourcentage)
                    });
                    if over_threshold && !self.data.was_over_threshold {
                        self.data.was_over_threshold = true;
                        if !self.data.is_working {
                            match self.requests.send(MessageClientToEngine::ScanLargeFiles) {
                                Ok(()) => {
                                    self.data.is_working = true;
                                    self.data.status_message = Some((
                                        true,
                                        "Seuil atteint : analyse des fichiers volumineux…".into(),
                                    ));
                                }
                                Err(error) => {
                                    self.data.last_error = Some(format!(
                                        "Impossible de lancer l'analyse après l'alerte : {error}"
                                    ));
                                }
                            }
                        }
                    } else if !over_threshold {
                        self.data.was_over_threshold = false;
                    }
                }
                Ok(MessageEngineToClient::LargeFilesSnapshot { files }) => {
                    self.data.large_files = files;
                    self.data.selected_paths.clear();
                    self.data.is_working = false;
                    self.data.has_scanned = true;
                    self.data.last_error = None;
                }
                Ok(MessageEngineToClient::ActionResult { success, message }) => {
                    self.receive_action_result(success, message, false);
                }
                Ok(MessageEngineToClient::FilesDeleted { success, message }) => {
                    self.receive_action_result(success, message, true);
                }
                Err(error) => {
                    self.data.is_working = false;
                    self.data.last_error = Some(error);
                }
            }
        }
        context.request_repaint_after(Duration::from_millis(250));
    }

    fn receive_action_result(&mut self, success: bool, message: String, refresh_files: bool) {
        self.data.is_working = false;
        self.data.last_error = None;
        self.data.status_message = Some((success, message));
        if refresh_files {
            self.data.selected_paths.clear();
            match self.requests.send(MessageClientToEngine::ScanLargeFiles) {
                Ok(()) => self.data.is_working = true,
                Err(error) => {
                    self.data.last_error =
                        Some(format!("Impossible d'actualiser l'analyse : {error}"));
                }
            }
        }
    }
}

impl eframe::App for NetDiskMonitorApp {
    /// Dessine la fenêtre et demande le traitement des réponses réseau disponibles.
    ///
    /// Entrées : `self`, données affichées ; `context`, contexte egui ;
    /// `_frame`, fenêtre native fournie par eframe.
    /// Sortie : aucune ; met à jour l'interface graphique.
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_updates(context);

        egui::TopBottomPanel::top("header").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("NetDiskMonitor");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!(
                        "Actualisation toutes les {} secondes",
                        REFRESH_INTERVAL.as_secs()
                    ));
                });
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            if let Some(error) = &self.data.last_error {
                ui.colored_label(egui::Color32::LIGHT_RED, format!("Erreur : {error}"));
                ui.add_space(8.0);
            }
            if let Some((success, message)) = &self.data.status_message {
                let color = if *success {
                    egui::Color32::LIGHT_GREEN
                } else {
                    egui::Color32::LIGHT_RED
                };
                ui.colored_label(color, message);
                ui.add_space(8.0);
            }

            ui.heading("Occupation des disques");
            ui.label(format!(
                "Seuil d'alerte : {:.1} %",
                self.data.threshold_percent
            ));
            ui.add_space(6.0);
            if self.data.disks.is_empty() {
                ui.label("Aucun disque disponible. Vérifiez que le moteur est démarré.");
            } else {
                for disk in &self.data.disks {
                    let percent = if disk.total_bytes == 0 {
                        0.0
                    } else {
                        disk.used_bytes as f32 / disk.total_bytes as f32
                    };
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.strong(&disk.name);
                            ui.label(format!(
                                "{} utilisés sur {}",
                                format_bytes(disk.used_bytes),
                                format_bytes(disk.total_bytes)
                            ));
                        });
                        let progress = egui::ProgressBar::new(percent.clamp(0.0, 1.0))
                            .text(format!("{:.1} %", percent * 100.0));
                        ui.add(progress);
                    });
                    ui.add_space(4.0);
                }
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.heading("Fichiers volumineux");
                if ui
                    .add_enabled(
                        !self.data.is_working,
                        egui::Button::new("Analyser les disques"),
                    )
                    .clicked()
                {
                    self.data.last_error = None;
                    self.data.status_message = None;
                    match self.requests.send(MessageClientToEngine::ScanLargeFiles) {
                        Ok(()) => self.data.is_working = true,
                        Err(error) => {
                            self.data.last_error = Some(format!(
                                "Impossible d'envoyer la demande d'analyse : {error}"
                            ))
                        }
                    }
                }
            });
            ui.label("Fichiers d'au moins 100 Mio ; les 100 plus volumineux sont affichés.");
            if self.data.is_working {
                ui.label("Opération en cours…");
            }

            if self.data.large_files.is_empty() {
                if self.data.has_scanned {
                    ui.label("Aucun fichier correspondant trouvé sur les disques accessibles.");
                } else {
                    ui.label("Lancez une analyse pour rechercher les fichiers volumineux.");
                }
            } else {
                let files = self.data.large_files.clone();
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        egui::Grid::new("large_files")
                            .striped(true)
                            .num_columns(3)
                            .show(ui, |ui| {
                                ui.strong("Sélection");
                                ui.strong("Fichier");
                                ui.strong("Taille");
                                ui.end_row();

                                for file in files {
                                    let mut selected =
                                        self.data.selected_paths.contains(&file.path);
                                    if ui.checkbox(&mut selected, "").changed() {
                                        if selected {
                                            self.data.selected_paths.insert(file.path.clone());
                                        } else {
                                            self.data.selected_paths.remove(&file.path);
                                        }
                                    }
                                    ui.label(&file.path);
                                    ui.label(format_bytes(file.size_bytes));
                                    ui.end_row();
                                }
                            });
                    });
                ui.horizontal(|ui| {
                    ui.label(format!(
                        "{} fichier(s) sélectionné(s)",
                        self.data.selected_paths.len()
                    ));
                    if ui
                        .add_enabled(
                            !self.data.is_working && !self.data.selected_paths.is_empty(),
                            egui::Button::new("Supprimer la sélection…"),
                        )
                        .clicked()
                    {
                        self.data.confirm_deletion = true;
                    }
                });
            }

            ui.add_space(12.0);
            ui.heading("Appareils du réseau local");
            ui.add_space(6.0);
            if self.data.devices.is_empty() {
                ui.label("Aucun appareil détecté dans la table ARP.");
            } else {
                egui::Grid::new("network_devices")
                    .striped(true)
                    .num_columns(3)
                    .show(ui, |ui| {
                        ui.strong("Adresse IP");
                        ui.strong("Adresse MAC");
                        ui.strong("Nom");
                        ui.end_row();

                        for device in &self.data.devices {
                            ui.label(&device.ip);
                            ui.label(&device.mac);
                            ui.label(device.hostname.as_deref().unwrap_or("—"));
                            ui.end_row();
                        }
                    });
            }
        });

        if self.data.confirm_deletion {
            egui::Window::new("Confirmer la suppression")
                .collapsible(false)
                .resizable(false)
                .show(context, |ui| {
                    ui.label(format!(
                        "Supprimer définitivement {} fichier(s) sélectionné(s) ?",
                        self.data.selected_paths.len()
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Annuler").clicked() {
                            self.data.confirm_deletion = false;
                        }
                        if ui.button("Supprimer").clicked() {
                            let paths = self.data.selected_paths.iter().cloned().collect();
                            match self
                                .requests
                                .send(MessageClientToEngine::DeleteFiles { paths })
                            {
                                Ok(()) => {
                                    self.data.is_working = true;
                                    self.data.confirm_deletion = false;
                                    self.data.last_error = None;
                                    self.data.status_message = None;
                                }
                                Err(error) => {
                                    self.data.last_error = Some(format!(
                                        "Impossible d'envoyer la suppression : {error}"
                                    ));
                                }
                            }
                        }
                    });
                });
        }

        egui::TopBottomPanel::bottom("footer").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Moteur : {ENGINE_ADDR}"));
                ui.separator();
                ui.label("État actualisé automatiquement");
            });
        });
    }
}

/// Démarre le client graphique et la tâche de récupération des états du moteur.
///
/// Entrées : arguments de ligne de commande ignorés.
/// Sortie : résultat eframe, avec une erreur si la fenêtre ne peut pas être créée.
fn main() -> Result<(), eframe::Error> {
    let (updates_tx, updates_rx) = mpsc::channel();
    let (requests_tx, requests_rx) = tokio_mpsc::unbounded_channel();
    start_status_polling(updates_tx, requests_rx);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 760.0])
            .with_min_inner_size([680.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NetDiskMonitor",
        options,
        Box::new(move |_creation_context| {
            Ok(Box::new(NetDiskMonitorApp::new(updates_rx, requests_tx)))
        }),
    )
}

/// Lance un thread qui interroge régulièrement le moteur et transmet les réponses à l'interface.
///
/// Entrées : `updates`, canal d'envoi des réponses ou erreurs vers la fenêtre.
/// Sortie : aucune ; le thread s'arrête lorsque l'interface ferme le canal.
fn start_status_polling(
    updates: mpsc::Sender<Result<MessageEngineToClient, String>>,
    mut requests: tokio_mpsc::UnboundedReceiver<MessageClientToEngine>,
) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = updates.send(Err(format!(
                    "Impossible de démarrer le client réseau : {error}"
                )));
                return;
            }
        };

        runtime.block_on(async move {
            let mut ticker = tokio::time::interval(REFRESH_INTERVAL);
            loop {
                let request = tokio::select! {
                    _ = ticker.tick() => MessageClientToEngine::GetStatus,
                    request = requests.recv() => match request {
                        Some(request) => request,
                        None => break,
                    },
                };
                let result = request_engine(request).await;
                if updates.send(result).is_err() {
                    break;
                }
            }
        });
    });
}

/// Établit une connexion au moteur et exécute une requête.
///
/// Entrées : `request`, commande à transmettre au moteur.
/// Sortie : réponse du moteur, ou description textuelle de l'erreur réseau/JSON.
async fn request_engine(request: MessageClientToEngine) -> Result<MessageEngineToClient, String> {
    let stream = TcpStream::connect(ENGINE_ADDR)
        .await
        .map_err(|error| error.to_string())?;
    let (read_half, mut write_half) = stream.into_split();
    let request = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    write_half
        .write_all(&request)
        .await
        .map_err(|error| error.to_string())?;
    write_half
        .write_all(b"\n")
        .await
        .map_err(|error| error.to_string())?;

    let mut response_line = String::new();
    BufReader::new(read_half)
        .read_line(&mut response_line)
        .await
        .map_err(|error| error.to_string())?;
    if response_line.is_empty() {
        return Err("Le moteur a fermé la connexion sans réponse.".into());
    }
    serde_json::from_str(&response_line)
        .map_err(|error| format!("Réponse du moteur invalide : {error}"))
}

/// Formate une taille en octets en utilisant l'unité binaire appropriée.
///
/// Entrées : `bytes`, taille à convertir.
/// Sortie : chaîne lisible en octets, Ko, Mo, Go ou To.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["octets", "Ko", "Mo", "Go", "To"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    #[test]
    /// Vérifie le formatage des octets et des unités supérieures.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si le texte formaté diffère des valeurs attendues.
    fn formats_disk_sizes_in_human_readable_units() {
        assert_eq!(format_bytes(512), "512 octets");
        assert_eq!(format_bytes(1024), "1.0 Ko");
        assert_eq!(format_bytes(1024 * 1024), "1.0 Mo");
    }
}
