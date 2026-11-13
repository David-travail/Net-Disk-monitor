//! Interface graphique du client NetDiskMonitor.
//!
//! Elle interroge le moteur TCP local périodiquement et affiche l'occupation
//! des disques et les appareils du réseau dans une fenêtre eframe/egui.
//!
//! Fonctions :
//! - `NetDiskMonitorApp::new` : crée l'état de l'interface.
//! - `NetDiskMonitorApp::receive_updates` : applique les réponses reçues du moteur.
//! - `NetDiskMonitorApp::show_monitoring_toggles` : active/désactive les surveillances.
//! - `stacked_blocks` : répartit la hauteur entre blocs, avec poignées de redimensionnement.
//! - `NetDiskMonitorApp::show_*` : dessinent chaque bloc (disques, fichiers, appareils, mouvements).
//! - `NetDiskMonitorApp::update` : dessine et actualise la fenêtre.
//! - `main` : démarre la collecte réseau et ouvre la fenêtre graphique.
//! - `start_status_polling` : exécute les demandes d'état périodiques en arrière-plan.
//! - `request_engine` : transmet une requête au moteur via TCP.
//! - `format_bytes` : convertit une taille en unité lisible.
//! - `formats_disk_sizes_in_human_readable_units` : teste le formatage des tailles.

use common::{
    Config, DeviceDetails, DiskDetails, LargeFileDetails, MessageClientToEngine,
    MessageEngineToClient, NetworkEventDetails, NetworkEventKind, MAX_ALIAS_CHARS,
};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
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

/// Délai maximal pour établir la connexion TCP avec le moteur.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Délai maximal de réponse du moteur pour les requêtes rapides.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct MonitorData {
    disks: Vec<DiskDetails>,
    devices: Vec<DeviceDetails>,
    network_events: Vec<NetworkEventDetails>,
    large_files: Vec<LargeFileDetails>,
    selected_paths: HashSet<String>,
    last_error: Option<String>,
    status_message: Option<(bool, String)>,
    is_working: bool,
    has_scanned: bool,
    was_over_threshold: bool,
    threshold_percent: f32,
    confirm_deletion: bool,
    /// État des surveillances rapporté par le moteur (`None` tant qu'il n'a pas répondu).
    monitoring: Option<(bool, bool)>,
}

struct NetDiskMonitorApp {
    updates: Receiver<Result<MessageEngineToClient, String>>,
    requests: UnboundedSender<MessageClientToEngine>,
    data: MonitorData,
    configuration_error: Option<String>,
    engine_address: String,
    minimum_file_size_mio: u64,
    maximum_files: usize,
    refresh_interval: Duration,
    layout: BlockLayout,
    /// Appareil en cours de renommage, avec le texte saisi.
    alias_edit: Option<AliasEdit>,
}

/// Saisie en cours d'un nom personnalisé.
struct AliasEdit {
    device: DeviceDetails,
    text: String,
    /// Le focus clavier a déjà été placé dans le champ de saisie.
    focused: bool,
}

impl NetDiskMonitorApp {
    /// Crée l'interface avec le canal de réception des réponses du moteur.
    ///
    /// Entrées : `updates`, récepteur des résultats des demandes de statut.
    /// Sortie : instance de l'application avec des données d'affichage initialement vides.
    fn new(
        updates: Receiver<Result<MessageEngineToClient, String>>,
        requests: UnboundedSender<MessageClientToEngine>,
        config: Config,
        configuration_error: Option<String>,
    ) -> Self {
        Self {
            updates,
            requests,
            data: MonitorData::default(),
            configuration_error,
            engine_address: config.adresse_moteur,
            minimum_file_size_mio: config.taille_min_fichier_volumineux_mio,
            maximum_files: config.nombre_max_fichiers_volumineux,
            refresh_interval: Duration::from_secs(config.intervalle_actualisation_ihm_secondes),
            layout: BlockLayout::default(),
            alias_edit: None,
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
                    surveillance_disque_active,
                    surveillance_reseau_active,
                    network_events,
                }) => {
                    self.data.network_events = network_events;
                    self.data.monitoring =
                        Some((surveillance_disque_active, surveillance_reseau_active));
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

    /// Affiche les cases d'activation des surveillances et transmet les changements au moteur.
    ///
    /// Les cases restent grisées tant que l'état du moteur n'est pas connu.
    fn show_monitoring_toggles(&mut self, ui: &mut egui::Ui) {
        let (mut disk, mut network) = self.data.monitoring.unwrap_or((false, false));
        let enabled = self.data.monitoring.is_some();
        let disk_changed = ui
            .add_enabled(
                enabled,
                egui::Checkbox::new(&mut disk, "Surveillance disque"),
            )
            .changed();
        let network_changed = ui
            .add_enabled(
                enabled,
                egui::Checkbox::new(&mut network, "Surveillance réseau"),
            )
            .changed();
        if disk_changed || network_changed {
            match self.requests.send(MessageClientToEngine::SetMonitoring {
                disque: disk,
                reseau: network,
            }) {
                Ok(()) => self.data.monitoring = Some((disk, network)),
                Err(error) => {
                    self.data.last_error = Some(format!(
                        "Impossible de modifier les surveillances : {error}"
                    ));
                }
            }
        }
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

/// Couleurs de statut lisibles en thème clair comme en thème sombre.
mod colors {
    use eframe::egui::{Color32, Ui};

    /// Vert : connecté, succès.
    pub fn ok(ui: &Ui) -> Color32 {
        if ui.visuals().dark_mode {
            Color32::LIGHT_GREEN
        } else {
            Color32::from_rgb(0, 128, 0)
        }
    }

    /// Rouge : erreur, déconnexion, seuil dépassé.
    pub fn error(ui: &Ui) -> Color32 {
        if ui.visuals().dark_mode {
            Color32::LIGHT_RED
        } else {
            Color32::from_rgb(190, 30, 30)
        }
    }

    /// Orange : avertissement (appareil qui ne répond plus, MAC privée).
    pub fn warning(ui: &Ui) -> Color32 {
        if ui.visuals().dark_mode {
            Color32::from_rgb(230, 170, 60)
        } else {
            Color32::from_rgb(180, 95, 0)
        }
    }

    /// Gris : élément atténué.
    pub fn dimmed(ui: &Ui) -> Color32 {
        ui.visuals().weak_text_color()
    }
}

/// Blocs affichés dans la zone centrale.
#[derive(Clone, Copy)]
enum Block {
    Disks,
    LargeFiles,
    Devices,
    Events,
}

/// Largeur de fenêtre à partir de laquelle les blocs sont répartis sur deux colonnes.
const TWO_COLUMNS_MIN_WIDTH: f32 = 1000.0;
/// Hauteur minimale d'un bloc, en pixels.
const MIN_BLOCK_HEIGHT: f32 = 70.0;
/// Hauteur de la poignée de redimensionnement entre deux blocs.
const SPLITTER_HEIGHT: f32 = 8.0;

/// Parts relatives de la hauteur attribuées à chaque bloc, modifiables à la souris.
#[derive(Clone, Copy)]
struct BlockLayout {
    /// Une colonne : disques, fichiers, appareils, mouvements.
    single: [f32; 4],
    /// Deux colonnes : disques et fichiers à gauche.
    left: [f32; 2],
    /// Deux colonnes : appareils et mouvements à droite.
    right: [f32; 2],
}

impl Default for BlockLayout {
    fn default() -> Self {
        Self {
            single: [1.0, 1.5, 1.5, 1.0],
            left: [1.0, 2.0],
            right: [2.0, 1.0],
        }
    }
}

/// Empile des blocs verticalement : chacun reçoit une part de la hauteur disponible
/// proportionnelle à son poids, et les poignées entre blocs modifient ces poids.
///
/// Entrées : `ui`, zone à remplir ; `weights`, poids
/// des blocs (mis à jour lors d'un glissement) ; `draw`, dessine le bloc d'indice donné.
fn stacked_blocks(
    ui: &mut egui::Ui,
    weights: &mut [f32],
    mut draw: impl FnMut(usize, &mut egui::Ui),
) {
    let count = weights.len();
    let width = ui.available_width();
    let total = (ui.available_height() - SPLITTER_HEIGHT * (count - 1) as f32)
        .max(MIN_BLOCK_HEIGHT * count as f32);
    let sum: f32 = weights.iter().sum();

    for index in 0..count {
        let height = total * weights[index] / sum;
        ui.allocate_ui_with_layout(
            egui::vec2(width, height),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_size(ui.available_size());
                    draw(index, ui);
                });
            },
        );

        if index + 1 < count {
            let (rect, response) =
                ui.allocate_exact_size(egui::vec2(width, SPLITTER_HEIGHT), egui::Sense::drag());
            let response = response.on_hover_cursor(egui::CursorIcon::ResizeVertical);
            let stroke = if response.hovered() || response.dragged() {
                ui.visuals().widgets.active.fg_stroke
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke
            };
            ui.painter().hline(rect.x_range(), rect.center().y, stroke);
            if response.dragged() {
                let delta = response.drag_delta().y / total * sum;
                let minimum = MIN_BLOCK_HEIGHT / total * sum;
                let pair = weights[index] + weights[index + 1];
                let upper = (weights[index] + delta).clamp(minimum, (pair - minimum).max(minimum));
                weights[index] = upper;
                weights[index + 1] = pair - upper;
            }
        }
    }
}

impl NetDiskMonitorApp {
    /// Dessine le bloc demandé.
    ///
    /// Chaque bloc reçoit son propre espace d'identifiants : sans cela, les poignées de
    /// colonnes des tableaux `egui_extras` (dérivées de l'identifiant du parent) entrent
    /// en conflit d'un bloc à l'autre.
    fn show_block(&mut self, block: Block, ui: &mut egui::Ui) {
        let id = match block {
            Block::Disks => "block_disks",
            Block::LargeFiles => "block_large_files",
            Block::Devices => "block_devices",
            Block::Events => "block_events",
        };
        ui.push_id(id, |ui| match block {
            Block::Disks => self.show_disks(ui),
            Block::LargeFiles => self.show_large_files(ui),
            Block::Devices => self.show_devices(ui),
            Block::Events => self.show_events(ui),
        });
    }

    /// Affiche les erreurs et le dernier message d'action.
    fn show_messages(&self, ui: &mut egui::Ui) {
        if let Some(error) = &self.configuration_error {
            ui.colored_label(colors::error(ui), format!("Configuration : {error}"));
        }
        if let Some(error) = &self.data.last_error {
            ui.colored_label(colors::error(ui), format!("Erreur : {error}"));
        }
        if let Some((success, message)) = &self.data.status_message {
            let color = if *success {
                colors::ok(ui)
            } else {
                colors::error(ui)
            };
            ui.colored_label(color, message);
        }
    }

    /// Bloc « Occupation des disques ».
    fn show_disks(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Occupation des disques");
            ui.label(format!(
                "Seuil d'alerte : {:.1} %",
                self.data.threshold_percent
            ));
        });
        if matches!(self.data.monitoring, Some((false, _))) {
            ui.label("Surveillance disque désactivée.");
            return;
        }
        if self.data.disks.is_empty() {
            ui.label("Aucun disque disponible. Vérifiez que le moteur est démarré.");
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("disks_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for disk in &self.data.disks {
                    let ratio = if disk.total_bytes == 0 {
                        0.0
                    } else {
                        disk.used_bytes as f32 / disk.total_bytes as f32
                    };
                    let over = ratio * 100.0 >= self.data.threshold_percent;
                    ui.horizontal(|ui| {
                        ui.strong(&disk.name);
                        ui.label(format!(
                            "{} utilisés sur {}",
                            format_bytes(disk.used_bytes),
                            format_bytes(disk.total_bytes)
                        ));
                    });
                    let mut progress = egui::ProgressBar::new(ratio.clamp(0.0, 1.0))
                        .desired_width(ui.available_width())
                        .text(format!("{:.1} %", ratio * 100.0));
                    if over {
                        progress = progress.fill(colors::error(ui));
                    }
                    ui.add(progress);
                    ui.add_space(4.0);
                }
            });
    }

    /// Bloc « Fichiers volumineux » : analyse, sélection et suppression.
    fn show_large_files(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
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
            if self.data.is_working {
                ui.spinner();
                ui.label("Opération en cours…");
            }
        });
        ui.label(format!(
            "Fichiers d'au moins {} Mio ; les {} plus volumineux sont affichés.",
            self.minimum_file_size_mio, self.maximum_files
        ));

        if self.data.large_files.is_empty() {
            if self.data.has_scanned {
                ui.label("Aucun fichier correspondant trouvé sur les disques accessibles.");
            } else {
                ui.label("Lancez une analyse pour rechercher les fichiers volumineux.");
            }
            return;
        }

        // La ligne d'actions est placée en bas ; le tableau occupe le reste.
        egui::TopBottomPanel::bottom("large_files_actions")
            .frame(egui::Frame::NONE)
            .show_inside(ui, |ui| {
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
            });

        let row_height = ui.spacing().interact_size.y;
        let files = &self.data.large_files;
        let selected_paths = &mut self.data.selected_paths;
        TableBuilder::new(ui)
            .id_salt("large_files_table")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(24.0))
            .column(Column::remainder().at_least(120.0).clip(true))
            .column(Column::auto().at_least(80.0))
            .header(row_height, |mut header| {
                header.col(|_| {});
                header.col(|ui| {
                    ui.strong("Fichier");
                });
                header.col(|ui| {
                    ui.strong("Poids");
                });
            })
            .body(|body| {
                body.rows(row_height, files.len(), |mut row| {
                    let file = &files[row.index()];
                    row.col(|ui| {
                        let mut selected = selected_paths.contains(&file.path);
                        if ui.checkbox(&mut selected, "").changed() {
                            if selected {
                                selected_paths.insert(file.path.clone());
                            } else {
                                selected_paths.remove(&file.path);
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(file_display_name(&file.path)).truncate())
                            .on_hover_text(&file.path);
                    });
                    row.col(|ui| {
                        ui.monospace(format_bytes(file.size_bytes));
                    });
                });
            });
    }

    /// Bloc « Appareils du réseau local ».
    fn show_devices(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Appareils du réseau local");
            if !self.data.devices.is_empty() {
                ui.label(format!("{} appareil(s)", self.data.devices.len()));
            }
        });
        if matches!(self.data.monitoring, Some((_, false))) {
            ui.label("Surveillance réseau désactivée.");
            return;
        }
        if self.data.devices.is_empty() {
            ui.label("Aucun appareil détecté dans la table ARP.");
            return;
        }

        let row_height = ui.spacing().interact_size.y;
        let devices = &self.data.devices;
        let mut edit_request = None;
        let dimmed = colors::dimmed(ui);
        TableBuilder::new(ui)
            .id_salt("devices_table")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(115.0).at_least(80.0).clip(true))
            .column(Column::initial(140.0).at_least(80.0).clip(true))
            .column(Column::remainder().at_least(100.0).clip(true))
            .column(Column::initial(170.0).at_least(80.0).clip(true))
            .column(Column::exact(28.0))
            .header(row_height, |mut header| {
                for title in ["Adresse IP", "Adresse MAC", "Nom", "État", ""] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, devices.len(), |mut row| {
                    let device = &devices[row.index()];
                    let responding = device.scans_manques == 0;
                    let color = if responding { None } else { Some(dimmed) };
                    let cell = |ui: &mut egui::Ui, text: egui::RichText| {
                        let text = match color {
                            Some(color) => text.color(color),
                            None => text,
                        };
                        ui.add(egui::Label::new(text).truncate())
                    };
                    row.col(|ui| {
                        cell(ui, egui::RichText::new(&device.ip));
                    });
                    row.col(|ui| {
                        let response = cell(ui, egui::RichText::new(&device.mac));
                        if device.has_private_mac() {
                            response.on_hover_text(
                                "Adresse MAC privée (aléatoire) : l'appareil peut en changer.",
                            );
                        }
                    });
                    row.col(|ui| {
                        let response = match &device.alias {
                            Some(alias) => cell(ui, egui::RichText::new(alias).strong()),
                            None => cell(
                                ui,
                                egui::RichText::new(device.hostname.as_deref().unwrap_or("—")),
                            ),
                        };
                        let detected = device.hostname.as_deref().unwrap_or("aucun");
                        let response = response
                            .on_hover_text(format!("Nom détecté sur le réseau : {detected}"));
                        if response.double_clicked() {
                            edit_request = Some(device.clone());
                        }
                    });
                    row.col(|ui| {
                        if responding {
                            ui.colored_label(colors::ok(ui), "connecté");
                        } else {
                            ui.colored_label(
                                colors::warning(ui),
                                format!("ne répond plus ({} scan(s))", device.scans_manques),
                            );
                        }
                    });
                    row.col(|ui| {
                        if ui
                            .small_button("✏")
                            .on_hover_text("Donner un nom à cet appareil")
                            .clicked()
                        {
                            edit_request = Some(device.clone());
                        }
                    });
                });
            });

        if let Some(device) = edit_request {
            let text = device.alias.clone().unwrap_or_default();
            self.alias_edit = Some(AliasEdit {
                device,
                text,
                focused: false,
            });
        }
    }

    /// Fenêtre de saisie du nom personnalisé d'un appareil.
    fn show_alias_dialog(&mut self, context: &egui::Context) {
        let Some(edit) = &mut self.alias_edit else {
            return;
        };
        let mut action: Option<Option<String>> = None; // Some(nom) : envoyer ; None : rien
        let mut close = false;
        egui::Window::new("Nommer l'appareil")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(context, |ui| {
                egui::Grid::new("alias_device_info")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label("Adresse IP");
                        ui.monospace(&edit.device.ip);
                        ui.end_row();
                        ui.label("Adresse MAC");
                        ui.monospace(&edit.device.mac);
                        ui.end_row();
                        ui.label("Nom détecté");
                        ui.label(edit.device.hostname.as_deref().unwrap_or("aucun"));
                        ui.end_row();
                    });
                if edit.device.has_private_mac() {
                    ui.colored_label(
                        colors::warning(ui),
                        "Adresse MAC privée : si l'appareil en change, le nom ne le suivra pas.",
                    );
                }
                ui.add_space(6.0);
                let response = ui.add(
                    egui::TextEdit::singleline(&mut edit.text)
                        .hint_text("Ex. : Caméra entrée")
                        .char_limit(MAX_ALIAS_CHARS)
                        .desired_width(280.0),
                );
                if !edit.focused {
                    response.request_focus();
                    edit.focused = true;
                }
                let submitted =
                    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Enregistrer").clicked() || submitted {
                        action = Some(Some(edit.text.trim().to_owned()));
                    }
                    if edit.device.alias.is_some() && ui.button("Retirer le nom").clicked() {
                        action = Some(Some(String::new()));
                    }
                    if ui.button("Annuler").clicked()
                        || ui.input(|input| input.key_pressed(egui::Key::Escape))
                    {
                        close = true;
                    }
                });
            });

        if let Some(Some(alias)) = action {
            let mac = edit.device.mac.clone();
            match self.requests.send(MessageClientToEngine::SetDeviceAlias {
                mac: mac.clone(),
                alias: alias.clone(),
            }) {
                Ok(()) => {
                    // Affichage immédiat, confirmé au prochain état reçu du moteur.
                    let alias = Some(alias).filter(|alias| !alias.is_empty());
                    for device in self.data.devices.iter_mut().filter(|d| d.mac == mac) {
                        device.alias = alias.clone();
                    }
                    close = true;
                }
                Err(error) => {
                    self.data.last_error =
                        Some(format!("Impossible d'enregistrer le nom : {error}"));
                }
            }
        }
        if close {
            self.alias_edit = None;
        }
    }

    /// Bloc « Mouvements récents » : connexions et déconnexions, la plus récente en premier.
    fn show_events(&mut self, ui: &mut egui::Ui) {
        ui.heading("Mouvements récents");
        let movements: Vec<_> = self
            .data
            .network_events
            .iter()
            .rev()
            .filter(|event| event.kind != NetworkEventKind::Present)
            .collect();
        if movements.is_empty() {
            ui.label("Aucune connexion ni déconnexion depuis le démarrage du moteur.");
            return;
        }

        let row_height = ui.spacing().interact_size.y;
        TableBuilder::new(ui)
            .id_salt("events_table")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(150.0).at_least(80.0).clip(true))
            .column(Column::initial(100.0).at_least(70.0).clip(true))
            .column(Column::initial(250.0).at_least(100.0).clip(true))
            .column(Column::remainder().at_least(80.0).clip(true))
            .header(row_height, |mut header| {
                for title in ["Heure", "Mouvement", "Appareil", "Nom"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, movements.len(), |mut row| {
                    let event = movements[row.index()];
                    row.col(|ui| {
                        ui.monospace(&event.timestamp);
                    });
                    row.col(|ui| {
                        if event.kind == NetworkEventKind::Deconnexion {
                            ui.colored_label(colors::error(ui), "Déconnexion");
                        } else {
                            ui.colored_label(colors::ok(ui), "Connexion");
                        }
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(format!("{} ({})", event.device.ip, event.device.mac))
                                .truncate(),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(event.device.display_name().unwrap_or("—")).truncate(),
                        );
                    });
                });
            });
    }

    /// Fenêtre de confirmation de suppression des fichiers sélectionnés.
    fn show_deletion_dialog(&mut self, context: &egui::Context) {
        if !self.data.confirm_deletion {
            return;
        }
        egui::Window::new("Confirmer la suppression")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
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
                                self.data.last_error =
                                    Some(format!("Impossible d'envoyer la suppression : {error}"));
                            }
                        }
                    }
                });
            });
    }
}

impl eframe::App for NetDiskMonitorApp {
    /// Dessine la fenêtre et demande le traitement des réponses réseau disponibles.
    ///
    /// Les blocs se partagent la hauteur de la fenêtre ; au-delà de `TWO_COLUMNS_MIN_WIDTH`
    /// pixels de large, ils sont répartis sur deux colonnes.
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_updates(context);

        egui::TopBottomPanel::top("header").show(context, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("NetDiskMonitor");
                ui.separator();
                self.show_monitoring_toggles(ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!(
                        "Actualisation toutes les {} secondes",
                        self.refresh_interval.as_secs()
                    ));
                });
            });
        });

        // Les panneaux du bas doivent être déclarés avant le panneau central.
        egui::TopBottomPanel::bottom("footer").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Moteur : {}", self.engine_address));
                ui.separator();
                ui.label("État actualisé automatiquement");
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            self.show_messages(ui);

            let mut layout = self.layout;
            if ui.available_width() >= TWO_COLUMNS_MIN_WIDTH {
                ui.columns(2, |columns| {
                    let (left, right) = columns.split_at_mut(1);
                    stacked_blocks(&mut left[0], &mut layout.left, |index, ui| {
                        let block = [Block::Disks, Block::LargeFiles][index];
                        self.show_block(block, ui);
                    });
                    stacked_blocks(&mut right[0], &mut layout.right, |index, ui| {
                        let block = [Block::Devices, Block::Events][index];
                        self.show_block(block, ui);
                    });
                });
            } else {
                stacked_blocks(ui, &mut layout.single, |index, ui| {
                    let block = [
                        Block::Disks,
                        Block::LargeFiles,
                        Block::Devices,
                        Block::Events,
                    ][index];
                    self.show_block(block, ui);
                });
            }
            self.layout = layout;
        });

        self.show_deletion_dialog(context);
        self.show_alias_dialog(context);
    }
}

/// Démarre le client graphique et la tâche de récupération des états du moteur.
///
/// Entrées : arguments de ligne de commande ignorés.
/// Sortie : résultat eframe, avec une erreur si la fenêtre ne peut pas être créée.
fn main() -> Result<(), eframe::Error> {
    let (updates_tx, updates_rx) = mpsc::channel();
    let (config, configuration_error) = match load_ui_config() {
        Ok(config) => (config, None),
        Err(error) => (Config::default(), Some(error)),
    };
    let (requests_tx, requests_rx) = tokio_mpsc::unbounded_channel();
    start_status_polling(
        updates_tx,
        requests_rx,
        config.adresse_moteur.clone(),
        Duration::from_secs(config.intervalle_actualisation_ihm_secondes),
    );

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([config.largeur_fenetre_ihm, config.hauteur_fenetre_ihm])
            .with_min_inner_size([
                config.largeur_min_fenetre_ihm,
                config.hauteur_min_fenetre_ihm,
            ]),
        ..Default::default()
    };

    eframe::run_native(
        "NetDiskMonitor",
        options,
        Box::new(move |_creation_context| {
            Ok(Box::new(NetDiskMonitorApp::new(
                updates_rx,
                requests_tx,
                config,
                configuration_error,
            )))
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
    engine_address: String,
    refresh_interval: Duration,
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
            let mut ticker = tokio::time::interval(refresh_interval);
            loop {
                let request = tokio::select! {
                    _ = ticker.tick() => MessageClientToEngine::GetStatus,
                    request = requests.recv() => match request {
                        Some(request) => request,
                        None => break,
                    },
                };
                let result = request_engine(request, &engine_address).await;
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
async fn request_engine(
    request: MessageClientToEngine,
    engine_address: &str,
) -> Result<MessageEngineToClient, String> {
    // L'analyse des disques et la suppression peuvent être longues : pas de délai de réponse.
    let response_timeout = match request {
        MessageClientToEngine::ScanLargeFiles | MessageClientToEngine::DeleteFiles { .. } => None,
        _ => Some(RESPONSE_TIMEOUT),
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(engine_address))
        .await
        .map_err(|_| "Délai de connexion au moteur dépassé.".to_owned())?
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
    let mut reader = BufReader::new(read_half);
    let read = reader.read_line(&mut response_line);
    match response_timeout {
        Some(limit) => tokio::time::timeout(limit, read)
            .await
            .map_err(|_| "Le moteur n'a pas répondu à temps.".to_owned())?,
        None => read.await,
    }
    .map_err(|error| error.to_string())?;
    if response_line.is_empty() {
        return Err("Le moteur a fermé la connexion sans réponse.".into());
    }
    serde_json::from_str(&response_line)
        .map_err(|error| format!("Réponse du moteur invalide : {error}"))
}

fn load_ui_config() -> Result<Config, String> {
    let contents = std::fs::read_to_string("config.toml")
        .map_err(|error| format!("Impossible de lire config.toml : {error}"))?;
    parse_ui_config(&contents)
}

fn parse_ui_config(contents: &str) -> Result<Config, String> {
    let config: Config = toml::from_str(contents)
        .map_err(|error| format!("Fichier config.toml invalide : {error}"))?;
    config
        .validate()
        .map_err(|error| format!("Configuration invalide : {error}"))?;
    Ok(config)
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

fn file_display_name(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    normalized
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{file_display_name, format_bytes, parse_ui_config};

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

    #[test]
    fn displays_file_name_without_hiding_its_full_path() {
        assert_eq!(
            file_display_name(r"C:\Users\test\large-file.iso"),
            "large-file.iso"
        );
    }

    #[test]
    fn reads_all_ui_settings_from_the_shared_config_file() {
        let config =
            parse_ui_config(include_str!("../../config.toml")).expect("parse shared config");

        assert_eq!(config.adresse_moteur, "127.0.0.1:7878");
        assert_eq!(config.intervalle_actualisation_ihm_secondes, 3);
        assert_eq!(config.taille_min_fichier_volumineux_mio, 100);
        assert_eq!(config.nombre_max_fichiers_volumineux, 100);
    }
}
