//! Types communs sérialisables échangés entre le moteur NetDiskMonitor et son client.
//!
//! Fonctions :
//! - [`Config::default`] : crée la configuration initiale du moteur.
//! - `default_config_enables_both_monitors_without_credentials` : vérifie la configuration initiale.
//! - `messages_round_trip_as_json` : vérifie la sérialisation des messages JSON.

use serde::{Deserialize, Serialize};

pub mod telegram;

/// Configuration globale du moteur.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub activer_surveillance_disque: bool,
    pub intervalle_scrutation_disque_secondes: u64,
    pub seuil_alerte_disque_pourcentage: f32,
    pub jeton_bot_telegram: String,
    pub delai_http_telegram_secondes: u64,
    pub identifiant_chat_telegram: String,
    pub activer_surveillance_reseau: bool,
    pub intervalle_scrutation_reseau_secondes: u64,
    pub alerte_nouvel_appareil_telegram: bool,
    /// Message Telegram au démarrage et à l'arrêt du moteur et de l'IHM.
    pub alerte_demarrage_arret_telegram: bool,
    /// Message Telegram à chaque connexion ou déconnexion d'appareil.
    pub alerte_connexion_deconnexion_telegram: bool,
    pub scans_manques_avant_deconnexion: u8,
    /// Nombre de jours de conservation des journaux réseau archivés.
    pub duree_conservation_journaux_jours: u32,
    pub taille_min_fichier_volumineux_mio: u64,
    pub nombre_max_fichiers_volumineux: usize,
    pub adresse_ecoute_moteur: String,
    pub adresse_moteur: String,
    pub intervalle_actualisation_ihm_secondes: u64,
    pub largeur_fenetre_ihm: f32,
    pub hauteur_fenetre_ihm: f32,
    pub largeur_min_fenetre_ihm: f32,
    pub hauteur_min_fenetre_ihm: f32,
}

impl Default for Config {
    /// Construit la configuration initiale avec les deux surveillances activées.
    ///
    /// Entrées : aucune.
    /// Sortie : configuration avec intervalles et seuil par défaut, sans identifiants Telegram.
    fn default() -> Self {
        Self {
            activer_surveillance_disque: true,
            intervalle_scrutation_disque_secondes: 60,
            seuil_alerte_disque_pourcentage: 85.0,
            jeton_bot_telegram: String::new(),
            delai_http_telegram_secondes: 10,
            identifiant_chat_telegram: String::new(),
            activer_surveillance_reseau: true,
            intervalle_scrutation_reseau_secondes: 30,
            alerte_nouvel_appareil_telegram: true,
            alerte_demarrage_arret_telegram: true,
            alerte_connexion_deconnexion_telegram: true,
            scans_manques_avant_deconnexion: 2,
            duree_conservation_journaux_jours: 10,
            taille_min_fichier_volumineux_mio: 100,
            nombre_max_fichiers_volumineux: 100,
            adresse_ecoute_moteur: "127.0.0.1:7878".to_owned(),
            adresse_moteur: "127.0.0.1:7878".to_owned(),
            intervalle_actualisation_ihm_secondes: 3,
            largeur_fenetre_ihm: 900.0,
            hauteur_fenetre_ihm: 760.0,
            largeur_min_fenetre_ihm: 680.0,
            hauteur_min_fenetre_ihm: 520.0,
        }
    }
}

impl Config {
    /// Vérifie les valeurs configurables avant leur utilisation.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.intervalle_scrutation_disque_secondes == 0
            || self.intervalle_scrutation_reseau_secondes == 0
            || self.intervalle_actualisation_ihm_secondes == 0
            || self.delai_http_telegram_secondes == 0
            || self.scans_manques_avant_deconnexion == 0
            || self.duree_conservation_journaux_jours == 0
        {
            return Err(
                "Les intervalles, délais, nombres de scans manqués et durée de conservation des journaux doivent être supérieurs à zéro.",
            );
        }
        if !self.seuil_alerte_disque_pourcentage.is_finite()
            || !(0.0..=100.0).contains(&self.seuil_alerte_disque_pourcentage)
        {
            return Err("Le seuil d'alerte disque doit être compris entre 0 et 100.");
        }
        if self.taille_min_fichier_volumineux_mio == 0
            || self
                .taille_min_fichier_volumineux_mio
                .checked_mul(1024 * 1024)
                .is_none()
            || self.nombre_max_fichiers_volumineux == 0
            || self.nombre_max_fichiers_volumineux > 10_000
        {
            return Err("Les réglages d'analyse des fichiers sont invalides.");
        }
        if self.adresse_ecoute_moteur.trim().is_empty() || self.adresse_moteur.trim().is_empty() {
            return Err("Les adresses réseau du moteur ne peuvent pas être vides.");
        }
        if [
            self.largeur_fenetre_ihm,
            self.hauteur_fenetre_ihm,
            self.largeur_min_fenetre_ihm,
            self.hauteur_min_fenetre_ihm,
        ]
        .iter()
        .any(|dimension| !dimension.is_finite() || *dimension <= 0.0)
        {
            return Err("Les dimensions de la fenêtre doivent être positives et finies.");
        }
        if self.largeur_fenetre_ihm < self.largeur_min_fenetre_ihm
            || self.hauteur_fenetre_ihm < self.hauteur_min_fenetre_ihm
        {
            return Err(
                "La fenêtre initiale doit être au moins aussi grande que sa taille minimale.",
            );
        }
        if self.jeton_bot_telegram.is_empty() != self.identifiant_chat_telegram.is_empty() {
            return Err(
                "Le jeton Telegram et l'identifiant du chat doivent être configurés ensemble.",
            );
        }
        Ok(())
    }
}

/// Messages JSON échangés sur une connexion TCP, un message par ligne.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageClientToEngine {
    GetStatus,
    /// Recherche les gros fichiers sur les disques indiqués (points de montage) ;
    /// une liste vide signifie « tous les disques ».
    ScanLargeFiles {
        disques: Vec<String>,
    },
    DeleteFiles {
        paths: Vec<String>,
    },
    UpdateConfig(Config),
    /// Active ou désactive à chaud les surveillances, sans modifier `config.toml`.
    SetMonitoring {
        disque: bool,
        reseau: bool,
    },
    /// Associe un nom personnalisé à une adresse MAC ; un nom vide supprime l'association.
    SetDeviceAlias {
        mac: String,
        alias: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageEngineToClient {
    StatusSnapshot {
        disk_info: Vec<DiskDetails>,
        connected_devices: Vec<DeviceDetails>,
        seuil_alerte_disque_pourcentage: f32,
        surveillance_disque_active: bool,
        surveillance_reseau_active: bool,
        /// Derniers mouvements réseau, du plus ancien au plus récent.
        network_events: Vec<NetworkEventDetails>,
    },
    LargeFilesSnapshot {
        files: Vec<LargeFileDetails>,
    },
    FilesDeleted {
        success: bool,
        message: String,
    },
    ActionResult {
        success: bool,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiskDetails {
    pub name: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDetails {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    /// Nombre de scans consécutifs sans réponse (0 si l'appareil vient de répondre).
    #[serde(default)]
    pub scans_manques: u8,
    /// Nom personnalisé donné par l'utilisateur, prioritaire sur `hostname`.
    #[serde(default)]
    pub alias: Option<String>,
    /// Machine sur laquelle tourne le moteur (toujours connectée, jamais journalisée).
    #[serde(default)]
    pub cette_machine: bool,
}

impl DeviceDetails {
    /// Nom à afficher : nom personnalisé, sinon nom découvert sur le réseau.
    pub fn display_name(&self) -> Option<&str> {
        self.alias.as_deref().or(self.hostname.as_deref())
    }

    /// Indique une adresse MAC privée (aléatoire), que l'appareil peut changer.
    pub fn has_private_mac(&self) -> bool {
        u8::from_str_radix(self.mac.get(0..2).unwrap_or("00"), 16)
            .map(|first| first & 0x02 != 0)
            .unwrap_or(false)
    }
}

/// Longueur maximale d'un nom personnalisé d'appareil, en caractères.
pub const MAX_ALIAS_CHARS: usize = 64;

/// Nature d'un mouvement d'appareil sur le réseau local.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkEventKind {
    /// Appareil déjà présent lors du premier scan.
    Present,
    Connexion,
    Deconnexion,
}

impl NetworkEventKind {
    /// Libellé utilisé dans la console et dans `network_events.log`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "PRESENT",
            Self::Connexion => "CONNEXION",
            Self::Deconnexion => "DECONNEXION",
        }
    }
}

/// Mouvement horodaté d'un appareil.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEventDetails {
    /// Date et heure locales au format `AAAA-MM-JJ HH:MM:SS`.
    pub timestamp: String,
    pub kind: NetworkEventKind,
    pub device: DeviceDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LargeFileDetails {
    pub path: String,
    pub size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::{Config, LargeFileDetails, MessageClientToEngine, MessageEngineToClient};

    #[test]
    /// Vérifie que la configuration par défaut active les deux surveillances sans identifiants.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si une assertion n'est pas satisfaite.
    fn default_config_enables_both_monitors_without_credentials() {
        let config = Config::default();

        assert!(config.activer_surveillance_disque);
        assert!(config.activer_surveillance_reseau);
        assert!(config.jeton_bot_telegram.is_empty());
        assert!(config.identifiant_chat_telegram.is_empty());
    }

    #[test]
    /// Vérifie le nom affiché et la détection des adresses MAC privées.
    fn device_display_name_and_private_mac() {
        let mut device = super::DeviceDetails {
            ip: "192.168.1.10".to_owned(),
            mac: "06:79:79:bb:d8:34".to_owned(),
            hostname: Some("Myrtille".to_owned()),
            scans_manques: 0,
            alias: None,
            cette_machine: false,
        };
        assert_eq!(device.display_name(), Some("Myrtille"));
        assert!(device.has_private_mac());

        device.alias = Some("Téléphone".to_owned());
        device.mac = "ec:71:db:9d:67:da".to_owned();
        assert_eq!(device.display_name(), Some("Téléphone"));
        assert!(!device.has_private_mac());
    }

    #[test]
    /// Vérifie que les messages client et moteur sont sérialisables puis désérialisables en JSON.
    ///
    /// Entrées : aucune.
    /// Sortie : aucune ; le test échoue si un aller-retour JSON est incorrect.
    fn messages_round_trip_as_json() {
        let request = MessageClientToEngine::GetStatus;
        let encoded = serde_json::to_string(&request).expect("serialize request");
        let decoded: MessageClientToEngine =
            serde_json::from_str(&encoded).expect("deserialize request");
        assert!(matches!(decoded, MessageClientToEngine::GetStatus));

        let scan_request = MessageClientToEngine::ScanLargeFiles {
            disques: vec!["/".to_owned()],
        };
        let encoded = serde_json::to_string(&scan_request).expect("serialize scan request");
        let decoded: MessageClientToEngine =
            serde_json::from_str(&encoded).expect("deserialize scan request");
        assert!(matches!(
            decoded,
            MessageClientToEngine::ScanLargeFiles { disques } if disques == ["/"]
        ));

        let toggle_request = MessageClientToEngine::SetMonitoring {
            disque: false,
            reseau: true,
        };
        let encoded = serde_json::to_string(&toggle_request).expect("serialize toggle request");
        let decoded: MessageClientToEngine =
            serde_json::from_str(&encoded).expect("deserialize toggle request");
        assert!(matches!(
            decoded,
            MessageClientToEngine::SetMonitoring {
                disque: false,
                reseau: true
            }
        ));

        let files_response = MessageEngineToClient::LargeFilesSnapshot {
            files: vec![LargeFileDetails {
                path: "C:\\data\\archive.bin".to_owned(),
                size_bytes: 1024,
            }],
        };
        let encoded = serde_json::to_string(&files_response).expect("serialize files response");
        let decoded: MessageEngineToClient =
            serde_json::from_str(&encoded).expect("deserialize files response");
        assert!(matches!(
            decoded,
            MessageEngineToClient::LargeFilesSnapshot { files } if files.len() == 1
        ));

        let response = MessageEngineToClient::ActionResult {
            success: true,
            message: "ok".to_owned(),
        };
        let encoded = serde_json::to_string(&response).expect("serialize response");
        let decoded: MessageEngineToClient =
            serde_json::from_str(&encoded).expect("deserialize response");
        assert!(matches!(
            decoded,
            MessageEngineToClient::ActionResult { success: true, .. }
        ));
    }
}
