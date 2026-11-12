//! Types communs sérialisables échangés entre le moteur NetDiskMonitor et son client.
//!
//! Fonctions :
//! - [`Config::default`] : crée la configuration initiale du moteur.
//! - `default_config_enables_both_monitors_without_credentials` : vérifie la configuration initiale.
//! - `messages_round_trip_as_json` : vérifie la sérialisation des messages JSON.

use serde::{Deserialize, Serialize};

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
        {
            return Err("Les intervalles et délais doivent être supérieurs à zéro.");
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
    ScanLargeFiles,
    DeleteFiles { paths: Vec<String> },
    UpdateConfig(Config),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageEngineToClient {
    StatusSnapshot {
        disk_info: Vec<DiskDetails>,
        connected_devices: Vec<DeviceDetails>,
        seuil_alerte_disque_pourcentage: f32,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceDetails {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
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

        let scan_request = MessageClientToEngine::ScanLargeFiles;
        let encoded = serde_json::to_string(&scan_request).expect("serialize scan request");
        let decoded: MessageClientToEngine =
            serde_json::from_str(&encoded).expect("deserialize scan request");
        assert!(matches!(decoded, MessageClientToEngine::ScanLargeFiles));

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
