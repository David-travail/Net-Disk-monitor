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
    pub identifiant_chat_telegram: String,
    pub activer_surveillance_reseau: bool,
    pub intervalle_scrutation_reseau_secondes: u64,
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
            identifiant_chat_telegram: String::new(),
            activer_surveillance_reseau: true,
            intervalle_scrutation_reseau_secondes: 30,
        }
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
