# Spécifications du projet : NetDiskMonitor (Moteur & IHM)

Ce document récapitule l'architecture, les fonctionnalités et les technologies du projet **NetDiskMonitor**. Il sert de guide contextuel pour le développement et pour GitHub Copilot.

---

## 1. Vision et Objectifs du Projet

**NetDiskMonitor** est un utilitaire système modulaire écrit en **Rust**, conçu pour tourner aussi bien sur PC (Linux / Windows) que sur Raspberry Pi 5.

L'application repose sur le modèle **Client / Serveur (Moteur + IHM)** :
* **Un Moteur (Daemon) :** Tourne en arrière-plan de manière permanente.
* **Une Interface Client (IHM) :** Peut s'y connecter ou s'en déconnecter à tout moment sans perturber l'exécution des tâches du moteur.

---

## 2. Fonctionnalités Principales

### A. Scrutation de l'Occupation Disque (`disk_monitor`)
* **Surveillance continue :** Évalue l'espace libre et utilisé des partitions système à intervalle paramétrable.
* **Alertes Telegram :** Émet une alerte automatique via l'API Telegram Bot dès que l'occupation dépasse un seuil paramétrable (ex: 85% ou 90%).
* **Suppression ciblée de fichiers :** Offre à l'utilisateur (via l'IHM) la possibilité d'analyser les disques, puis de sélectionner et supprimer un ou plusieurs fichiers volumineux directement depuis l'application. L'utilisateur choisit le ou les disques à analyser ; un disque est parcouru sans descendre dans les autres disques montés à l'intérieur. Seuls les fichiers réguliers issus de la dernière analyse peuvent être supprimés (pas de dossiers).

### B. Scrutation du Réseau Local (`network_monitor`)
* **Détection d'appareils :** Scanne périodiquement le réseau local (intervalle paramétrable) à la recherche de nouvelles machines ou adresses IP/MAC connectées. Seules les interfaces physiques sont balayées (VPN et interfaces virtuelles exclus). Sous macOS, les entrées ARP expirées sont écartées (`arp -anx`). Un appareil est déclaré déconnecté après `scans_manques_avant_deconnexion` scans sans réponse.
* **Noms des appareils :** découverte automatique par mDNS unicast puis DNS inverse ; noms personnalisés saisis dans l'IHM (message `SetDeviceAlias`), associés à l'adresse MAC et enregistrés par le moteur dans `noms_appareils.toml`.
* **Mouvements dans l'IHM :** L'état de chaque appareil (connecté / ne répond plus) et les dernières connexions/déconnexions sont transmis dans `StatusSnapshot`.
* **Alertes & Journalisation :** Journalise les présences, connexions et déconnexions (console et `network_events.log`, archivé chaque jour en `network_events_AAAA-MM-JJ.log` et conservé `duree_conservation_journaux_jours` jours). Un appareil jamais vu depuis le démarrage du moteur déclenche une alerte Telegram (réglage `alerte_nouvel_appareil_telegram`).

### C. Gestion Dynamique des Tâches & Configuration
* **Tâches modulaires :** Le moteur est lancé avec les deux tâches activées par défaut.
* **Activation/Désactivation à chaud :** Possibilité de désactiver l'une des tâches, les deux, ou de réactiver à la demande via les cases à cocher de l'IHM (message `SetMonitoring`). Ce changement n'est pas enregistré dans `config.toml`.

---

## 3. Stack Technique & Crates Rust

* **Langage & Standard :** Rust 2021 Edition.
* **Architecture :** Cargo Workspace (`engine`, `common`, `ui`).
* **Runtime Asynchrone :** `tokio` (multithreading et boucles de scrutation).
* **Information Système & Disques :** `sysinfo` (multi-plateforme Linux/Windows/macOS).
* **Envoi d'alertes Telegram :** `reqwest` / API HTTP Telegram Bot.
* **Découverte Réseau (LAN) :** Scan ARP / Analyse de `/proc/net/arp` / Pings actifs via sockets TCP/ICMP.
* **Communication Moteur <-> IHM :** sockets TCP, une connexion par requête, un message JSON par ligne dans chaque sens (`serde` / `serde_json`).
* **Interface graphique :** `eframe` / `egui`.
* **Configuration :** fichier `config.toml` partagé par le moteur et l'IHM (`toml`).

---

## 4. Architecture du Cargo Workspace

```text
net_disk_monitor/
├── Cargo.toml                  # Workspace Racine
├── config.toml                 # Configuration partagée moteur / IHM
├── GUIDE_LANCEMENT.md          # Guide de lancement
├── specifications_et_instructions_copilot.md  # Ce fichier d'instructions
├── common/                     # Crate bibliothèque partagée (Types, Messages, DTOs)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
├── engine/                     # Crate Moteur / Daemon (Service permanent)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
└── ui/                         # Crate Interface Client (CLI / TUI / GUI)
    ├── Cargo.toml
    └── src/
        └── main.rs
```

---

## 5. Structures de Données Essentielles (`common`)

Le module `common` contient les structures partagées entre le Moteur et l'IHM (extrait de `common/src/lib.rs`) :

```rust
use serde::{Deserialize, Serialize};

/// Configuration générale du système, lue depuis `config.toml`.
/// Les champs absents prennent leur valeur par défaut (`#[serde(default)]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    // Surveillance disque
    pub activer_surveillance_disque: bool,
    pub intervalle_scrutation_disque_secondes: u64,
    pub seuil_alerte_disque_pourcentage: f32,
    // Telegram (désactivé si les deux champs sont vides)
    pub jeton_bot_telegram: String,
    pub delai_http_telegram_secondes: u64,
    pub identifiant_chat_telegram: String,
    // Surveillance réseau
    pub activer_surveillance_reseau: bool,
    pub intervalle_scrutation_reseau_secondes: u64,
    pub alerte_nouvel_appareil_telegram: bool,
    pub scans_manques_avant_deconnexion: u8,
    // Analyse des fichiers volumineux
    pub taille_min_fichier_volumineux_mio: u64,
    pub nombre_max_fichiers_volumineux: usize,
    // Réseau moteur / IHM
    pub adresse_ecoute_moteur: String,
    pub adresse_moteur: String,
    // IHM
    pub intervalle_actualisation_ihm_secondes: u64,
    pub largeur_fenetre_ihm: f32,
    pub hauteur_fenetre_ihm: f32,
    pub largeur_min_fenetre_ihm: f32,
    pub hauteur_min_fenetre_ihm: f32,
}
// `Config::validate()` vérifie intervalles, seuil, analyse, adresses, fenêtre et Telegram.

/// Ordres envoyés par l'IHM au Moteur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageClientToEngine {
    GetStatus,
    ScanLargeFiles { disques: Vec<String> }, // points de montage ; vide = tous
    DeleteFiles { paths: Vec<String> },
    UpdateConfig(Config),
    SetMonitoring { disque: bool, reseau: bool },
    SetDeviceAlias { mac: String, alias: String }, // alias vide = suppression
}

/// Réponses envoyées par le Moteur à l'IHM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageEngineToClient {
    StatusSnapshot {
        disk_info: Vec<DiskDetails>,
        connected_devices: Vec<DeviceDetails>,
        seuil_alerte_disque_pourcentage: f32,
        surveillance_disque_active: bool,
        surveillance_reseau_active: bool,
        network_events: Vec<NetworkEventDetails>,
    },
    LargeFilesSnapshot { files: Vec<LargeFileDetails> },
    FilesDeleted { success: bool, message: String },
    ActionResult { success: bool, message: String },
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
    #[serde(default)]
    pub scans_manques: u8,
    #[serde(default)]
    pub alias: Option<String>, // nom personnalisé, prioritaire sur hostname
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkEventKind { Present, Connexion, Deconnexion }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEventDetails {
    pub timestamp: String, // AAAA-MM-JJ HH:MM:SS
    pub kind: NetworkEventKind,
    pub device: DeviceDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LargeFileDetails {
    pub path: String,
    pub size_bytes: u64,
}
```

---

## 6. Consignes pour la Génération de Code (Copilot)

1. **Idiomatique & Robuste :** Toujours privilégier la gestion des erreurs avec `Result` et le pattern matching. Ne pas faire de `unwrap()` non sécurisé dans le moteur.
2. **Asynchronisme :** Utiliser `tokio::spawn` pour isoler la scrutation disque, la scrutation réseau et le serveur de communication de l'IHM.
3. **Portabilité :** S'assurer que le code est compilable sur Linux (Raspberry Pi OS, Debian), Windows et macOS sans modification de code applicatif.