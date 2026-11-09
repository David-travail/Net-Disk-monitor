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
* **Suppression ciblée de fichiers :** Offre à l'utilisateur (via l'IHM) la possibilité de sélectionner et supprimer un ou plusieurs fichiers/dossiers volumineux directement depuis l'application.

### B. Scrutation du Réseau Local (`network_monitor`)
* **Détection d'appareils :** Scanne périodiquement le réseau local (intervalle paramétrable) à la recherche de nouvelles machines ou adresses IP/MAC connectées.
* **Alertes & Journalisation :** Détecte l'arrivée de nouveaux équipements inconnus sur le LAN et notifie le système ou l'utilisateur.

### C. Gestion Dynamique des Tâches & Configuration
* **Tâches modulaires :** Le moteur est lancé avec les deux tâches activées par défaut.
* **Activation/Désactivation à chaud :** Possibilité de désactiver l'une des tâches, les deux, ou de réactiver à la demande via les paramètres transmises par l'IHM.

---

## 3. Stack Technique & Crates Rust

* **Langage & Standard :** Rust 2021 Edition.
* **Architecture :** Cargo Workspace (`engine`, `common`, `ui`).
* **Runtime Asynchrone :** `tokio` (multithreading et boucles de scrutation).
* **Information Système & Disques :** `sysinfo` (multi-plateforme Linux/Windows/macOS).
* **Envoi d'alertes Telegram :** `reqwest` / API HTTP Telegram Bot.
* **Découverte Réseau (LAN) :** Scan ARP / Analyse de `/proc/net/arp` / Pings actifs via sockets TCP/ICMP.
* **Communication Moteur <-> IHM :** WebSockets (`tokio-tungstenite`) ou sockets TCP personnalisés avec sérialisation/désérialisation JSON (`serde` / `serde_json`).

---

## 4. Architecture du Cargo Workspace

```text
net_disk_monitor/
├── Cargo.toml                  # Workspace Racine
├── .github/
│   └── copilot-instructions.md # Ce fichier d'instructions
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

Le module `common` contient les structures partagées entre le Moteur et l'IHM :

```rust
use serde::{Deserialize, Serialize};

/// Configuration générale du système
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub activer_surveillance_disque: bool,
    pub intervalle_scrutation_disque_secondes: u64,
    pub seuil_alerte_disque_pourcentage: f32,
    pub jeton_bot_telegram: String,
    pub identifiant_chat_telegram: String,

    pub activer_surveillance_reseau: bool,
    pub intervalle_scrutation_reseau_secondes: u64,
}

/// Ordres envoyés par l'IHM au Moteur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageClientToEngine {
    GetStatus,
    DeleteFiles { paths: Vec<String> },
    UpdateConfig(Config),
}

/// Réponses envoyées par le Moteur à l'IHM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageEngineToClient {
    StatusSnapshot {
        disk_info: Vec<DiskDetails>,
        connected_devices: Vec<DeviceDetails>,
    },
    ActionResult { success: bool, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskDetails {
    pub name: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDetails {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
}
```

---

## 6. Consignes pour la Génération de Code (Copilot)

1. **Idiomatique & Robuste :** Toujours privilégier la gestion des erreurs avec `Result` et le pattern matching. Ne pas faire de `unwrap()` non sécurisé dans le moteur.
2. **Asynchronisme :** Utiliser `tokio::spawn` pour isoler la scrutation disque, la scrutation réseau et le serveur de communication de l'IHM.
3. **Portabilité :** S'assurer que le code est compilable sur Linux (Raspberry Pi OS, Debian) et Windows sans modification de code applicatif.