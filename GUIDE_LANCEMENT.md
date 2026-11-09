# Lancer NetDiskMonitor

## Prérequis

- Rust et Cargo installés.
- Un terminal ouvert à la racine du projet, dans le dossier contenant `Cargo.toml`.

Les commandes ci-dessous fonctionnent dans PowerShell, Windows Terminal et les terminaux Linux/macOS.

## Régler les intervalles de scrutation

Modifiez le fichier `config.toml` à la racine du projet avant de lancer le moteur :

```toml
# Intervalle de vérification des disques, en secondes.
intervalle_scrutation_disque_secondes = 60

# Intervalle de lecture de la table ARP, en secondes.
intervalle_scrutation_reseau_secondes = 30

# Alerte quand l'occupation d'un disque atteint ce pourcentage.
seuil_alerte_disque_pourcentage = 85.0

# Facultatif : a renseigner lors de la configuration Telegram.
jeton_bot_telegram = ""
identifiant_chat_telegram = ""
```

Les intervalles sont exprimés en secondes et doivent être supérieurs à zéro. Le seuil doit être compris entre 0 et 100. Telegram reste inactif tant que le jeton du bot ou l'identifiant du chat n'est pas renseigné. Le moteur lit ce fichier au démarrage ; redémarrez-le pour appliquer les modifications. Si le fichier est absent, il est créé automatiquement avec les intervalles, le seuil et des identifiants Telegram vides.

## Lancer le serveur seul

Dans un terminal, à la racine du projet :

```powershell
cargo run -p engine
```

Le moteur démarre la surveillance disque et réseau, puis écoute les connexions du client sur `127.0.0.1:7878`. Laissez ce terminal ouvert pour que le moteur continue de fonctionner.

Pour arrêter le moteur, faites `Ctrl+C` dans ce terminal.

## Lancer le serveur puis le client UI

1. Dans un premier terminal, démarrez le moteur :

   ```powershell
   cargo run -p engine
   ```

2. Ouvrez un second terminal à la racine du projet et lancez le client :

   ```powershell
   cargo run -p ui
   ```

Le client ouvre une fenêtre graphique qui affiche l'occupation des disques et les appareils présents dans la table ARP. Le bouton d'analyse recherche les fichiers d'au moins 100 Mio (au maximum 100 résultats) sur les disques accessibles ; sélectionnez ensuite les fichiers à supprimer et confirmez l'action. Les données de statut sont actualisées automatiquement toutes les trois secondes. Si le moteur ne répond pas, un message d'erreur s'affiche dans la fenêtre et le client continue de réessayer.

Le client peut être démarré même si le serveur n'est pas encore lancé : la fenêtre indique l'erreur de connexion et réessaie automatiquement. Arrêtez le moteur avec `Ctrl+C` dans le premier terminal et fermez la fenêtre du client normalement.

## Compiler sans lancer

Pour compiler tous les composants du workspace :

```powershell
cargo build --workspace
```
