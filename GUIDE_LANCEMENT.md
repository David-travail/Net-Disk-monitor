# Lancer NetDiskMonitor

## Prérequis

- Rust et Cargo installés.
- Un terminal ouvert à la racine du projet, dans le dossier contenant `Cargo.toml`.

Les commandes ci-dessous fonctionnent dans PowerShell, Windows Terminal et les terminaux Linux/macOS.

## Régler les paramètres

Le fichier `config.toml` à la racine du projet centralise les paramètres du moteur et de l'IHM :

```toml
# Surveillance disque.
activer_surveillance_disque = true
intervalle_scrutation_disque_secondes = 60
seuil_alerte_disque_pourcentage = 85.0

# Telegram : laissez les deux champs vides pour desactiver les notifications.
jeton_bot_telegram = ""
identifiant_chat_telegram = ""
delai_http_telegram_secondes = 10

# Surveillance reseau local.
activer_surveillance_reseau = true
intervalle_scrutation_reseau_secondes = 30

# Fichiers affiches lors d'une analyse.
taille_min_fichier_volumineux_mio = 100
nombre_max_fichiers_volumineux = 100

# Adresse d'ecoute du moteur et adresse utilisee par l'IHM.
adresse_ecoute_moteur = "127.0.0.1:7878"
adresse_moteur = "127.0.0.1:7878"

# IHM : intervalle de rafraichissement et dimensions de la fenetre (pixels).
intervalle_actualisation_ihm_secondes = 3
largeur_fenetre_ihm = 900.0
hauteur_fenetre_ihm = 760.0
largeur_min_fenetre_ihm = 680.0
hauteur_min_fenetre_ihm = 520.0
```

Les intervalles et délais sont exprimés en secondes et doivent être supérieurs à zéro. Le seuil doit être compris entre 0 et 100. La taille minimale des fichiers est exprimée en Mio ; le nombre de résultats est limité à 10 000. Telegram est désactivé si les deux identifiants sont vides ; renseignez-les ensemble pour activer les alertes. Le moteur et l'IHM lisent `config.toml` au démarrage : redémarrez les programmes concernés après une modification. Si le fichier est absent, le moteur le crée avec toutes les valeurs par défaut.

Par défaut, le moteur n'écoute que sur `127.0.0.1`. Pour connecter une IHM depuis une autre machine, configurez l'adresse d'écoute du moteur sur une interface réseau appropriée et définissez `adresse_moteur` avec l'adresse correspondante dans la configuration de l'IHM. L'interface TCP ne fournit pas d'authentification ; ne l'exposez pas à un réseau non fiable.

## Lancer le serveur seul

Dans un terminal, à la racine du projet :

```powershell
cargo run -p engine
```

Le moteur démarre les surveillances activées et écoute à l'adresse définie par `adresse_ecoute_moteur`. Laissez ce terminal ouvert pour que le moteur continue de fonctionner.

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

Le client ouvre une fenêtre graphique qui affiche l'occupation des disques et les appareils présents dans la table ARP. Le bouton d'analyse recherche les fichiers selon `taille_min_fichier_volumineux_mio` (au maximum `nombre_max_fichiers_volumineux` résultats) sur les disques accessibles ; sélectionnez ensuite les fichiers à supprimer et confirmez l'action. Les données de statut sont actualisées selon `intervalle_actualisation_ihm_secondes`. Si le moteur ne répond pas, un message d'erreur s'affiche dans la fenêtre et le client continue de réessayer.

Le client peut être démarré même si le serveur n'est pas encore lancé : la fenêtre indique l'erreur de connexion et réessaie automatiquement. Arrêtez le moteur avec `Ctrl+C` dans le premier terminal et fermez la fenêtre du client normalement.

## Compiler sans lancer

Pour compiler tous les composants du workspace :

```powershell
cargo build --workspace
```
