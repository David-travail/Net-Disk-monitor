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
alerte_nouvel_appareil_telegram = true
scans_manques_avant_deconnexion = 2

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

Les intervalles et délais sont exprimés en secondes et doivent être supérieurs à zéro. Le seuil doit être compris entre 0 et 100. La taille minimale des fichiers est exprimée en Mio ; le nombre de résultats est limité à 10 000. Telegram est désactivé si les deux identifiants sont vides ; renseignez-les ensemble pour activer les alertes. Avec `alerte_nouvel_appareil_telegram = true`, un message Telegram est aussi envoyé quand un appareil jamais vu depuis le démarrage du moteur apparaît sur le réseau (les appareils présents au premier scan ne déclenchent pas d'alerte). Le moteur et l'IHM lisent `config.toml` au démarrage : redémarrez les programmes concernés après une modification. Si le fichier est absent, le moteur le crée avec toutes les valeurs par défaut.

Par défaut, le moteur n'écoute que sur `127.0.0.1`. Pour connecter une IHM depuis une autre machine, configurez l'adresse d'écoute du moteur sur une interface réseau appropriée et définissez `adresse_moteur` avec l'adresse correspondante dans la configuration de l'IHM. L'interface TCP ne fournit pas d'authentification ; ne l'exposez pas à un réseau non fiable.

## Lancer le serveur seul

Dans un terminal, à la racine du projet :

```powershell
cargo run -p engine
```

Le moteur démarre les surveillances activées et écoute à l'adresse définie par `adresse_ecoute_moteur`. Laissez ce terminal ouvert pour que le moteur continue de fonctionner.

À chaque cycle de surveillance réseau, le moteur balaye les réseaux locaux de la machine (interfaces physiques uniquement : un VPN actif est ignoré), puis lit la table ARP. Sous macOS, les entrées ARP expirées, conservées jusqu'à 20 minutes par le système, sont écartées : un appareil parti n'est plus compté. Un appareil est déclaré déconnecté après `scans_manques_avant_deconnexion` scans sans réponse, soit environ ce nombre multiplié par `intervalle_scrutation_reseau_secondes` (1 minute avec les valeurs par défaut).

Le moteur affiche un message horodaté dans la console à chaque cycle. Les événements de présence, connexion et déconnexion sont également horodatés dans la console et dans `network_events.log`.

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

Le client ouvre une fenêtre graphique qui affiche l'occupation des disques et les appareils présents dans la table ARP. Le bouton d'analyse recherche les fichiers selon `taille_min_fichier_volumineux_mio` (au maximum `nombre_max_fichiers_volumineux` résultats) sur les disques accessibles ; sélectionnez ensuite les fichiers à supprimer et confirmez l'action. Le nom des appareils est découvert automatiquement : le moteur interroge chaque appareil en mDNS (Bonjour/Avahi : Mac, iPhone, imprimantes, box, Linux…), puis par DNS inverse. Les appareils qui ne répondent à aucune des deux méthodes (certaines caméras, prises connectées…) restent sans nom : cliquez sur ✏ (ou double-cliquez sur le nom) pour leur en donner un. Ce nom personnalisé est associé à l'adresse MAC, enregistré par le moteur dans `noms_appareils.toml` et utilisé dans l'IHM, la console, `network_events.log` et les alertes Telegram. Une adresse MAC « privée » (aléatoire, fréquente sur les téléphones) est signalée au survol : si l'appareil en change, le nom ne le suit pas.

La section « Appareils du réseau local » indique pour chaque appareil s'il est connecté ou s'il ne répond plus depuis un ou plusieurs scans ; la section « Mouvements récents » liste les dernières connexions et déconnexions, la plus récente en premier. Les cases « Surveillance disque » et « Surveillance réseau » de l'en-tête activent ou désactivent ces tâches à chaud ; ce choix est perdu au redémarrage du moteur, qui reprend les valeurs de `config.toml`. Les données de statut sont actualisées selon `intervalle_actualisation_ihm_secondes`. Si le moteur ne répond pas, un message d'erreur s'affiche dans la fenêtre et le client continue de réessayer.

Le client peut être démarré même si le serveur n'est pas encore lancé : la fenêtre indique l'erreur de connexion et réessaie automatiquement. Arrêtez le moteur avec `Ctrl+C` dans le premier terminal et fermez la fenêtre du client normalement.

## Compiler sans lancer

Pour compiler tous les composants du workspace :

```powershell
cargo build --workspace
```
