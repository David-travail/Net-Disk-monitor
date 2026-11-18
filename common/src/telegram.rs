//! Envoi de messages au bot Telegram configuré, partagé par le moteur et l'IHM.
//!
//! Fonctions :
//! - `is_configured` : indique si le jeton et le chat Telegram sont renseignés.
//! - `send_message` : envoie un message texte au chat configuré.

use crate::Config;
use std::{error::Error, time::Duration};

/// Indique si les identifiants Telegram sont renseignés.
pub fn is_configured(config: &Config) -> bool {
    !config.jeton_bot_telegram.is_empty() && !config.identifiant_chat_telegram.is_empty()
}

/// Envoie un message texte au chat Telegram configuré, avec le délai HTTP configuré.
///
/// Entrées : `client`, client HTTP réutilisable ; `config`, identifiants et délai ; `text`, message.
/// Sortie : `Ok(())` si Telegram a accepté le message, sinon l'erreur (sans le jeton dans l'URL).
pub async fn send_message(
    client: &reqwest::Client,
    config: &Config,
    text: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        config.jeton_bot_telegram
    );
    tokio::time::timeout(
        Duration::from_secs(config.delai_http_telegram_secondes),
        async {
            client
                .post(url)
                .json(&serde_json::json!({
                    "chat_id": config.identifiant_chat_telegram,
                    "text": text,
                }))
                .send()
                .await
                .map_err(|error| error.without_url())?
                .error_for_status()
                .map_err(|error| error.without_url())?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        },
    )
    .await
    .map_err(|_| "Délai d'attente Telegram dépassé")??;
    Ok(())
}
