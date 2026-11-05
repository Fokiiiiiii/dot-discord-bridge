//! Idempotent reactions to messages observed from an authorized user.
use crate::{exact, snowflake, string, Bridge};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::time::Duration;

fn parse(p: &Value) -> Result<(&str, &str, &str)> {
    exact(p, &["message_id", "emoji", "action"])?;
    let id = string(p, "message_id")?;
    let emoji = string(p, "emoji")?;
    let action = string(p, "action")?;
    if !snowflake(id)
        || emoji.is_empty()
        || emoji.len() > 128
        || emoji
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
        || !matches!(action, "add" | "remove")
    {
        bail!("Invalid reaction");
    }
    Ok((id, emoji, action))
}
pub async fn apply(b: &Bridge, p: &Value) -> Result<Value> {
    let (id, emoji, action) = parse(p)?;
    let (channel, author): (String, String) = b.db.lock().unwrap().query_row(
        "SELECT channel,author FROM messages WHERE id=?",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !b.can_respond(&author) {
        bail!("Unauthorized source");
    }
    b.ensure_channel(&channel).await?;
    b.check_rest_cooldown()?;
    let encoded: String = url::form_urlencoded::byte_serialize(emoji.as_bytes()).collect();
    let endpoint = format!(
        "https://discord.com/api/v10/channels/{channel}/messages/{id}/reactions/{encoded}/@me"
    );
    let client = reqwest::Client::builder()
        .user_agent("DiscordBot (https://github.com/Fokiiiiiii/dot-discord-bridge, 0.4.0)")
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let req = if action == "add" {
        client.put(endpoint)
    } else {
        client.delete(endpoint)
    };
    let response = req
        .header("Authorization", format!("Bot {}", b.config.bot))
        .send()
        .await?;
    if response.status().as_u16() == 429 {
        b.set_rest_cooldown(crate::retry_delay(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            None,
        ));
    }
    if response.status().as_u16() != 204 {
        bail!("Discord reaction not confirmed");
    }
    Ok(json!({"message_id":id,"action":action,"confirmed":true}))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_unicode_and_custom_emoji_and_rejects_bad_inputs() {
        for emoji in ["👍", "custom_name:123456789012345678"] {
            assert!(parse(
                &json!({"message_id":"333333333333333333","emoji":emoji,"action":"add"})
            )
            .is_ok());
        }
        for emoji in ["", "bad/emoji", "bad\nemoji"] {
            assert!(parse(
                &json!({"message_id":"333333333333333333","emoji":emoji,"action":"add"})
            )
            .is_err());
        }
        assert!(parse(&json!({"message_id":"x","emoji":"👍","action":"add"})).is_err());
        assert!(
            parse(&json!({"message_id":"333333333333333333","emoji":"👍","action":"wipe"}))
                .is_err()
        );
    }
}
