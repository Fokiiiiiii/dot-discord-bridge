//! Owner-only proactive notifications with durable, conservative idempotency.
use crate::{exact, now, retry_delay, snowflake, string, Bridge};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS notifications(key_hash TEXT PRIMARY KEY,owner TEXT NOT NULL,content_hash TEXT NOT NULL,channel TEXT NOT NULL,state TEXT NOT NULL,result TEXT,created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS notification_destinations(owner TEXT NOT NULL,channel TEXT NOT NULL,PRIMARY KEY(owner,channel));")?;
    Ok(())
}
/// Call only after validating this channel as the configured owner's one-to-one DM.
/// Keep all distinct observations: a later conflicting channel must fail closed.
pub fn remember(db: &Connection, owner: &str, channel: &str) -> Result<()> {
    if !snowflake(owner) || !snowflake(channel) {
        bail!("Invalid notification destination identifiers");
    }
    db.execute(
        "INSERT OR IGNORE INTO notification_destinations(owner,channel) VALUES(?,?)",
        params![owner, channel],
    )?;
    Ok(())
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
struct Prepared {
    key_hash: String,
    content_hash: String,
    content: String,
    mention: bool,
    importance: String,
}
fn prepare(p: &Value, owner: &str) -> Result<Prepared> {
    exact(
        p,
        &["idempotency_key", "text", "importance", "mention_owner"],
    )?;
    let key = string(p, "idempotency_key")?;
    if !(1..=128).contains(&key.len()) || !key.bytes().all(|c| c.is_ascii_graphic()) {
        bail!("Invalid notification idempotency key");
    }
    let text = string(p, "text")?;
    let importance = string(p, "importance")?;
    if !matches!(importance, "normal" | "important") {
        bail!("Invalid notification importance");
    }
    let mention = p["mention_owner"]
        .as_bool()
        .context("Invalid mention selection")?;
    if text.trim().is_empty() {
        bail!("Notification text is empty");
    }
    let content = if mention {
        format!("<@{owner}> {text}")
    } else {
        text.to_owned()
    };
    if crate::splitter::discord_len(&content) > 2000 {
        bail!("Notification exceeds 2000 UTF-16 units including mention");
    }
    let content_hash = digest(&serde_json::to_string(&json!([
        owner, text, importance, mention
    ]))?);
    Ok(Prepared {
        key_hash: digest(key),
        content_hash,
        content,
        mention,
        importance: importance.to_owned(),
    })
}
fn payload(owner: &str, p: &Prepared) -> Value {
    let users = if p.mention { vec![owner] } else { vec![] };
    json!({"content":p.content,"allowed_mentions":{"parse":[],"users":users,"roles":[],"replied_user":false},"nonce":&p.key_hash[..24],"enforce_nonce":true})
}
trait Transport {
    async fn write(&self, channel: &str, body: &Value) -> Result<String>;
}
struct Discord<'a>(&'a Bridge);
impl Transport for Discord<'_> {
    async fn write(&self, channel: &str, body: &Value) -> Result<String> {
        let b = self.0;
        b.check_rest_cooldown()?;
        let mut response = b
            .http
            .post(format!(
                "https://discord.com/api/v10/channels/{channel}/messages"
            ))
            .timeout(std::time::Duration::from_secs(20))
            .header("Authorization", format!("Bot {}", b.config.bot))
            .json(body)
            .send()
            .await
            .map_err(|_| anyhow!("Notification send uncertain; do not retry with a new key"))?;
        let status = response.status().as_u16();
        let retry_header = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<f64>().ok());
        if status == 429 {
            b.set_rest_cooldown(retry_delay(retry_header, None));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("Notification response uncertain; operator inspection required"))?
        {
            if bytes.len() + chunk.len() > 65536 {
                bail!("Notification response exceeds limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if status == 429 {
            b.set_rest_cooldown(retry_delay(retry_header, body["retry_after"].as_f64()));
        }
        if status != 200 {
            bail!("Notification not confirmed; operator inspection required");
        }
        let id = body["id"].as_str().unwrap_or("");
        if !snowflake(id) || body["channel_id"].as_str() != Some(channel) {
            bail!("Notification response identity mismatch");
        }
        Ok(id.to_owned())
    }
}
pub(crate) fn candidate_channels(db: &Connection, owner: &str) -> Result<Vec<String>> {
    let mut query = db.prepare(
        "SELECT channel FROM notification_destinations WHERE owner=?1 UNION SELECT channel FROM messages WHERE author=?1 AND COALESCE(json_extract(body, '$.is_guild'), 0)=0 ORDER BY channel LIMIT 2",
    )?;
    let channels = query
        .query_map([owner], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(channels)
}
fn candidate(db: &Connection, owner: &str) -> Result<String> {
    let channels = candidate_channels(db, owner)?;
    if channels.is_empty() {
        bail!("No previously observed owner DM (One previously observed owner DM required)");
    }
    if channels.len() != 1 {
        bail!("Multiple previously observed owner DM candidates (One previously observed owner DM required)");
    }
    Ok(channels[0].clone())
}
fn record_intent(
    db: &mut Connection,
    owner: &str,
    channel: &str,
    prepared: &Prepared,
) -> Result<()> {
    let transaction = db.transaction()?;
    // Fresh Discord verification awaited outside SQLite. Ingestion may have
    // added another verified destination meanwhile: recheck before reserving.
    if candidate(&transaction, owner)? != channel {
        bail!("Notification destination changed during verification");
    }
    remember(&transaction, owner, channel)?;
    transaction.execute(
        "INSERT INTO notifications(key_hash,owner,content_hash,channel,state,created) VALUES(?,?,?,?,'pending',?)",
        params![prepared.key_hash, owner, prepared.content_hash, channel, now()],
    )?;
    transaction.commit()?;
    Ok(())
}

pub async fn send(b: &Bridge, p: &Value) -> Result<Value> {
    execute(b, p, &Discord(b)).await
}
async fn execute<T: Transport>(b: &Bridge, p: &Value, transport: &T) -> Result<Value> {
    if b.config.users.len() != 1 {
        bail!("Exactly one notification owner required");
    }
    let owner = b.config.users.iter().next().unwrap();
    if !snowflake(owner) {
        bail!("Invalid configured notification owner");
    }
    let prepared = prepare(p, owner)?;
    let _lock = b.reply_lock.lock().await;
    let prior: Option<(String, String, String, Option<String>)> =
        b.db.lock()
            .unwrap()
            .query_row(
                "SELECT owner,content_hash,state,result FROM notifications WHERE key_hash=?",
                [&prepared.key_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
    if let Some((old_owner, hash, state, result)) = prior {
        if old_owner != *owner || hash != prepared.content_hash {
            bail!("Notification key conflicts with prior request");
        }
        if state == "done" {
            return serde_json::from_str(&result.context("Missing notification result")?)
                .context("Invalid notification result");
        }
        bail!("Notification outcome uncertain; operator inspection required; do not use a new key");
    }
    let channel = candidate(&b.db.lock().unwrap(), owner)?;
    b.check_rest_cooldown()?;
    b.ensure_dm_fresh(&channel).await?;
    record_intent(&mut b.db.lock().unwrap(), owner, &channel, &prepared)?;
    let id = transport
        .write(&channel, &payload(owner, &prepared))
        .await?;
    if !snowflake(&id) {
        bail!("Notification response identity invalid");
    }
    let result = json!({"message_id":id,"channel_id":channel,"mention_owner":prepared.mention,"importance":prepared.importance});
    b.db.lock().unwrap().execute(
        "UPDATE notifications SET state='done',result=? WHERE key_hash=? AND state='pending'",
        params![result.to_string(), prepared.key_hash],
    )?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    const OWNER: &str = "222222222222222222";
    const CHANNEL: &str = "111111111111111111";

    struct Mock {
        calls: Mutex<Vec<Value>>,
        fail: bool,
    }
    impl Transport for Mock {
        async fn write(&self, channel: &str, body: &Value) -> Result<String> {
            assert_eq!(channel, CHANNEL);
            self.calls.lock().unwrap().push(body.clone());
            if self.fail {
                bail!("synthetic uncertain write");
            }
            Ok("777777777777777777".to_owned())
        }
    }
    fn bridge() -> Bridge {
        let b = crate::tests::bridge();
        init(&b.db.lock().unwrap()).unwrap();
        remember(&b.db.lock().unwrap(), OWNER, CHANNEL).unwrap();
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO messages VALUES('333333333333333333',?,?, '{}',?)",
                params![CHANNEL, OWNER, now()],
            )
            .unwrap();
        b
    }
    fn request(text: &str) -> Value {
        json!({"idempotency_key":"test:1","text":text,"importance":"normal","mention_owner":false})
    }
    fn mock(fail: bool) -> Mock {
        Mock {
            calls: Mutex::new(vec![]),
            fail,
        }
    }
    #[test]
    fn mentions_only_allow_explicit_configured_owner_at_any_importance() {
        let mut p = request("@everyone <@&123> <@999999999999999999>");
        let normal = payload(OWNER, &prepare(&p, OWNER).unwrap());
        assert_eq!(
            normal["allowed_mentions"],
            json!({"parse":[],"users":[],"roles":[],"replied_user":false})
        );
        p["mention_owner"] = json!(true);
        let normal_mention = payload(OWNER, &prepare(&p, OWNER).unwrap());
        assert_eq!(
            normal_mention["allowed_mentions"],
            json!({"parse":[],"users":[OWNER],"roles":[],"replied_user":false})
        );
        assert!(normal_mention["content"]
            .as_str()
            .unwrap()
            .starts_with(&format!("<@{OWNER}> ")));
        p["importance"] = json!("important");
        let body = payload(OWNER, &prepare(&p, OWNER).unwrap());
        assert_eq!(body["allowed_mentions"]["users"], json!([OWNER]));
        assert_eq!(body["allowed_mentions"]["parse"], json!([]));
        assert!(body["content"]
            .as_str()
            .unwrap()
            .starts_with(&format!("<@{OWNER}> ")));
    }
    #[test]
    fn input_bounds_and_destination_injection_reject() {
        assert!(prepare(&request(&"😀".repeat(1000)), OWNER).is_ok());
        assert!(prepare(&request(&"😀".repeat(1001)), OWNER).is_err());
        let mut p = request(&"a".repeat(2000));
        p["importance"] = json!("important");
        p["mention_owner"] = json!(true);
        assert!(prepare(&p, OWNER).is_err());
        let remaining = 2000 - crate::splitter::discord_len(&format!("<@{OWNER}> "));
        p["text"] = json!("a".repeat(remaining));
        assert!(prepare(&p, OWNER).is_ok());
        p["text"] = json!("a".repeat(remaining + 1));
        assert!(prepare(&p, OWNER).is_err());
        for key in [
            "channel_id",
            "recipient_id",
            "owner_user_id",
            "allowed_mentions",
        ] {
            let mut p = request("hello");
            p[key] = json!("injection");
            assert!(prepare(&p, OWNER).is_err());
        }
        for key in ["", "bad key", "bad\nkey"] {
            let mut p = request("hello");
            p["idempotency_key"] = json!(key);
            assert!(prepare(&p, OWNER).is_err());
        }
    }
    #[tokio::test]
    async fn successful_notification_deduplicates_and_conflict_fails() {
        let b = bridge();
        let t = mock(false);
        let p = request("hello");
        let first = execute(&b, &p, &t).await.unwrap();
        assert_eq!(execute(&b, &p, &t).await.unwrap(), first);
        assert_eq!(first["message_id"], "777777777777777777");
        assert!(execute(&b, &request("changed"), &t).await.is_err());
        let mut changed = p.clone();
        changed["importance"] = json!("important");
        assert!(execute(&b, &changed, &t).await.is_err());
        changed["mention_owner"] = json!(true);
        assert!(execute(&b, &changed, &t).await.is_err());
        assert_eq!(t.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn invalid_returned_message_id_never_marks_done() {
        struct Invalid;
        impl Transport for Invalid {
            async fn write(&self, _: &str, _: &Value) -> Result<String> {
                Ok("invalid-message-id".to_owned())
            }
        }
        let b = bridge();
        assert!(execute(&b, &request("hello"), &Invalid).await.is_err());
        let state: String =
            b.db.lock()
                .unwrap()
                .query_row("SELECT state FROM notifications", [], |r| r.get(0))
                .unwrap();
        assert_eq!(state, "pending");
    }
    #[tokio::test]
    async fn uncertain_notification_is_quarantined_and_not_replayed() {
        let b = bridge();
        let t = mock(true);
        let p = request("hello");
        assert!(execute(&b, &p, &t).await.is_err());
        init(&b.db.lock().unwrap()).unwrap();
        assert!(execute(&b, &p, &t).await.is_err());
        assert_eq!(t.calls.lock().unwrap().len(), 1);
        let row: (String, String) =
            b.db.lock()
                .unwrap()
                .query_row("SELECT state,content_hash FROM notifications", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
        assert_eq!(row.0, "pending");
        assert_eq!(row.1.len(), 64);
    }
    #[tokio::test]
    async fn pending_intent_exists_before_write_and_survives_disk_reopen() {
        struct Inspect<'a>(&'a Bridge, Mutex<usize>);
        impl Transport for Inspect<'_> {
            async fn write(&self, _: &str, _: &Value) -> Result<String> {
                let state: String = self
                    .0
                    .db
                    .lock()
                    .unwrap()
                    .query_row("SELECT state FROM notifications", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(state, "pending");
                *self.1.lock().unwrap() += 1;
                bail!("synthetic crash after possible POST");
            }
        }
        let path =
            std::env::temp_dir().join(format!("notification-test-{}.sqlite", uuid::Uuid::new_v4()));
        let fixture = crate::tests::bridge();
        let b = Bridge::new(path.to_str().unwrap(), fixture.config).unwrap();
        init(&b.db.lock().unwrap()).unwrap();
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO messages VALUES('333333333333333333',?,?, '{}',?)",
                params![CHANNEL, OWNER, now()],
            )
            .unwrap();
        let inspect = Inspect(&b, Mutex::new(0));
        assert!(execute(&b, &request("hello"), &inspect).await.is_err());
        assert_eq!(*inspect.1.lock().unwrap(), 1);
        drop(inspect);
        let config = b.config;
        drop(b.db);
        let reopened = Bridge::new(path.to_str().unwrap(), config).unwrap();
        init(&reopened.db.lock().unwrap()).unwrap();
        let channel: String = reopened
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT channel FROM notification_destinations WHERE owner=?",
                [OWNER],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(channel, CHANNEL);
        let transport = mock(false);
        assert!(execute(&reopened, &request("hello"), &transport)
            .await
            .is_err());
        assert!(transport.calls.lock().unwrap().is_empty());
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn destination_change_during_verification_cannot_reserve_send() {
        let b = bridge();
        let mut db = b.db.lock().unwrap();
        let original = candidate(&db, OWNER).unwrap();
        assert_eq!(original, CHANNEL);
        let prepared = prepare(&request("hello"), OWNER).unwrap();
        remember(&db, OWNER, "555555555555555555").unwrap();
        assert!(record_intent(&mut db, OWNER, &original, &prepared).is_err());
        let count: i64 = db
            .query_row("SELECT count(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        db.execute(
            "DELETE FROM notification_destinations WHERE channel=?",
            [CHANNEL],
        )
        .unwrap();
        db.execute("DELETE FROM messages", []).unwrap();
        assert!(record_intent(&mut db, OWNER, &original, &prepared).is_err());
        let count: i64 = db
            .query_row("SELECT count(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn retained_destination_sends_without_retained_message_text() {
        let b = bridge();
        let t = mock(false);
        b.db.lock()
            .unwrap()
            .execute("DELETE FROM messages", [])
            .unwrap();
        assert!(execute(&b, &request("hello"), &t).await.is_ok());
        assert_eq!(t.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn retained_conflicting_destinations_fail_closed() {
        let b = bridge();
        let t = mock(false);
        remember(&b.db.lock().unwrap(), OWNER, "555555555555555555").unwrap();
        b.db.lock()
            .unwrap()
            .execute("DELETE FROM messages", [])
            .unwrap();
        assert!(execute(&b, &request("hello"), &t).await.is_err());
        assert!(t.calls.lock().unwrap().is_empty());
        let count: i64 =
            b.db.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM notification_destinations", [], |r| {
                    r.get(0)
                })
                .unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn unknown_other_owner_or_ambiguous_channel_never_send() {
        let b = bridge();
        let t = mock(false);
        b.db.lock()
            .unwrap()
            .execute("DELETE FROM messages", [])
            .unwrap();
        b.db.lock()
            .unwrap()
            .execute("DELETE FROM notification_destinations", [])
            .unwrap();
        assert!(execute(&b, &request("hello"), &t).await.is_err());
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO messages VALUES('333333333333333333',?,'999999999999999999','{}',?)",
                params![CHANNEL, now()],
            )
            .unwrap();
        assert!(execute(&b, &request("hello"), &t).await.is_err());
        b.db.lock()
            .unwrap()
            .execute("UPDATE messages SET author=?", [OWNER])
            .unwrap();
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO messages VALUES('444444444444444444','555555555555555555',?,'{}',?)",
                params![OWNER, now()],
            )
            .unwrap();
        assert!(execute(&b, &request("hello"), &t).await.is_err());
        assert!(t.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn guild_messages_in_history_do_not_make_owner_dm_ambiguous() {
        let b = bridge();
        let t = mock(false);
        b.db.lock()
            .unwrap()
            .execute(
                r#"INSERT INTO messages VALUES('444444444444444444','1563460728818630698',?,'{"is_guild":true}',?)"#,
                params![OWNER, now()],
            )
            .unwrap();
        let result = execute(&b, &request("hello after guild message"), &t)
            .await
            .unwrap();
        assert_eq!(result["channel_id"], CHANNEL);
        assert_eq!(t.calls.lock().unwrap().len(), 1);
    }
}
