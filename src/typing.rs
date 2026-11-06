//! Bounded best-effort typing leases. Discord has no stop-typing endpoint.
use crate::{now, params, Bridge, Connection, OptionalExtension, Result};
use serde_json::Value;

pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS typing_leases(source TEXT PRIMARY KEY,channel TEXT NOT NULL,sid TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS typing_channels(channel TEXT PRIMARY KEY,next_due INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_typing_leases_state_expires ON typing_leases(state, expires); CREATE INDEX IF NOT EXISTS idx_typing_leases_created ON typing_leases(created); CREATE INDEX IF NOT EXISTS idx_typing_leases_sid_active ON typing_leases(sid) WHERE state='active';")?;
    // Never resume cosmetic typing after process restart.
    db.execute(
        "UPDATE typing_leases SET state='stopped' WHERE state='active'",
        [],
    )?;
    Ok(())
}
pub fn delivered(db: &Connection, data: &Value, sid: &str, seconds: u64) -> Result<()> {
    if seconds == 0 {
        return Ok(());
    }
    let source = data["message_id"].as_str().unwrap_or("");
    let channel = data["channel_id"].as_str().unwrap_or("");
    if !crate::snowflake(source) || !crate::snowflake(channel) {
        return Ok(());
    }
    // A reply can race the callback ACK. It must never restart typing.
    let replied: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM replies WHERE source=?)",
        [source],
        |r| r.get(0),
    )?;
    if replied {
        return Ok(());
    }
    db.execute(
        "INSERT OR IGNORE INTO typing_leases VALUES(?,?,?,?, 'active',?)",
        params![source, channel, sid, now() + seconds.min(300) as i64, now()],
    )?;
    Ok(())
}
pub fn finish(db: &Connection, source: &str) -> Result<()> {
    // A tombstone also handles no-response/failure arriving before callback ACK.
    db.execute("INSERT INTO typing_leases VALUES(?,'','',0,'stopped',?) ON CONFLICT(source) DO UPDATE SET state='stopped'", params![source,now()])?;
    Ok(())
}
pub fn stop_subscription(db: &Connection, sid: &str) -> Result<()> {
    db.execute(
        "UPDATE typing_leases SET state='stopped' WHERE sid=? AND state='active'",
        [sid],
    )?;
    Ok(())
}
pub fn prune(db: &Connection) -> Result<()> {
    db.execute(
        "UPDATE typing_leases SET state='stopped' WHERE state='active' AND expires<=?",
        [now()],
    )?;
    db.execute(
        "DELETE FROM typing_leases WHERE created<?",
        [now() - 7 * 86400],
    )?;
    Ok(())
}
fn active(b: &Bridge, source: &str, sid: &str) -> Result<bool> {
    let db = b.db.lock().unwrap();
    let author: Option<String> = db.query_row("SELECT m.author FROM typing_leases t JOIN messages m ON m.id=t.source JOIN subscriptions s ON s.id=t.sid WHERE t.source=? AND t.state='active' AND t.expires>? AND s.expires>? AND m.channel=t.channel AND NOT EXISTS(SELECT 1 FROM replies r WHERE r.source=t.source)", params![source,now(),now()], |r| r.get(0)).optional()?;
    let valid = author
        .as_deref()
        .is_some_and(|author| b.can_respond(author));
    if !valid {
        return Ok(false);
    }
    if let Some(oauth) = &b.config.oauth {
        let family: Option<String> = db
            .query_row(
                "SELECT family FROM subscription_grants WHERE sid=?",
                [sid],
                |r| r.get(0),
            )
            .optional()?;
        return Ok(family.is_some_and(|f| oauth.grant_active(&f)));
    }
    Ok(true)
}
fn reserve_channel(db: &Connection, channel: &str, at: i64) -> Result<bool> {
    let due: i64 = db
        .query_row(
            "SELECT next_due FROM typing_channels WHERE channel=?",
            [channel],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if due > at {
        return Ok(false);
    }
    db.execute(
        "INSERT OR REPLACE INTO typing_channels VALUES(?,?)",
        params![channel, at + 8],
    )?;
    Ok(true)
}
pub async fn tick(b: &Bridge) -> Result<()> {
    let rows: Vec<(String, String, String)> = {
        let db = b.db.lock().unwrap();
        prune(&db)?;
        let mut q = db.prepare(
            "SELECT t.source,t.channel,t.sid FROM typing_leases t LEFT JOIN typing_channels tc ON tc.channel=t.channel WHERE t.state='active' ORDER BY COALESCE(tc.next_due,0) ASC, t.created ASC, t.source ASC LIMIT 200",
        )?;
        let rows = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut refreshed_channels = std::collections::HashSet::new();
    for (source, channel, sid) in rows {
        if refreshed_channels.contains(&channel) {
            continue;
        }
        if !active(b, &source, &sid)? {
            finish(&b.db.lock().unwrap(), &source)?;
            continue;
        }
        if b.check_rest_cooldown().is_err() {
            continue;
        }
        let due: i64 =
            b.db.lock()
                .unwrap()
                .query_row(
                    "SELECT next_due FROM typing_channels WHERE channel=?",
                    [&channel],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
        if due > now() {
            continue;
        }
        if b.ensure_channel(&channel).await.is_err() {
            finish(&b.db.lock().unwrap(), &source)?;
            continue;
        }
        if !active(b, &source, &sid)? {
            continue;
        }
        // One request/channel/eight seconds, independent of source count.
        if !reserve_channel(&b.db.lock().unwrap(), &channel, now())? {
            continue;
        }
        refreshed_channels.insert(channel.clone());
        if refreshed_channels.len() >= 20 {
            break;
        }
        let response = b
            .http
            .post(format!(
                "https://discord.com/api/v10/channels/{channel}/typing"
            ))
            .timeout(std::time::Duration::from_secs(3))
            .header("Authorization", format!("Bot {}", b.config.bot))
            .send()
            .await;
        match response {
            Ok(r) if r.status().as_u16() == 204 => {}
            Ok(mut r) if r.status().as_u16() == 429 => {
                let delay = r
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<f64>().ok());
                b.set_rest_cooldown(crate::retry_delay(delay, None));
                let mut bytes = Vec::new();
                while let Ok(Some(chunk)) = r.chunk().await {
                    if bytes.len() + chunk.len() > 65536 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk);
                }
                let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                b.set_rest_cooldown(crate::retry_delay(delay, body["retry_after"].as_f64()));
            }
            _ => {
                finish(&b.db.lock().unwrap(), &source)?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE replies(source TEXT PRIMARY KEY);")
            .unwrap();
        init(&db).unwrap();
        db
    }
    fn data() -> Value {
        json!({"message_id":"333333333333333333","channel_id":"111111111111111111"})
    }
    #[test]
    fn ack_retry_never_extends_or_restarts_lease() {
        let db = db();
        delivered(&db, &data(), "sub", 30).unwrap();
        let first: i64 = db
            .query_row("SELECT expires FROM typing_leases", [], |r| r.get(0))
            .unwrap();
        delivered(&db, &data(), "sub", 300).unwrap();
        assert_eq!(
            first,
            db.query_row("SELECT expires FROM typing_leases", [], |r| r
                .get::<_, i64>(0))
                .unwrap()
        );
        finish(&db, "333333333333333333").unwrap();
        delivered(&db, &data(), "sub", 300).unwrap();
        assert_eq!(
            db.query_row("SELECT state FROM typing_leases", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "stopped"
        );
    }
    #[test]
    fn early_no_response_reply_restart_and_unsubscribe_stop() {
        let db = db();
        finish(&db, "333333333333333333").unwrap();
        delivered(&db, &data(), "sub", 30).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM typing_leases WHERE state='active'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        db.execute("DELETE FROM typing_leases", []).unwrap();
        db.execute("INSERT INTO replies VALUES('333333333333333333')", [])
            .unwrap();
        delivered(&db, &data(), "sub", 30).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM typing_leases", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        db.execute("DELETE FROM replies", []).unwrap();
        delivered(&db, &data(), "sub", 30).unwrap();
        stop_subscription(&db, "sub").unwrap();
        assert_eq!(
            db.query_row("SELECT state FROM typing_leases", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "stopped"
        );
        db.execute("UPDATE typing_leases SET state='active'", [])
            .unwrap();
        init(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT state FROM typing_leases", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "stopped"
        );
    }
    #[test]
    fn refresh_rate_is_per_channel_and_respects_interval() {
        let db = db();
        assert!(reserve_channel(&db, "111111111111111111", 100).unwrap());
        assert!(!reserve_channel(&db, "111111111111111111", 100).unwrap());
        assert!(!reserve_channel(&db, "111111111111111111", 107).unwrap());
        assert!(reserve_channel(&db, "111111111111111111", 108).unwrap());
    }
    #[tokio::test]
    async fn owner_revocation_and_no_response_stop_without_network() {
        let mut b = crate::tests::bridge();
        let m = serde_json::json!({"id":"333333333333333333","channel_id":"111111111111111111","author":{"id":"222222222222222222"},"content":"hello"});
        b.ingest(&m).unwrap();
        b.db.lock().unwrap().execute("INSERT INTO subscriptions VALUES('sub','222222222222222222','https://callback.example/events','unused',?,NULL,0)",[now()+100]).unwrap();
        delivered(&b.db.lock().unwrap(), &data(), "sub", 30).unwrap();
        assert!(active(&b, "333333333333333333", "sub").unwrap());
        b.finish_response(
            &serde_json::json!({"message_id":"333333333333333333","outcome":"no_response"}),
        )
        .unwrap();
        tick(&b).await.unwrap();
        assert!(!active(&b, "333333333333333333", "sub").unwrap());
        b.db.lock()
            .unwrap()
            .execute("UPDATE typing_leases SET state='active'", [])
            .unwrap();
        b.config.users = std::collections::HashSet::from(["999999999999999999".into()]);
        tick(&b).await.unwrap();
        assert!(!active(&b, "333333333333333333", "sub").unwrap());
    }
    #[tokio::test]
    async fn oauth_revocation_stops_typing_even_with_another_grant() {
        let mut b = crate::tests::bridge();
        b.ingest(&serde_json::json!({"id":"333333333333333333","channel_id":"111111111111111111","author":{"id":"222222222222222222"},"content":"test"})).unwrap();
        let (oauth, _, family) = crate::oauth::OAuth::test_fixture();
        let oauth = std::sync::Arc::new(oauth);
        b.config.oauth = Some(oauth.clone());
        b.db.lock().unwrap().execute("INSERT INTO subscriptions VALUES('sub','222222222222222222','https://callback.example/events','unused',?,NULL,0)",[now()+100]).unwrap();
        b.db.lock()
            .unwrap()
            .execute("INSERT INTO subscription_grants VALUES('sub',?)", [&family])
            .unwrap();
        delivered(&b.db.lock().unwrap(), &data(), "sub", 30).unwrap();
        assert!(active(&b, "333333333333333333", "sub").unwrap());
        oauth.test_revoke(&family);
        oauth.test_new_grant();
        tick(&b).await.unwrap();
        assert!(!active(&b, "333333333333333333", "sub").unwrap());
    }
    #[test]
    fn timeout_and_disabled_are_bounded() {
        let db = db();
        delivered(&db, &data(), "sub", 0).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM typing_leases", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        delivered(&db, &data(), "sub", 999).unwrap();
        assert!(
            db.query_row("SELECT expires FROM typing_leases", [], |r| r
                .get::<_, i64>(0))
                .unwrap()
                <= now() + 300
        );
        db.execute("UPDATE typing_leases SET expires=0", [])
            .unwrap();
        prune(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT state FROM typing_leases", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "stopped"
        );
    }
}
