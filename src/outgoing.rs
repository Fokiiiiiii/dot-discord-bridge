//! Durable, conservative multipart send/edit journal. Unknown writes never retry blindly.
use crate::{exact, now, retry_delay, snowflake, string, Bridge};
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS outgoing_parts(source TEXT NOT NULL,part INTEGER NOT NULL,message_id TEXT NOT NULL,content TEXT,updated INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(source,part)); CREATE TABLE IF NOT EXISTS outgoing_jobs(source TEXT PRIMARY KEY,kind TEXT NOT NULL,content_hash TEXT NOT NULL,state TEXT NOT NULL,result TEXT); CREATE TABLE IF NOT EXISTS outgoing_writes(id TEXT PRIMARY KEY,source TEXT NOT NULL,part INTEGER NOT NULL,kind TEXT NOT NULL,target TEXT,content_hash TEXT,state TEXT NOT NULL,created INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS idx_outgoing_parts_updated_notnull ON outgoing_parts(updated) WHERE content IS NOT NULL; CREATE INDEX IF NOT EXISTS idx_outgoing_parts_message_id ON outgoing_parts(message_id) WHERE active=1 AND content IS NOT NULL; CREATE INDEX IF NOT EXISTS idx_outgoing_parts_source_active ON outgoing_parts(source, active) WHERE content IS NOT NULL; CREATE INDEX IF NOT EXISTS idx_outgoing_jobs_state ON outgoing_jobs(state); CREATE INDEX IF NOT EXISTS idx_outgoing_writes_state ON outgoing_writes(state);")?;
    Ok(())
}
pub fn prune(db: &Connection, cutoff: i64) -> Result<()> {
    db.execute(
        "UPDATE outgoing_parts SET content=NULL WHERE content IS NOT NULL AND updated<?",
        [cutoff],
    )?;
    Ok(())
}
fn digest(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}
#[derive(Clone, Debug)]
struct Part {
    index: usize,
    id: String,
}
#[derive(Clone, Debug)]
enum Action {
    Create {
        index: usize,
        text: String,
    },
    Edit {
        index: usize,
        id: String,
        text: String,
    },
    Delete {
        index: usize,
        id: String,
    },
}
trait Transport {
    async fn write(
        &self,
        channel: &str,
        source: &str,
        revision: &str,
        action: &Action,
    ) -> Result<Option<String>>;
}
struct Discord<'a>(&'a Bridge);
impl Transport for Discord<'_> {
    async fn write(
        &self,
        channel: &str,
        source: &str,
        revision: &str,
        action: &Action,
    ) -> Result<Option<String>> {
        let b = self.0;
        b.check_rest_cooldown()?;
        b.ensure_channel(channel).await?;
        let client = &b.http;
        let base = format!("https://discord.com/api/v10/channels/{channel}/messages");
        let mentions = json!({"parse":[],"replied_user":false});
        let request = match action {
            Action::Create { index, text } => {
                let nonce = digest(&format!("{source}:{revision}:{index}"));
                client.post(&base).json(&json!({"content":text,"allowed_mentions":mentions,"message_reference":{"message_id":source,"channel_id":channel,"fail_if_not_exists":true},"nonce":&nonce[..24],"enforce_nonce":true}))
            }
            Action::Edit { id, text, .. } => client
                .patch(format!("{base}/{id}"))
                .json(&json!({"content":text,"allowed_mentions":mentions})),
            Action::Delete { id, .. } => client.delete(format!("{base}/{id}")),
        };
        let response = request
            .header("Authorization", format!("Bot {}", b.config.bot))
            .send()
            .await
            .map_err(|_| anyhow!("Discord write uncertain; operator inspection required"))?;
        confirm_response(b, channel, action, response).await
    }
}

async fn confirm_response(
    b: &Bridge,
    channel: &str,
    action: &Action,
    mut response: reqwest::Response,
) -> Result<Option<String>> {
    let status = response.status().as_u16();
    let header_delay = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<f64>().ok());
    // Known 429 takes effect even if the body later fails or is oversized.
    if status == 429 {
        b.set_rest_cooldown(retry_delay(header_delay, None));
    }
    if matches!(action, Action::Delete { .. }) && status == 204 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("Discord response uncertain"))?
    {
        if bytes.len() + chunk.len() > 65536 {
            bail!("Discord response exceeds limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if matches!(action, Action::Delete { .. }) && status == 404 && body["code"] == 10008 {
        return Ok(None); // Known-owned message already deleted; not an authorization error.
    }
    if status == 429 {
        b.set_rest_cooldown(retry_delay(header_delay, body["retry_after"].as_f64()));
    }
    if status != 200 || matches!(action, Action::Delete { .. }) {
        bail!("Discord write not confirmed; operator inspection required");
    }
    let id = string(&body, "id")?;
    if !snowflake(id) || body["channel_id"].as_str() != Some(channel) {
        bail!("Discord response identity mismatch");
    }
    if let Action::Edit { id: expected, .. } = action {
        if expected != id {
            bail!("Discord edit identity mismatch");
        }
    }
    Ok(Some(id.to_owned()))
}

pub async fn send(b: &Bridge, p: &Value) -> Result<Value> {
    execute(b, p, false, &Discord(b)).await
}
pub async fn edit(b: &Bridge, p: &Value) -> Result<Value> {
    execute(b, p, true, &Discord(b)).await
}
async fn execute<T: Transport>(b: &Bridge, p: &Value, editing: bool, t: &T) -> Result<Value> {
    exact(p, &["message_id", "text"])?;
    let source = string(p, "message_id")?;
    if !snowflake(source) {
        bail!("Invalid source message");
    }
    let text = string(p, "text")?;
    let chunks = crate::splitter::split(text)?;
    let content_hash = digest(text);
    let _lock = b.reply_lock.lock().await;
    let (channel, author): (String, String) =
        b.db.lock()
            .unwrap()
            .query_row(
                "SELECT channel,author FROM messages WHERE id=?",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context("Reply target not observed")?;
    if !b.can_respond(&author) {
        bail!("Reply not authorized");
    }
    b.ensure_channel(&channel).await?;
    if !b.is_verified_channel(&channel) {
        bail!("Reply recipient not verified");
    }
    b.check_rest_cooldown()?;
    let actions = {
        let mut db = b.db.lock().unwrap();
        let tx = db.transaction()?;
        let prior: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT content_hash,result FROM replies WHERE source=?",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let job: Option<(String, String, Option<String>)> = tx
            .query_row(
                "SELECT content_hash,state,result FROM outgoing_jobs WHERE source=?",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if job.as_ref().is_some_and(|(_, state, _)| state != "done") {
            bail!("Previous multipart operation incomplete or uncertain; operator inspection required");
        }
        let legacy_result = prior.as_ref().and_then(|(_, r)| r.clone());
        if !editing {
            if let Some((hash, result)) = prior {
                if hash != content_hash {
                    bail!("Different reply already exists; use discord_edit_reply");
                }
                return result
                    .map(|s| serde_json::from_str(&s).map_err(Into::into))
                    .unwrap_or_else(|| {
                        Err(anyhow!(
                            "Previous send uncertain; operator inspection required"
                        ))
                    });
            }
            tx.execute(
                "INSERT INTO replies VALUES(?,?,NULL)",
                params![source, content_hash],
            )?;
        } else {
            let (_, result) = prior.context("No bridge-owned reply for source")?;
            if result.is_none() {
                bail!("Original reply uncertain; operator inspection required");
            }
            if let Some((hash, _, Some(result))) = &job {
                if hash == &content_hash {
                    return Ok(serde_json::from_str(result)?);
                }
            }
        }
        let mut parts: Vec<Part> = {
            let mut stmt=tx.prepare("SELECT part,message_id FROM outgoing_parts WHERE source=? AND active=1 ORDER BY part")?;
            let rows = stmt
                .query_map([source], |r| {
                    Ok(Part {
                        index: r.get(0)?,
                        id: r.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        if editing && parts.is_empty() {
            if job.is_some() {
                bail!("Owned reply mapping missing");
            }
            let value: Value =
                serde_json::from_str(&legacy_result.context("Confirmed legacy reply required")?)?;
            exact(&value, &["message_id", "channel_id"])?;
            let id = string(&value, "message_id")?;
            if !snowflake(id)
                || id == source
                || value["channel_id"].as_str() != Some(channel.as_str())
            {
                bail!("Legacy reply identity mismatch");
            }
            let existing: i64 = tx.query_row(
                "SELECT count(*) FROM outgoing_parts WHERE source=?",
                [source],
                |r| r.get(0),
            )?;
            if existing != 0 {
                bail!("Legacy mapping not empty");
            }
            tx.execute(
                "INSERT INTO outgoing_parts VALUES(?,0,?,NULL,?,1)",
                params![source, id, now()],
            )?;
            parts.push(Part {
                index: 0,
                id: id.to_owned(),
            });
        }
        if parts
            .iter()
            .enumerate()
            .any(|(n, p)| p.index != n || !snowflake(&p.id))
        {
            bail!("Invalid outgoing ownership journal");
        }
        let mut actions = Vec::new();
        for (index, chunk) in chunks.into_iter().enumerate() {
            actions.push(if let Some(part) = parts.get(index) {
                Action::Edit {
                    index,
                    id: part.id.clone(),
                    text: chunk,
                }
            } else {
                Action::Create { index, text: chunk }
            });
        }
        let desired = actions.len();
        for part in parts.iter().skip(desired).rev() {
            actions.push(Action::Delete {
                index: part.index,
                id: part.id.clone(),
            });
        }
        tx.execute(
            "INSERT OR REPLACE INTO outgoing_jobs VALUES(?,?,?,'pending',NULL)",
            params![source, if editing { "edit" } else { "send" }, content_hash],
        )?;
        tx.commit()?;
        actions
    };
    // Journal is already pending before every external write. On any failure it
    // remains quarantined across restart; confirmed earlier parts remain visible.
    let operation_nonce = uuid::Uuid::new_v4().to_string();
    for action in actions {
        let (index, kind, target, hash) = match &action {
            Action::Create { index, text } => (*index, "create", None, Some(digest(text))),
            Action::Edit { index, id, text } => {
                (*index, "edit", Some(id.as_str()), Some(digest(text)))
            }
            Action::Delete { index, id } => (*index, "delete", Some(id.as_str()), None),
        };
        let write_id = format!("{operation_nonce}:{index}:{kind}");
        b.db.lock().unwrap().execute(
            "INSERT INTO outgoing_writes VALUES(?,?,?,?,?,?,'pending',?)",
            params![write_id, source, index, kind, target, hash, now()],
        )?;
        let id = t.write(&channel, source, &operation_nonce, &action).await?;
        let mut db = b.db.lock().unwrap();
        let db = db.transaction()?;
        match action {
            Action::Create { index, text } => {
                let id = id.context("Missing created message identity")?;
                if !snowflake(&id) {
                    bail!("Invalid created identity");
                }
                db.execute(
                    "INSERT OR REPLACE INTO outgoing_parts VALUES(?,?,?,?,?,1)",
                    params![source, index, id, text, now()],
                )?;
            }
            Action::Edit {
                index,
                id: expected,
                text,
            } => {
                if id.as_deref() != Some(&expected) {
                    bail!("Edit response identity mismatch");
                }
                db.execute("UPDATE outgoing_parts SET content=?,updated=? WHERE source=? AND part=? AND message_id=? AND active=1",params![text,now(),source,index,expected])?;
            }
            Action::Delete {
                index,
                id: expected,
            } => {
                if id.is_some() {
                    bail!("Unexpected delete result");
                }
                db.execute("UPDATE outgoing_parts SET active=0,content=NULL,updated=? WHERE source=? AND part=? AND message_id=?",params![now(),source,index,expected])?;
            }
        }
        db.execute(
            "UPDATE outgoing_writes SET state='confirmed' WHERE id=?",
            [write_id],
        )?;
        db.commit()?;
    }
    let mut db = b.db.lock().unwrap();
    let tx = db.transaction()?;
    let ids: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT message_id FROM outgoing_parts WHERE source=? AND active=1 ORDER BY part",
        )?;
        let rows = stmt
            .query_map([source], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let result = json!({"message_id":ids.first().context("Empty outgoing reply")?,"message_ids":ids,"channel_id":channel,"part_count":ids.len()});
    tx.execute(
        "UPDATE outgoing_jobs SET state='done',result=? WHERE source=?",
        params![result.to_string(), source],
    )?;
    tx.execute(
        "UPDATE replies SET result=? WHERE source=?",
        params![result.to_string(), source],
    )?;
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    const SOURCE: &str = "333333333333333333";
    struct Mock {
        calls: Mutex<Vec<Action>>,
        fail_at: Option<usize>,
    }
    impl Mock {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail_at,
            }
        }
    }
    impl Transport for Mock {
        async fn write(
            &self,
            channel: &str,
            _source: &str,
            _revision: &str,
            action: &Action,
        ) -> Result<Option<String>> {
            assert_eq!(channel, "111111111111111111");
            let mut calls = self.calls.lock().unwrap();
            let n = calls.len();
            calls.push(action.clone());
            if self.fail_at == Some(n) {
                bail!("Synthetic uncertain transport");
            }
            Ok(match action {
                Action::Create { .. } => Some(format!("7{n:017}")),
                Action::Edit { id, .. } => Some(id.clone()),
                Action::Delete { .. } => None,
            })
        }
    }
    fn bridge() -> Bridge {
        let b = crate::tests::bridge();
        init(&b.db.lock().unwrap()).unwrap();
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO messages VALUES(?,?,?,?,?)",
                params![
                    SOURCE,
                    "111111111111111111",
                    "222222222222222222",
                    "{}",
                    now()
                ],
            )
            .unwrap();
        b
    }
    fn request(text: &str) -> Value {
        json!({"message_id":SOURCE,"text":text})
    }
    #[tokio::test]
    async fn multipart_send_deduplicates_and_maps_only_owned_ids() {
        let b = bridge();
        let t = Mock::new(None);
        let text = "a".repeat(4500);
        let result = execute(&b, &request(&text), false, &t).await.unwrap();
        assert_eq!(result["part_count"], 3);
        let repeat = execute(&b, &request(&text), false, &t).await.unwrap();
        assert_eq!(result, repeat);
        assert_eq!(t.calls.lock().unwrap().len(), 3);
        assert!(execute(&b, &request("different"), false, &t).await.is_err());
        let mut arbitrary = request("bad");
        arbitrary["outgoing_id"] = json!("799999999999999999");
        assert!(execute(&b, &arbitrary, true, &t).await.is_err());
        let db = b.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM outgoing_parts WHERE active=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
    }
    #[tokio::test]
    async fn edits_grow_then_shrink_and_repeat_without_writes() {
        let b = bridge();
        let t = Mock::new(None);
        execute(&b, &request("short"), false, &t).await.unwrap();
        let result = execute(&b, &request(&"b".repeat(4100)), true, &t)
            .await
            .unwrap();
        assert_eq!(result["part_count"], 3);
        let result = execute(&b, &request("final"), true, &t).await.unwrap();
        assert_eq!(result["part_count"], 1);
        let before = t.calls.lock().unwrap().len();
        assert_eq!(
            execute(&b, &request("final"), true, &t).await.unwrap(),
            result
        );
        assert_eq!(t.calls.lock().unwrap().len(), before);
        let calls = t.calls.lock().unwrap();
        assert!(matches!(&calls[1], Action::Edit { .. }));
        assert!(matches!(&calls[5], Action::Delete { index: 2, .. }));
        assert!(matches!(&calls[6], Action::Delete { index: 1, .. }));
        let db = b.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM outgoing_parts WHERE active=1",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM outgoing_parts WHERE active=0 AND content IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
    }
    #[tokio::test]
    async fn partial_send_failure_is_durable_and_never_blindly_retried() {
        let b = bridge();
        let t = Mock::new(Some(1));
        let p = request(&"x".repeat(4500));
        assert!(execute(&b, &p, false, &t).await.is_err());
        assert_eq!(t.calls.lock().unwrap().len(), 2);
        assert!(execute(&b, &p, false, &t).await.is_err());
        assert!(execute(&b, &request("edit"), true, &t).await.is_err());
        assert_eq!(t.calls.lock().unwrap().len(), 2);
        let db = b.db.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT state FROM outgoing_jobs", [], |r| r
                .get::<_, String>(0))
                .unwrap(),
            "pending"
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM outgoing_parts", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn partial_edit_failure_blocks_followup_send_and_edit() {
        let b = bridge();
        let t = Mock::new(None);
        execute(&b, &request(&"x".repeat(4100)), false, &t)
            .await
            .unwrap();
        let failure = Mock::new(Some(1));
        assert!(execute(&b, &request("small"), true, &failure)
            .await
            .is_err());
        assert!(execute(&b, &request("small"), true, &failure)
            .await
            .is_err());
        assert!(execute(&b, &request(&"x".repeat(4100)), false, &failure)
            .await
            .is_err());
        assert_eq!(failure.calls.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn owner_and_legacy_uncertain_guards_precede_transport() {
        let b = bridge();
        let t = Mock::new(None);
        b.db.lock()
            .unwrap()
            .execute("UPDATE messages SET author='999999999999999999'", [])
            .unwrap();
        assert!(execute(&b, &request("x"), false, &t).await.is_err());
        b.db.lock()
            .unwrap()
            .execute("UPDATE messages SET author='222222222222222222'", [])
            .unwrap();
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO replies VALUES(?,?,NULL)",
                params![SOURCE, digest("x")],
            )
            .unwrap();
        assert!(execute(&b, &request("x"), false, &t).await.is_err());
        assert!(t.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn incomplete_job_survives_database_reopen() {
        let b = bridge();
        let t = Mock::new(Some(1));
        let p = request(&"z".repeat(4100));
        assert!(execute(&b, &p, false, &t).await.is_err());
        let path =
            std::env::temp_dir().join(format!("outgoing-test-{}.sqlite", uuid::Uuid::new_v4()));
        b.db.lock()
            .unwrap()
            .execute("VACUUM INTO ?", [path.to_str().unwrap()])
            .unwrap();
        drop(b);
        let mut reopened = crate::tests::bridge();
        reopened.db = Mutex::new(Connection::open(&path).unwrap());
        let fresh = Mock::new(None);
        assert!(execute(&reopened, &p, false, &fresh).await.is_err());
        assert!(fresh.calls.lock().unwrap().is_empty());
        assert_eq!(
            reopened
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM outgoing_writes WHERE state='pending'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn malformed_outgoing_identity_quarantines_operation() {
        struct Wrong;
        impl Transport for Wrong {
            async fn write(&self, _: &str, _: &str, _: &str, _: &Action) -> Result<Option<String>> {
                Ok(Some("not-an-id".into()))
            }
        }
        let b = bridge();
        assert!(execute(&b, &request("x"), false, &Wrong).await.is_err());
        assert!(execute(&b, &request("x"), false, &Mock::new(None))
            .await
            .is_err());
        assert_eq!(
            b.db.lock()
                .unwrap()
                .query_row("SELECT count(*) FROM outgoing_parts", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn confirmed_legacy_reply_migrates_but_malformed_or_foreign_does_not() {
        let b = bridge();
        let t = Mock::new(None);
        let id = "777777777777777777";
        let legacy = json!({"message_id":id,"channel_id":"111111111111111111"});
        b.db.lock()
            .unwrap()
            .execute(
                "INSERT INTO replies VALUES(?,?,?)",
                params![SOURCE, digest("old"), legacy.to_string()],
            )
            .unwrap();
        let result = execute(&b, &request("updated"), true, &t).await.unwrap();
        assert_eq!(result["message_id"], id);
        assert!(matches!(&t.calls.lock().unwrap()[0],Action::Edit{id:target,..} if target==id));
        for invalid in [
            json!({"message_id":id,"channel_id":"999999999999999999"}),
            json!({"message_id":"not-id","channel_id":"111111111111111111"}),
            json!({"message_id":id,"channel_id":"111111111111111111","extra":true}),
        ] {
            let b = bridge();
            let t = Mock::new(None);
            b.db.lock()
                .unwrap()
                .execute(
                    "INSERT INTO replies VALUES(?,?,?)",
                    params![SOURCE, digest("old"), invalid.to_string()],
                )
                .unwrap();
            assert!(execute(&b, &request("updated"), true, &t).await.is_err());
            assert!(t.calls.lock().unwrap().is_empty());
        }
    }
    async fn response_fixture(
        b: &Bridge,
        status: u16,
        body: String,
        delay: Option<&str>,
        action: &Action,
    ) -> Result<Option<String>> {
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::get,
            Router,
        };
        let mut headers = HeaderMap::new();
        if let Some(delay) = delay {
            headers.insert("retry-after", delay.parse().unwrap());
        }
        let app = Router::new().route(
            "/",
            get(move || async move { (StatusCode::from_u16(status).unwrap(), headers, body) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let response = reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let result = confirm_response(b, "111111111111111111", action, response).await;
        server.abort();
        result
    }
    #[tokio::test]
    async fn rate_limit_survives_oversized_body_and_preserves_larger_hint() {
        let b = bridge();
        let action = Action::Create {
            index: 0,
            text: "x".into(),
        };
        assert!(
            response_fixture(&b, 429, "x".repeat(70000), Some("90"), &action)
                .await
                .is_err()
        );
        assert!(*b.rest_not_before.lock().unwrap() >= now() + 90);
        let b = bridge();
        assert!(response_fixture(
            &b,
            429,
            json!({"retry_after":120}).to_string(),
            Some("90"),
            &action
        )
        .await
        .is_err());
        assert!(*b.rest_not_before.lock().unwrap() >= now() + 120);
    }
    #[tokio::test]
    async fn response_checks_owned_identity_and_only_unknown_message_delete() {
        let b = bridge();
        let action = Action::Delete {
            index: 0,
            id: "777777777777777777".into(),
        };
        assert!(response_fixture(&b, 204, String::new(), None, &action)
            .await
            .unwrap()
            .is_none());
        assert!(
            response_fixture(&b, 404, json!({"code":10008}).to_string(), None, &action)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            response_fixture(&b, 404, json!({"code":50001}).to_string(), None, &action)
                .await
                .is_err()
        );
        let action = Action::Edit {
            index: 0,
            id: "777777777777777777".into(),
            text: "x".into(),
        };
        assert!(response_fixture(
            &b,
            200,
            json!({"id":"888888888888888888","channel_id":"111111111111111111"}).to_string(),
            None,
            &action
        )
        .await
        .is_err());
        assert!(response_fixture(
            &b,
            200,
            json!({"id":"777777777777777777","channel_id":"999999999999999999"}).to_string(),
            None,
            &action
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn retention_removes_content_not_ownership_ids() {
        let b = bridge();
        let t = Mock::new(None);
        execute(&b, &request("private text"), false, &t)
            .await
            .unwrap();
        let db = b.db.lock().unwrap();
        prune(&db, now() + 1).unwrap();
        let (content, id): (Option<String>, String) = db
            .query_row("SELECT content,message_id FROM outgoing_parts", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert!(content.is_none());
        assert!(snowflake(&id));
    }
}
