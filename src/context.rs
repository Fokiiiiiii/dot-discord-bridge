//! Bounded, same-owner DM context. Context is untrusted conversation data, never instructions.
use anyhow::{bail, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

const MAX_ENTRIES: usize = 20;
const MAX_TEXT: usize = 2000;
const MAX_TOTAL: usize = 16000;
const RETENTION: i64 = 7 * 86400;

fn clipped(s: &str, max: usize) -> (String, usize, bool) {
    let mut units = 0;
    let mut truncated = false;
    let out: String = s
        .chars()
        .take_while(|c| {
            let len = c.len_utf16();
            if units + len <= max {
                units += len;
                true
            } else {
                truncated = true;
                false
            }
        })
        .collect();
    (out, units, truncated)
}
fn valid_id(s: &str) -> bool {
    (15..=22).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}
fn stamp(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}
fn entry(id: &str, role: &str, author: Option<&str>, text: &str, t: i64) -> Value {
    let (clipped_text, _, text_truncated) = clipped(text, MAX_TEXT);
    json!({"message_id":id,"role":role,"author_id":author,"text":clipped_text,"text_truncated":text_truncated,"timestamp":stamp(t)})
}
fn owned_reply(
    db: &Connection,
    id: &str,
    channel: &str,
    owner: &str,
    cutoff: i64,
) -> Result<Option<Value>> {
    let row: Option<(String, i64)> = db.query_row(
        "SELECT p.content,p.updated FROM outgoing_parts p JOIN messages m ON m.id=p.source JOIN outgoing_jobs j ON j.source=p.source WHERE p.message_id=?1 AND p.active=1 AND p.content IS NOT NULL AND p.updated>=?4 AND m.received>=?4 AND m.channel=?2 AND m.author=?3 AND j.state='done' LIMIT 1",
        params![id, channel, owner, cutoff],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    if let Some((text, t)) = row {
        return Ok(Some(entry(id, "assistant", None, &text, t)));
    }

    let notif_row: Option<(String, i64)> = db.query_row(
        "SELECT content,created FROM notification_contents WHERE message_id=?1 AND channel=?2 AND owner=?3 AND created>=?4 LIMIT 1",
        params![id, channel, owner, cutoff],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional().unwrap_or(None);
    if let Some((text, t)) = notif_row {
        return Ok(Some(entry(id, "assistant", None, &text, t)));
    }

    let file_row: Option<(String, i64)> = db.query_row(
        "SELECT filename,created FROM file_sends WHERE message_id=?1 AND (recipient=?2 OR recipient=?3) AND state='confirmed' AND created>=?4 LIMIT 1",
        params![id, channel, owner, cutoff],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional().unwrap_or(None);
    if let Some((filename, t)) = file_row {
        let text = format!("[file: {filename}]");
        return Ok(Some(entry(id, "assistant", None, &text, t)));
    }

    Ok(None)
}
fn cached_owner(
    db: &Connection,
    id: &str,
    channel: &str,
    owner: &str,
    cutoff: i64,
) -> Result<Option<Value>> {
    let row: Option<(String,i64)> = db.query_row("SELECT body,received FROM messages WHERE id=?1 AND channel=?2 AND author=?3 AND received>=?4",params![id,channel,owner,cutoff],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    Ok(row.and_then(|(body, t)| {
        serde_json::from_str::<Value>(&body).ok().and_then(|v| {
            v["text"]
                .as_str()
                .map(|s| entry(id, "user", Some(owner), s, t))
        })
    }))
}

/// Call only after authenticating the incoming owner and verifying its one-to-one DM,
/// within the ingestion transaction before inserting the current message. No REST lookups.
pub fn augment(
    db: &Connection,
    m: &Value,
    data: &mut Value,
    owner: &str,
    recent_limit: usize,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    augment_at(db, m, data, owner, recent_limit, now)
}
fn augment_at(
    db: &Connection,
    m: &Value,
    data: &mut Value,
    owner: &str,
    recent_limit: usize,
    now: i64,
) -> Result<()> {
    let channel = m["channel_id"].as_str().unwrap_or("");
    let current = m["id"].as_str().unwrap_or("");
    if !data.is_object()
        || !valid_id(channel)
        || !valid_id(current)
        || !valid_id(owner)
        || m["author"]["id"].as_str() != Some(owner)
        || !m["guild_id"].is_null()
        || m["author"]["bot"].as_bool() == Some(true)
        || !m["webhook_id"].is_null()
    {
        bail!("Context source is not an authorized owner DM");
    }
    let cutoff = now - RETENTION;
    data["reply_to"] = Value::Null;
    let reference = &m["message_reference"];
    // Forward snapshots and references outside this DM are deliberately not imported.
    if reference.is_object()
        && reference.get("type").is_none_or(|v| v.as_u64() == Some(0))
        && reference["channel_id"].as_str() == Some(channel)
        && reference["guild_id"].is_null()
    {
        if let Some(id) = reference["message_id"]
            .as_str()
            .filter(|id| valid_id(id) && *id != current)
        {
            let mut result = json!({"message_id":id,"status":"unavailable"});
            match m.get("referenced_message") {
                Some(Value::Null) => {
                    result["status"] = json!("deleted");
                }
                Some(inline) => {
                    if inline["id"].as_str() == Some(id)
                        && inline["channel_id"].as_str() == Some(channel)
                        && inline["guild_id"].is_null()
                        && inline["webhook_id"].is_null()
                    {
                        if inline["author"]["id"].as_str() == Some(owner)
                            && inline["author"]["bot"].as_bool() != Some(true)
                        {
                            if let Some(text) = inline["content"].as_str() {
                                let t = inline["timestamp"]
                                    .as_str()
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|d| d.timestamp())
                                    .unwrap_or(now);
                                result = entry(id, "user", Some(owner), text, t);
                                result["status"] = json!("available");
                            }
                        } else if let Some(owned) = owned_reply(db, id, channel, owner, cutoff)? {
                            result = owned;
                            result["status"] = json!("cached");
                        }
                    }
                }
                None => {
                    if let Some(cached) = cached_owner(db, id, channel, owner, cutoff)?
                        .or(owned_reply(db, id, channel, owner, cutoff)?)
                    {
                        result = cached;
                        result["status"] = json!("cached");
                    }
                }
            }
            data["reply_to"] = result;
        }
    }
    let limit = recent_limit.min(MAX_ENTRIES);
    let mut rows: Vec<(i64, String, Value)> = Vec::new();
    if limit > 0 {
        let mut q=db.prepare("SELECT id,body,received FROM messages WHERE channel=?1 AND author=?2 AND id<>?3 AND received>=?4 ORDER BY received DESC,length(id) DESC,id DESC LIMIT ?5")?;
        let items = q.query_map(
            params![channel, owner, current, cutoff, (limit + 1) as i64],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )?;
        for row in items {
            let (id, body, t) = row?;
            if let Ok(v) = serde_json::from_str::<Value>(&body) {
                if let Some(text) = v["text"].as_str() {
                    rows.push((t, id.clone(), entry(&id, "user", Some(owner), text, t)));
                }
            }
        }
        let mut q=db.prepare("SELECT p.message_id,p.content,p.updated FROM outgoing_parts p JOIN messages m ON m.id=p.source JOIN outgoing_jobs j ON j.source=p.source WHERE m.channel=?1 AND m.author=?2 AND p.active=1 AND p.content IS NOT NULL AND p.updated>=?3 AND m.received>=?3 AND j.state='done' ORDER BY p.updated DESC,length(p.message_id) DESC,p.message_id DESC LIMIT ?4")?;
        let items = q.query_map(params![channel, owner, cutoff, (limit + 1) as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in items {
            let (id, text, t) = row?;
            if valid_id(&id) {
                rows.push((t, id.clone(), entry(&id, "assistant", None, &text, t)));
            }
        }
        if let Ok(mut q) = db.prepare(
            "SELECT message_id,content,created FROM notification_contents WHERE channel=?1 AND owner=?2 AND created>=?3 ORDER BY created DESC,length(message_id) DESC,message_id DESC LIMIT ?4",
        ) {
            if let Ok(items) = q.query_map(params![channel, owner, cutoff, (limit + 1) as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            }) {
                for row in items.flatten() {
                    let (id, text, t) = row;
                    if valid_id(&id) {
                        rows.push((t, id.clone(), entry(&id, "assistant", None, &text, t)));
                    }
                }
            }
        }
        if let Ok(mut q) = db.prepare(
            "SELECT message_id,filename,created FROM file_sends WHERE (recipient=?1 OR recipient=?2) AND state='confirmed' AND message_id IS NOT NULL AND created>=?3 ORDER BY created DESC,length(message_id) DESC,message_id DESC LIMIT ?4",
        ) {
            if let Ok(items) = q.query_map(params![channel, owner, cutoff, (limit + 1) as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            }) {
                for row in items.flatten() {
                    let (id, filename, t) = row;
                    if valid_id(&id) {
                        let text = format!("[file: {filename}]");
                        rows.push((t, id.clone(), entry(&id, "assistant", None, &text, t)));
                    }
                }
            }
        }
    }
    rows.sort_by(|a, b| (b.0, b.1.len(), &b.1).cmp(&(a.0, a.1.len(), &a.1)));
    rows.dedup_by(|a, b| a.1 == b.1);
    let mut truncated = rows.len() > limit;
    rows.truncate(limit);
    let mut remaining = MAX_TOTAL;
    for (_, _, v) in &mut rows {
        let (s, units, was_clipped) = clipped(v["text"].as_str().unwrap_or(""), remaining);
        v["text_truncated"] = json!(v["text_truncated"] == true || was_clipped);
        truncated |= v["text_truncated"] == true;
        remaining = remaining.saturating_sub(units);
        v["text"] = json!(s);
    }
    rows.retain(|(_, _, v)| v["text"].as_str().is_some_and(|s| !s.is_empty()));
    rows.reverse();
    data["recent_context"] = Value::Array(rows.into_iter().map(|(_, _, v)| v).collect());
    data["recent_context_truncated"] = json!(truncated);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const OWNER: &str = "222222222222222222";
    const CHANNEL: &str = "111111111111111111";
    const CURRENT: &str = "333333333333333333";
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE messages(id TEXT PRIMARY KEY,channel TEXT,author TEXT,body TEXT,received INTEGER); CREATE TABLE outgoing_parts(source TEXT,part INTEGER,message_id TEXT,content TEXT,updated INTEGER,active INTEGER); CREATE TABLE outgoing_jobs(source TEXT PRIMARY KEY,state TEXT); CREATE TABLE notification_contents(message_id TEXT PRIMARY KEY,channel TEXT,owner TEXT,content TEXT,created INTEGER); CREATE TABLE file_sends(id TEXT PRIMARY KEY,recipient TEXT,message_id TEXT,filename TEXT,filesize INTEGER,state TEXT,created INTEGER);").unwrap();
        db
    }
    fn msg() -> Value {
        json!({"id":CURRENT,"channel_id":CHANNEL,"author":{"id":OWNER},"content":"current"})
    }
    fn insert(db: &Connection, id: &str, ch: &str, author: &str, text: &str, t: i64) {
        db.execute(
            "INSERT INTO messages VALUES(?,?,?,?,?)",
            params![
                id,
                ch,
                author,
                json!({"text":text,"recent_context":["nested must not leak"]}).to_string(),
                t
            ],
        )
        .unwrap();
    }
    #[test]
    fn recent_context_is_bounded_chronological_and_same_owner_channel() {
        let db = db();
        for i in 0..25 {
            insert(
                &db,
                &format!("400000000000000{i:03}"),
                CHANNEL,
                OWNER,
                &"😀".repeat(1500),
                1000 + i,
            );
        }
        insert(
            &db,
            "500000000000000000",
            "999999999999999999",
            OWNER,
            "other channel",
            2000,
        );
        insert(
            &db,
            "600000000000000000",
            CHANNEL,
            "999999999999999999",
            "other owner",
            2001,
        );
        insert(&db, CURRENT, CHANNEL, OWNER, "current excluded", 2002);
        let mut data = json!({});
        augment_at(&db, &msg(), &mut data, OWNER, 10, 3000).unwrap();
        let a = data["recent_context"].as_array().unwrap();
        assert_eq!(a.len(), 8);
        assert_eq!(data["recent_context_truncated"], true);
        assert!(a.iter().all(|v| v["text_truncated"] == true));
        assert!(a
            .iter()
            .all(|v| v["role"] == "user"
                && v["text"].as_str().unwrap().encode_utf16().count() <= 2000));
        assert_eq!(
            a.iter()
                .map(|v| v["text"].as_str().unwrap().encode_utf16().count())
                .sum::<usize>(),
            16000
        );
        assert!(a
            .windows(2)
            .all(|w| w[0]["timestamp"].as_str() <= w[1]["timestamp"].as_str()));
        assert!(a.iter().all(|v| v.get("recent_context").is_none()));
    }
    #[test]
    fn reply_reference_checks_identity_channel_and_deleted_state() {
        let db = db();
        let mut m = msg();
        m["message_reference"] = json!({"message_id":"444444444444444444","channel_id":CHANNEL});
        m["referenced_message"] = json!({"id":"444444444444444444","channel_id":CHANNEL,"author":{"id":OWNER},"content":"owner reference"});
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 0, 1000).unwrap();
        assert_eq!(data["reply_to"]["text"], "owner reference");
        m["referenced_message"]["author"]["id"] = json!("999999999999999999");
        augment_at(&db, &m, &mut data, OWNER, 0, 1000).unwrap();
        assert!(data["reply_to"].get("text").is_none());
        m["referenced_message"] = Value::Null;
        augment_at(&db, &m, &mut data, OWNER, 0, 1000).unwrap();
        assert_eq!(data["reply_to"]["status"], "deleted");
        m["message_reference"]["channel_id"] = json!("999999999999999999");
        augment_at(&db, &m, &mut data, OWNER, 0, 1000).unwrap();
        assert!(data["reply_to"].is_null());
    }
    #[test]
    fn cached_context_rejects_stale_and_unconfirmed_outgoing() {
        let db = db();
        insert(&db, "444444444444444444", CHANNEL, OWNER, "old", 1);
        insert(&db, "555555555555555555", CHANNEL, OWNER, "recent", 700000);
        db.execute(
            "INSERT INTO outgoing_jobs VALUES('555555555555555555','uncertain')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO outgoing_parts VALUES('555555555555555555',0,'666666666666666666','not confirmed edit',700010,1)",[]).unwrap();
        let mut m = msg();
        m["message_reference"] = json!({"message_id":"666666666666666666","channel_id":CHANNEL});
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 20, 700100).unwrap();
        assert_eq!(data["recent_context"].as_array().unwrap().len(), 1);
        assert!(data["reply_to"].get("text").is_none());
        db.execute("UPDATE outgoing_jobs SET state='done'", [])
            .unwrap();
        augment_at(&db, &m, &mut data, OWNER, 20, 700100).unwrap();
        assert_eq!(data["reply_to"]["role"], "assistant");
        assert_eq!(data["recent_context"].as_array().unwrap().len(), 2);
        db.execute("UPDATE outgoing_parts SET active=0", [])
            .unwrap();
        augment_at(&db, &m, &mut data, OWNER, 20, 700100).unwrap();
        assert!(data["reply_to"].get("text").is_none());
    }
    #[test]
    fn forwarded_and_unauthorized_sources_are_not_imported() {
        let db = db();
        let mut m = msg();
        m["message_reference"] =
            json!({"type":1,"message_id":"444444444444444444","channel_id":CHANNEL});
        m["message_snapshots"] = json!([{"message":{"content":"forwarded private message"}}]);
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 0, 1000).unwrap();
        assert!(data["reply_to"].is_null());
        assert_eq!(data["recent_context"], json!([]));
        m["guild_id"] = json!("999999999999999999");
        assert!(augment_at(&db, &m, &mut data, OWNER, 0, 1000).is_err());
    }
    #[test]
    fn missing_inline_owner_reference_uses_only_retained_cache() {
        let db = db();
        insert(
            &db,
            "444444444444444444",
            CHANNEL,
            OWNER,
            "cached owner",
            1000,
        );
        let mut m = msg();
        m["message_reference"] = json!({"message_id":"444444444444444444","channel_id":CHANNEL});
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 0, 2000).unwrap();
        assert_eq!(data["reply_to"]["status"], "cached");
        m["referenced_message"] = Value::Null;
        augment_at(&db, &m, &mut data, OWNER, 0, 2000).unwrap();
        assert!(data["reply_to"].get("text").is_none());
    }
    #[test]
    fn configured_zero_and_hard_count_cap_are_explicit() {
        let db = db();
        for i in 0..30 {
            insert(
                &db,
                &format!("400000000000000{i:03}"),
                CHANNEL,
                OWNER,
                "small",
                1000 + i,
            );
        }
        let mut data = json!({});
        augment_at(&db, &msg(), &mut data, OWNER, 10000, 2000).unwrap();
        assert_eq!(data["recent_context"].as_array().unwrap().len(), 20);
        assert_eq!(data["recent_context_truncated"], true);
        assert!(data["recent_context"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["text_truncated"] == false));
        augment_at(&db, &msg(), &mut data, OWNER, 0, 2000).unwrap();
        assert_eq!(data["recent_context"], json!([]));
        assert_eq!(data["recent_context_truncated"], false);
    }
    #[test]
    fn outgoing_context_cannot_cross_owner_or_channel_boundary() {
        let db = db();
        insert(
            &db,
            "444444444444444444",
            "999999999999999999",
            OWNER,
            "other DM",
            1000,
        );
        insert(
            &db,
            "555555555555555555",
            CHANNEL,
            "999999999999999999",
            "other owner",
            1000,
        );
        for (source, id) in [
            ("444444444444444444", "666666666666666666"),
            ("555555555555555555", "777777777777777777"),
        ] {
            db.execute("INSERT INTO outgoing_jobs VALUES(?,'done')", [source])
                .unwrap();
            db.execute(
                "INSERT INTO outgoing_parts VALUES(?,0,?,'must not leak',1010,1)",
                params![source, id],
            )
            .unwrap();
        }
        let mut m = msg();
        m["message_reference"] = json!({"message_id":"666666666666666666","channel_id":CHANNEL});
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 20, 2000).unwrap();
        assert_eq!(data["recent_context"], json!([]));
        assert!(data["reply_to"].get("text").is_none());
        m["message_reference"]["type"] = json!(-1);
        augment_at(&db, &m, &mut data, OWNER, 20, 2000).unwrap();
        assert!(data["reply_to"].is_null());
    }

    #[test]
    fn recent_context_and_reply_to_include_notifications_and_file_sends() {
        let db = db();
        let now = 2000;
        db.execute(
            "INSERT INTO notification_contents VALUES('600000000000000001',?,?,?,?)",
            params![CHANNEL, OWNER, "Proactive alert", now - 100],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_sends VALUES('fs1',?,'600000000000000002','data.csv',1234,'confirmed',?)",
            params![CHANNEL, now - 50],
        )
        .unwrap();

        let mut m = msg();
        let mut data = json!({});
        augment_at(&db, &m, &mut data, OWNER, 20, now).unwrap();
        let ctx = data["recent_context"].as_array().unwrap();
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0]["message_id"], "600000000000000001");
        assert_eq!(ctx[0]["text"], "Proactive alert");
        assert_eq!(ctx[0]["role"], "assistant");
        assert_eq!(ctx[1]["message_id"], "600000000000000002");
        assert_eq!(ctx[1]["text"], "[file: data.csv]");
        assert_eq!(ctx[1]["role"], "assistant");

        m["message_reference"] = json!({"message_id":"600000000000000001","channel_id":CHANNEL});
        augment_at(&db, &m, &mut data, OWNER, 20, now).unwrap();
        assert_eq!(data["reply_to"]["text"], "Proactive alert");
        assert_eq!(data["reply_to"]["status"], "cached");

        m["message_reference"] = json!({"message_id":"600000000000000002","channel_id":CHANNEL});
        augment_at(&db, &m, &mut data, OWNER, 20, now).unwrap();
        assert_eq!(data["reply_to"]["text"], "[file: data.csv]");
        assert_eq!(data["reply_to"]["status"], "cached");
    }
}
