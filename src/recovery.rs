//! Bounded content-free diagnostics and explicit retry of transient failed inbox lookups.
//! Does not send messages, reset outgoing journals, or revive subscriptions.
use crate::{exact, now, snowflake, string, Bridge};
use anyhow::{bail, Result};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const LIMIT: usize = 50;
const MAX_RETRY_AGE: i64 = 7 * 86400;

fn safe_reason(s: &str) -> &str {
    match s {
        "discord_unavailable"
        | "discord_http_error"
        | "discord_response_failed"
        | "discord_invalid_response"
        | "discord_rate_limited"
        | "discord_shared_cooldown"
        | "dm_verification_expired"
        | "lookup_internal_error" => s,
        _ => "other",
    }
}

pub(crate) fn safe_file_error(s: &str) -> &str {
    match s {
        "discord_rate_limited"
        | "discord_payload_too_large"
        | "discord_upload_rejected"
        | "discord_transport_uncertain"
        | "discord_5xx_uncertain" => s,
        _ => "other",
    }
}

pub fn diagnostics(b: &Bridge, args: &Value) -> Result<Value> {
    exact(args, &[])?;
    let db = b.db.lock().unwrap();
    let owner = b.config.users.iter().next().unwrap();
    let current_now = now();
    let cutoff = current_now - MAX_RETRY_AGE;

    let expired_failed_inbox_count: i64 = db
        .query_row(
            "SELECT count(*) FROM inbox WHERE status='failed' AND received < ?1",
            [cutoff],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let mut stmt = db.prepare(
        "SELECT id,author,tries,received,COALESCE(last_error,'') FROM inbox WHERE status='failed' ORDER BY (received >= ?1) DESC, received DESC, length(id) DESC, id DESC",
    )?;
    let mut rows = stmt.query([cutoff])?;
    let mut inbox = Vec::new();
    let mut inbox_truncated = false;
    let mut author_cache = std::collections::HashMap::<String, bool>::new();
    while let Some(r) = rows.next()? {
        let author: String = r.get(1)?;
        let allowed = *author_cache
            .entry(author.clone())
            .or_insert_with(|| b.can_respond(&author));
        if !allowed {
            continue;
        }
        if inbox.len() == LIMIT {
            inbox_truncated = true;
            break;
        }
        let id: String = r.get(0)?;
        let tries: i64 = r.get(2)?;
        let received: i64 = r.get(3)?;
        let reason: String = r.get(4)?;
        inbox.push(json!({
            "message_id": id,
            "attempts": tries,
            "age_seconds": current_now.saturating_sub(received).max(0),
            "retry_eligible": received >= cutoff,
            "reason": safe_reason(&reason)
        }));
    }
    drop(rows);
    drop(stmt);
    // Terminal callback failures are deleted by the existing delivery policy;
    // but recorded in callback_failures table for diagnosis.
    let mut stmt =
        db.prepare("SELECT sid,eid,tries,due FROM queue ORDER BY due,sid,eid LIMIT 51")?;
    let mut queue = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)))?
        .map(|row| row.map(|(sid,eid,tries,due)| {
            let digest = format!("{:x}", Sha256::digest(format!("{}:{}:{}", sid.len(), sid, eid).as_bytes()));
            let source = eid.strip_prefix("discord_").filter(|id| snowflake(id));
            json!({"delivery_id":digest,"message_id":source,"attempts":tries,"due_in_seconds":due.saturating_sub(current_now).max(0)})
        })).collect::<rusqlite::Result<Vec<_>>>()?;
    let queue_truncated = queue.len() > LIMIT;
    queue.truncate(LIMIT);
    drop(stmt);
    let mut stmt = db.prepare("SELECT source,kind FROM (SELECT source,kind FROM outgoing_jobs WHERE state<>'done' UNION ALL SELECT r.source,'legacy' FROM replies r WHERE r.result IS NULL AND NOT EXISTS (SELECT 1 FROM outgoing_jobs j WHERE j.source=r.source)) ORDER BY length(source),source LIMIT 51")?;
    let mut outgoing = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?
        .map(|row| row.map(|(source,kind)| json!({"message_id":source,"kind":match kind.as_str() {"send"=>"send","edit"=>"edit","legacy"=>"legacy",_=>"other"}})))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let outgoing_truncated = outgoing.len() > LIMIT;
    outgoing.truncate(LIMIT);
    drop(stmt);
    let mut stmt = db.prepare(
        "SELECT j.source,j.kind,j.state,j.result,MAX(p.updated) FROM outgoing_jobs j LEFT JOIN outgoing_parts p ON p.source=j.source GROUP BY j.source ORDER BY COALESCE(MAX(p.updated),0) DESC,length(j.source) DESC,j.source DESC LIMIT 20",
    )?;
    let recent_outgoing = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })?
        .map(|row| {
            row.map(|(source, kind, state, result, max_up)| {
                let sent_id = result
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| {
                        v["message_id"]
                            .as_str()
                            .filter(|id| snowflake(id))
                            .map(str::to_owned)
                    });
                json!({
                    "message_id": source,
                    "kind": match kind.as_str() { "send" => "send", "edit" => "edit", _ => "other" },
                    "state": match state.as_str() { "done" => "done", "pending" => "pending", "partial" => "partial", _ => "other" },
                    "sent_message_id": sent_id,
                    "age_seconds": max_up.map(|u| current_now.saturating_sub(u).max(0))
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let dest_channels = crate::notifications::candidate_channels(&db, owner).unwrap_or_default();
    let dest_count = dest_channels.len();
    let dest_status = match dest_count {
        0 => "missing",
        1 => "ready",
        _ => "ambiguous",
    };
    let mut stmt = db.prepare(
        "SELECT key_hash,created FROM notifications WHERE state<>'done' ORDER BY created DESC LIMIT 20",
    )?;
    let uncertain_notifications = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .map(|row| {
            row.map(|(key_hash, created)| {
                json!({
                    "operation_id": key_hash,
                    "age_seconds": current_now.saturating_sub(created).max(0)
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut stmt = db.prepare(
        "SELECT key_hash,state,result,created FROM notifications ORDER BY created DESC,key_hash ASC LIMIT 20",
    )?;
    let recent_notifications = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .map(|row| {
            row.map(|(key_hash, state, result, created)| {
                let sent_id = result
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| {
                        v["message_id"]
                            .as_str()
                            .filter(|id| snowflake(id))
                            .map(str::to_owned)
                    });
                json!({
                    "operation_id": key_hash,
                    "state": match state.as_str() { "done" => "done", "pending" => "pending", "rejected" => "rejected", _ => "other" },
                    "sent_message_id": sent_id,
                    "age_seconds": current_now.saturating_sub(created).max(0)
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut stmt = db.prepare(
        "SELECT source FROM file_sends WHERE state='pending' ORDER BY length(source),source LIMIT 20",
    )?;
    let uncertain_file_sends = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|row| row.map(|source| json!({"message_id": source})))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut stmt = db.prepare(
        "SELECT source,state,result,size_bytes,updated,error FROM file_sends ORDER BY COALESCE(updated,0) DESC,length(source),source LIMIT 20",
    )?;
    let recent_file_sends = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?
        .map(|row| {
            row.map(|(source, state, result, size_bytes, updated, error)| {
                let sent_id = result
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| {
                        v["message_id"]
                            .as_str()
                            .filter(|id| snowflake(id))
                            .map(str::to_owned)
                    });
                json!({
                    "message_id": source,
                    "state": match state.as_str() { "done" => "done", "pending" => "pending", "rejected" => "rejected", _ => "other" },
                    "sent_message_id": sent_id,
                    "size_bytes": size_bytes,
                    "error": error.as_deref().map(safe_file_error),
                    "age_seconds": updated.map(|u| current_now.saturating_sub(u).max(0))
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let mut stmt =
        db.prepare("SELECT tool,stage,reason,at FROM tool_failures ORDER BY id DESC LIMIT 20")?;
    let recent_tool_failures = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .map(|row| {
            row.map(|(tool, stage, reason, at)| {
                json!({
                    "tool": tool,
                    "stage": stage,
                    "reason": reason,
                    "age_seconds": current_now.saturating_sub(at).max(0)
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);
    let recent_callback_failures = if let Ok(mut stmt) = db
        .prepare("SELECT sid,eid,status,error,at FROM callback_failures ORDER BY id DESC LIMIT 20")
    {
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?
        .map(|row| {
            row.map(|(sid, eid, status, error, at)| {
                let digest = format!(
                    "{:x}",
                    Sha256::digest(format!("{}:{}:{}", sid.len(), sid, eid).as_bytes())
                );
                let source = eid.strip_prefix("discord_").filter(|id| snowflake(id));
                json!({
                    "delivery_id": digest,
                    "message_id": source,
                    "status_code": status,
                    "error": error,
                    "age_seconds": current_now.saturating_sub(at).max(0)
                })
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(
        json!({"failed_inbox":inbox,"failed_inbox_truncated":inbox_truncated,
        "expired_failed_inbox_count": expired_failed_inbox_count,
        "pending_callbacks":queue,"pending_callbacks_truncated":queue_truncated,
        "terminal_callback_failure_history_available":false,
        "recent_callback_failures": recent_callback_failures,
        "uncertain_outgoing":outgoing,"uncertain_outgoing_truncated":outgoing_truncated,
        "recent_outgoing":recent_outgoing,
        "notification_destination_status":dest_status,
        "notification_destination_count":dest_count,
        "uncertain_notifications":uncertain_notifications,
        "recent_notifications":recent_notifications,
        "uncertain_file_sends":uncertain_file_sends,
        "recent_file_sends":recent_file_sends,
        "recent_tool_failures":recent_tool_failures}),
    )
}

/// A single conditional update is atomic against concurrent retries and the worker.
/// It only permits a recent, already staged owner ID that exhausted transient lookup retries.
pub fn retry_failed_inbox(b: &Bridge, args: &Value) -> Result<Value> {
    exact(args, &["message_id"])?;
    let id = string(args, "message_id")?;
    if !snowflake(id) {
        bail!("Invalid message ID");
    }
    let t = now();
    let db = b.db.lock().unwrap();
    let author: Option<String> = db
        .query_row(
            "SELECT author FROM inbox WHERE id=?1 AND status='failed'",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(author) = author.filter(|a| b.can_respond(a)) else {
        bail!("Message is not eligible for retry");
    };
    let n = db.execute("UPDATE inbox SET status='pending',tries=0,due=?1,last_error=NULL WHERE id=?2 AND author=?3 AND status='failed' AND received>=?4 AND received<=?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.id=inbox.id)", params![t,id,author,t-MAX_RETRY_AGE])?;
    if n != 1 {
        bail!("Message is not eligible for retry");
    }
    Ok(json!({"message_id":id,"status":"pending"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge() -> Bridge {
        crate::tests::bridge()
    }

    #[test]
    fn failed_inbox_prioritizes_recent_and_reports_expired_count() {
        let b = bridge();
        let db = b.db.lock().unwrap();
        let current_now = now();
        let old_time = current_now - 8 * 86400;
        let recent_time = current_now - 100;
        let owner = b.config.users.iter().next().unwrap();

        for i in 0..50 {
            db.execute(
                "INSERT INTO inbox(id,channel,author,status,tries,due,received,last_error) VALUES(?,'ch',?,'failed',5,0,?,'lookup_internal_error')",
                params![format!("100000000000000{i:03}"), owner, old_time],
            ).unwrap();
        }
        db.execute(
            "INSERT INTO inbox(id,channel,author,status,tries,due,received,last_error) VALUES('200000000000000001','ch',?,'failed',3,0,?,'discord_rate_limited')",
            params![owner, recent_time],
        ).unwrap();
        drop(db);

        let diag = diagnostics(&b, &json!({})).unwrap();
        let failed = diag["failed_inbox"].as_array().unwrap();
        assert!(!failed.is_empty());
        assert_eq!(failed[0]["message_id"], "200000000000000001");
        assert_eq!(failed[0]["retry_eligible"], true);
        assert_eq!(diag["expired_failed_inbox_count"], 50);
    }

    #[test]
    fn diagnostics_includes_recent_callback_failures_and_notifications() {
        let b = bridge();
        let db = b.db.lock().unwrap();
        let current_now = now();
        let owner = b.config.users.iter().next().unwrap();

        db.execute(
            r#"INSERT INTO notifications VALUES('keyhash1',?,'hash1','ch1','done','{"message_id":"300000000000000001","channel_id":"ch1"}',?)"#,
            params![owner, current_now - 50],
        ).unwrap();

        db.execute(
            "INSERT INTO callback_failures(sid,eid,status,error,at) VALUES('sub1','discord_400000000000000001',500,'Internal Server Error',?)",
            params![current_now - 20],
        ).unwrap();
        drop(db);

        let diag = diagnostics(&b, &json!({})).unwrap();
        assert_eq!(diag["terminal_callback_failure_history_available"], false);
        let cb_failures = diag["recent_callback_failures"].as_array().unwrap();
        assert_eq!(cb_failures.len(), 1);
        assert_eq!(cb_failures[0]["message_id"], "400000000000000001");
        assert_eq!(cb_failures[0]["status_code"], 500);

        let notifs = diag["recent_notifications"].as_array().unwrap();
        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0]["operation_id"], "keyhash1");
        assert_eq!(notifs[0]["sent_message_id"], "300000000000000001");
    }
}
