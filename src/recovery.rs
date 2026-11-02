//! Bounded content-free diagnostics and explicit retry of transient failed inbox lookups.
//! Does not send messages, reset outgoing journals, or revive subscriptions.
use crate::{exact, now, snowflake, string, Bridge};
use anyhow::{bail, Result};
use rusqlite::params;
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

pub fn diagnostics(b: &Bridge, args: &Value) -> Result<Value> {
    exact(args, &[])?;
    let db = b.db.lock().unwrap();
    let owner = b.config.users.iter().next().unwrap();
    let mut stmt = db.prepare("SELECT id,tries,received,COALESCE(last_error,'') FROM inbox WHERE status='failed' AND author=? ORDER BY received,id LIMIT 51")?;
    let mut inbox = stmt.query_map([owner], |r| Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?
        .map(|row| row.map(|(id,tries,received,reason)| json!({"message_id":id,"attempts":tries,"age_seconds":now().saturating_sub(received).max(0),"reason":safe_reason(&reason)})))
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let inbox_truncated = inbox.len() > LIMIT;
    inbox.truncate(LIMIT);
    drop(stmt);
    // Terminal callback failures are deleted by the existing delivery policy;
    // do not present pending events as a failed-event history.
    let mut stmt =
        db.prepare("SELECT sid,eid,tries,due FROM queue ORDER BY due,sid,eid LIMIT 51")?;
    let mut queue = stmt.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?)))?
        .map(|row| row.map(|(sid,eid,tries,due)| {
            let digest = format!("{:x}", Sha256::digest(format!("{}:{}:{}", sid.len(), sid, eid).as_bytes()));
            let source = eid.strip_prefix("discord_").filter(|id| snowflake(id));
            json!({"delivery_id":digest,"message_id":source,"attempts":tries,"due_in_seconds":due.saturating_sub(now()).max(0)})
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
    Ok(
        json!({"failed_inbox":inbox,"failed_inbox_truncated":inbox_truncated,
        "pending_callbacks":queue,"pending_callbacks_truncated":queue_truncated,
        "terminal_callback_failure_history_available":false,
        "uncertain_outgoing":outgoing,"uncertain_outgoing_truncated":outgoing_truncated}),
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
    let owner = b.config.users.iter().next().unwrap();
    let t = now();
    let db = b.db.lock().unwrap();
    let n = db.execute("UPDATE inbox SET status='pending',tries=0,due=?1,last_error=NULL WHERE id=?2 AND author=?3 AND status='failed' AND received>=?4 AND received<=?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE messages.id=inbox.id)", params![t,id,owner,t-MAX_RETRY_AGE])?;
    if n != 1 {
        bail!("Message is not eligible for retry");
    }
    Ok(json!({"message_id":id,"status":"pending"}))
}
