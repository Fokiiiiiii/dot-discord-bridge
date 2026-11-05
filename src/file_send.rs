//! File replies to observed DMs with durable idempotency and bounded uploads.
use crate::{exact, snowflake, string, Bridge};
use anyhow::{bail, Context, Result};
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const LIMIT: usize = 20 * 1024 * 1024;
pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS file_sends (key_hash TEXT PRIMARY KEY, source TEXT NOT NULL, content_hash TEXT NOT NULL, state TEXT NOT NULL, result TEXT)")?;
    Ok(())
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn prepare(p: &Value) -> Result<(String, String, String, Vec<u8>)> {
    exact(
        p,
        &["message_id", "idempotency_key", "filename", "data_base64"],
    )?;
    let source = string(p, "message_id")?;
    let key = string(p, "idempotency_key")?;
    let name = string(p, "filename")?;
    let data = string(p, "data_base64")?;
    if !snowflake(source)
        || key.is_empty()
        || key.len() > 128
        || name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | '"'))
        || data.len() > ((LIMIT + 2) / 3) * 4
    {
        bail!("Invalid upload parameters");
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
    if bytes.len() >= LIMIT {
        bail!("Invalid upload size");
    }
    Ok((source.into(), key.into(), name.into(), bytes))
}
pub async fn send(b: &Bridge, p: &Value) -> Result<Value> {
    let (source, key, name, data) = prepare(p)?;
    let _lock = b.reply_lock.lock().await;
    let (channel, author): (String, String) = b.db.lock().unwrap().query_row(
        "SELECT channel,author FROM messages WHERE id=?",
        [&source],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !b.can_respond(&author) {
        bail!("Unauthorized source");
    }
    b.ensure_channel(&channel).await?;
    b.check_rest_cooldown()?;
    let key_hash = digest(key.as_bytes());
    let mut hash = Sha256::new();
    for part in [source.as_bytes(), name.as_bytes(), data.as_slice()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let content_hash = format!("{:x}", hash.finalize());
    {
        let db = b.db.lock().unwrap();
        let prior: Option<(String, String, Option<String>)> = db
            .query_row(
                "SELECT content_hash,state,result FROM file_sends WHERE key_hash=?",
                [&key_hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((hash, state, result)) = prior {
            if hash != content_hash || state != "done" {
                bail!("Upload conflict or uncertain; inspect Discord");
            }
            return Ok(serde_json::from_str(&result.context("Missing result")?)?);
        }
        db.execute(
            "INSERT INTO file_sends VALUES(?,?,?,'pending',NULL)",
            params![key_hash, source, content_hash],
        )?;
    }
    let boundary = format!("discordbridge{}", uuid::Uuid::new_v4().simple());
    let payload = json!({"message_reference":{"message_id":source,"channel_id":channel,"fail_if_not_exists":true},"allowed_mentions":{"parse":[],"replied_user":false},"attachments":[{"id":0,"filename":name}],"nonce":&key_hash[..24],"enforce_nonce":true});
    let payload = payload.to_string();
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n{payload}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(&data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut res = b
        .http
        .post(format!(
            "https://discord.com/api/v10/channels/{channel}/messages"
        ))
        .timeout(std::time::Duration::from_secs(30))
        .header("Authorization", format!("Bot {}", b.config.bot))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await?;
    if res.status().as_u16() == 429 {
        b.set_rest_cooldown(crate::retry_delay(
            res.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            None,
        ));
    }
    if res.status().as_u16() != 200 {
        bail!("Upload unconfirmed; inspect Discord");
    }
    let mut buf = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if buf.len() + chunk.len() > 65536 {
            bail!("Invalid response");
        }
        buf.extend_from_slice(&chunk);
    }
    let result: Value = serde_json::from_slice(&buf)?;
    let mid = string(&result, "id")?;
    if !snowflake(mid) || result["channel_id"].as_str() != Some(&channel) {
        bail!("Invalid response identity");
    }
    let result = json!({"message_id":mid,"channel_id":channel});
    {
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET state='done',result=? WHERE key_hash=?",
            params![result.to_string(), key_hash],
        )?;
        crate::typing::finish(&db, &source)?;
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_exactly_twenty_mib_and_larger() {
        let mut p = json!({"message_id":"333333333333333333","idempotency_key":"x","filename":"a.txt","data_base64":""});
        p["data_base64"] = json!(base64::engine::general_purpose::STANDARD.encode(vec![0; LIMIT]));
        assert!(prepare(&p).is_err());
        p["data_base64"] =
            json!(base64::engine::general_purpose::STANDARD.encode(vec![0; LIMIT - 1]));
        assert_eq!(prepare(&p).unwrap().3.len(), LIMIT - 1);
    }
    #[test]
    fn rejects_invalid_uploads() {
        let p = json!({"message_id":"333333333333333333","idempotency_key":"x","filename":"日本語.txt","data_base64":"aGk="});
        assert_eq!(prepare(&p).unwrap().3, b"hi");
        let mut empty = p.clone();
        empty["data_base64"] = json!("");
        assert!(prepare(&empty).unwrap().3.is_empty());
        for bad in [
            json!({"filename":"../bad"}),
            json!({"data_base64":"!!!"}),
            json!({"message_id":"bad"}),
        ] {
            let mut v = p.clone();
            for (k, val) in bad.as_object().unwrap() {
                v[k] = val.clone();
            }
            assert!(prepare(&v).is_err());
        }
    }
}
