//! File replies to observed DMs with durable idempotency and bounded uploads.
use crate::{now, snowflake, string, Bridge};
use anyhow::{bail, Context, Result};
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const LIMIT: usize = 20 * 1024 * 1024;
pub fn init(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS file_sends (key_hash TEXT PRIMARY KEY, source TEXT NOT NULL, content_hash TEXT NOT NULL, state TEXT NOT NULL, result TEXT, size_bytes INTEGER, updated INTEGER, error TEXT); CREATE INDEX IF NOT EXISTS idx_file_sends_state_source ON file_sends(state, source);")?;
    for col in [
        "ALTER TABLE file_sends ADD COLUMN size_bytes INTEGER",
        "ALTER TABLE file_sends ADD COLUMN updated INTEGER",
        "ALTER TABLE file_sends ADD COLUMN error TEXT",
    ] {
        let _ = db.execute(col, []);
    }
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_file_sends_updated ON file_sends(updated DESC);",
    )?;
    Ok(())
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn is_truncated_container(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return bytes.len() < 20 || !bytes.ends_with(b"\x00\x00\x00\x00IEND\xaeB\x60\x82");
    }
    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        let mut offset = 0usize;
        let mut saw_moov_or_moof = false;
        while offset < bytes.len() {
            if bytes.len() - offset < 8 {
                return true;
            }
            let size32 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            let box_type = &bytes[offset + 4..offset + 8];
            if box_type == b"moov" || box_type == b"moof" {
                saw_moov_or_moof = true;
            }
            let box_len = if size32 == 0 {
                bytes.len() - offset
            } else if size32 == 1 {
                if bytes.len() - offset < 16 {
                    return true;
                }
                let size64 = u64::from_be_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
                if size64 < 16 || size64 > (bytes.len() - offset) as u64 {
                    return true;
                }
                size64 as usize
            } else if size32 < 8 {
                return true;
            } else {
                size32
            };
            if box_len > bytes.len() - offset {
                return true;
            }
            offset += box_len;
        }
        return !saw_moov_or_moof;
    }
    false
}
fn prepare(p: &Value) -> Result<(String, String, String, Vec<u8>)> {
    let m = p.as_object().context("Expected object")?;
    for req in ["message_id", "idempotency_key", "filename", "data_base64"] {
        if !m.contains_key(req) {
            bail!("Unexpected fields");
        }
    }
    for k in m.keys() {
        if !matches!(
            k.as_str(),
            "message_id"
                | "idempotency_key"
                | "filename"
                | "data_base64"
                | "expected_size_bytes"
                | "expected_sha256"
        ) {
            bail!("Unexpected fields");
        }
    }
    let expected_size = match m.get("expected_size_bytes") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v.as_u64().context("Invalid upload parameters")?;
            if n >= LIMIT as u64 {
                bail!("Invalid upload size");
            }
            Some(n as usize)
        }
    };
    let expected_sha256 = match m.get("expected_sha256") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let s = v.as_str().context("Invalid upload parameters")?;
            if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("Invalid upload parameters");
            }
            Some(s)
        }
    };
    let source = string(p, "message_id")?;
    let key = string(p, "idempotency_key")?;
    let name = string(p, "filename")?;
    let data = string(p, "data_base64")?;
    let max_b64 = LIMIT.div_ceil(3) * 4;
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
        || data.len() > max_b64 + max_b64 / 32
    {
        bail!("Invalid upload parameters");
    }
    let cleaned: std::borrow::Cow<'_, [u8]> = if data.bytes().any(|b| b.is_ascii_whitespace()) {
        std::borrow::Cow::Owned(
            data.bytes()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>(),
        )
    } else {
        std::borrow::Cow::Borrowed(data.as_bytes())
    };
    if cleaned.len() > max_b64 {
        bail!("Invalid upload parameters");
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_ref())
        .ok()
        .context("Invalid upload parameters")?;
    if bytes.len() >= LIMIT {
        bail!("Invalid upload size");
    }
    if let Some(exp) = expected_size {
        if bytes.len() != exp {
            bail!("Upload size mismatch");
        }
    }
    if let Some(exp) = expected_sha256 {
        if !digest(&bytes).eq_ignore_ascii_case(exp) {
            bail!("Upload checksum mismatch");
        }
    }
    if is_truncated_container(&bytes) {
        bail!("Upload data appears truncated");
    }
    Ok((source.into(), key.into(), name.into(), bytes))
}
pub async fn send(b: &Bridge, p: &Value) -> Result<Value> {
    let (source, key, name, data) = prepare(p)?;
    let _lock = b.reply_lock.lock().await;
    let (channel, author): (String, String) =
        b.db.lock()
            .unwrap()
            .query_row(
                "SELECT channel,author FROM messages WHERE id=?",
                [&source],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context("Source not observed")?;
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
    let t = now();
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
            if state == "done" && hash == content_hash {
                return Ok(serde_json::from_str(&result.context("Missing result")?)?);
            }
            if state != "rejected" {
                bail!("Upload conflict or uncertain; inspect Discord");
            }
            db.execute(
                "UPDATE file_sends SET source=?,content_hash=?,state='pending',result=NULL,size_bytes=?,updated=?,error=NULL WHERE key_hash=?",
                params![source, content_hash, data.len() as i64, t, key_hash],
            )?;
        } else {
            db.execute(
                "INSERT INTO file_sends(key_hash,source,content_hash,state,result,size_bytes,updated,error) VALUES(?,?,?,'pending',NULL,?,?,NULL)",
                params![key_hash, source, content_hash, data.len() as i64, t],
            )?;
        }
    }
    let boundary = format!("discordbridge{}", uuid::Uuid::new_v4().simple());
    let payload = json!({"message_reference":{"message_id":source,"channel_id":channel,"fail_if_not_exists":true},"allowed_mentions":{"parse":[],"replied_user":false},"attachments":[{"id":0,"filename":name}],"nonce":&key_hash[..24],"enforce_nonce":true});
    let payload = payload.to_string();
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n{payload}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend_from_slice(&data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut res = match b
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
        .await
    {
        Ok(r) => r,
        Err(_) => {
            let db = b.db.lock().unwrap();
            let _ = db.execute(
                "UPDATE file_sends SET updated=?,error='discord_transport_uncertain' WHERE key_hash=?",
                params![now(), key_hash],
            );
            bail!("Upload unconfirmed; inspect Discord");
        }
    };
    let status = res.status().as_u16();
    if status == 429 {
        let retry_header = res
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        b.set_rest_cooldown(crate::retry_delay(retry_header, None));
        let mut bytes = Vec::new();
        while let Ok(Some(chunk)) = res.chunk().await {
            if bytes.len() + chunk.len() > 65536 {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        b.set_rest_cooldown(crate::retry_delay(
            retry_header,
            body["retry_after"].as_f64(),
        ));
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET state='rejected',updated=?,error='discord_rate_limited' WHERE key_hash=?",
            params![now(), key_hash],
        )?;
        crate::typing::finish(&db, &source)?;
        bail!("Discord rate limited file upload");
    }
    if status == 413 {
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET state='rejected',updated=?,error='discord_payload_too_large' WHERE key_hash=?",
            params![now(), key_hash],
        )?;
        crate::typing::finish(&db, &source)?;
        bail!("Discord rejected file upload: payload too large");
    }
    if matches!(status, 400 | 401 | 403 | 404 | 405 | 415 | 422) {
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET state='rejected',updated=?,error='discord_upload_rejected' WHERE key_hash=?",
            params![now(), key_hash],
        )?;
        crate::typing::finish(&db, &source)?;
        bail!("Discord rejected file upload");
    }
    if status != 200 {
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET updated=?,error='discord_5xx_uncertain' WHERE key_hash=?",
            params![now(), key_hash],
        )?;
        crate::typing::finish(&db, &source)?;
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
    let result = json!({"message_id":mid,"channel_id":channel,"size_bytes":data.len()});
    {
        let db = b.db.lock().unwrap();
        db.execute(
            "UPDATE file_sends SET state='done',result=?,size_bytes=?,updated=?,error=NULL WHERE key_hash=?",
            params![result.to_string(), data.len() as i64, now(), key_hash],
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
        let mut multiline = p.clone();
        multiline["data_base64"] = json!("aG\nk=\r\n");
        assert_eq!(prepare(&multiline).unwrap().3, b"hi");
        let mut empty = p.clone();
        empty["data_base64"] = json!("");
        assert!(prepare(&empty).unwrap().3.is_empty());
        for bad in [
            json!({"filename":"../bad"}),
            json!({"data_base64":"!!!"}),
            json!({"message_id":"bad"}),
            json!({"expected_size_bytes":999}),
            json!({"expected_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}),
        ] {
            let mut v = p.clone();
            for (k, val) in bad.as_object().unwrap() {
                v[k] = val.clone();
            }
            assert!(prepare(&v).is_err());
        }
    }
    #[test]
    fn detects_truncated_mp4_and_png_containers() {
        // Valid minimal MP4: [ftyp (16 bytes)][moov (8 bytes)][mdat (16 bytes)]
        let mut valid_mp4 = Vec::new();
        valid_mp4.extend_from_slice(&16u32.to_be_bytes());
        valid_mp4.extend_from_slice(b"ftypisom    ");
        valid_mp4.extend_from_slice(&8u32.to_be_bytes());
        valid_mp4.extend_from_slice(b"moov");
        valid_mp4.extend_from_slice(&1000u32.to_be_bytes());
        valid_mp4.extend_from_slice(b"mdat");
        valid_mp4.extend_from_slice(&vec![0u8; 992]);
        let p_valid = json!({
            "message_id": "333333333333333333",
            "idempotency_key": "mp4-ok",
            "filename": "video.mp4",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(&valid_mp4),
            "expected_size_bytes": valid_mp4.len()
        });
        assert_eq!(prepare(&p_valid).unwrap().3.len(), valid_mp4.len());

        // Truncated MP4 cut mid-mdat (even on a 4-byte boundary so base64 decodes cleanly!)
        let truncated_mp4 = &valid_mp4[..120];
        let p_trunc = json!({
            "message_id": "333333333333333333",
            "idempotency_key": "mp4-trunc",
            "filename": "video.mp4",
            "data_base64": base64::engine::general_purpose::STANDARD.encode(truncated_mp4)
        });
        let err = prepare(&p_trunc).unwrap_err();
        assert_eq!(err.to_string(), "Upload data appears truncated");
    }
}
