//! Bounded untrusted attachment metadata and verified-source content retrieval.
use serde_json::{json, Value};

const MAX_ATTACHMENTS: usize = 10;
const MAX_FILENAME_UTF16: usize = 255;
const MAX_MEDIA_TYPE_BYTES: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

// Drop control/format characters that could forge lines or disguise displayed text.
fn unsafe_filename_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

fn filename(value: &Value, changed: &mut bool) -> Option<String> {
    let Some(input) = value.as_str() else {
        *changed = true;
        return None;
    };
    let mut result = String::new();
    let mut units = 0;
    for c in input.chars() {
        if unsafe_filename_char(c) {
            *changed = true;
            continue;
        }
        if units + c.len_utf16() > MAX_FILENAME_UTF16 {
            *changed = true;
            break;
        }
        units += c.len_utf16();
        result.push(c);
    }
    if result.is_empty() {
        *changed = true;
        None
    } else {
        Some(result)
    }
}

fn media_type(value: &Value, changed: &mut bool) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let Some(s) = value.as_str() else {
        *changed = true;
        return None;
    };
    let mut parts = s.split('/');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&c))
    };
    if s.len() > MAX_MEDIA_TYPE_BYTES
        || !parts.next().is_some_and(valid_part)
        || !parts.next().is_some_and(valid_part)
        || parts.next().is_some()
    {
        *changed = true;
        return None;
    }
    Some(s.to_owned())
}

/// Call only for an already verified owner DM, after source identity checks.
/// Missing/malformed arrays are left unknown rather than represented as empty.
pub fn augment(message: &Value, data: &mut Value) {
    let Some(items) = message.get("attachments").and_then(Value::as_array) else {
        return;
    };
    let mut changed = items.len() > MAX_ATTACHMENTS;
    let metadata: Vec<Value> = items
        .iter()
        .take(MAX_ATTACHMENTS)
        .map(|item| {
            let name = filename(&item["filename"], &mut changed);
            let media = media_type(&item["content_type"], &mut changed);
            let size = match item["size"].as_u64() {
                Some(n) if n <= MAX_SAFE_INTEGER => Some(n),
                _ => {
                    changed = true;
                    None
                }
            };
            json!({"filename":name,"media_type":media,"size_bytes":size})
        })
        .collect();
    data["attachments"] = json!(metadata);
    data["attachments_truncated"] = json!(changed);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_untrusted_metadata_excludes_urls() {
        let mut list = vec![
            json!({"filename":format!("a\n\u{202e}{}", "😀".repeat(200)),"content_type":"image/png","size":42,"url":"https://cdn.example/secret","proxy_url":"https://proxy.example/secret"}),
        ];
        list.extend((0..10).map(|_| json!({"filename":"x","content_type":"bad\nmedia","size":-1})));
        let mut data = json!({});
        augment(&json!({"attachments":list}), &mut data);
        let a = data["attachments"].as_array().unwrap();
        assert_eq!(a.len(), 10);
        assert_eq!(
            a[0]["filename"].as_str().unwrap().encode_utf16().count(),
            255
        );
        assert!(!a[0]["filename"].as_str().unwrap().contains('\n'));
        assert!(!a[0]["filename"].as_str().unwrap().contains('\u{202e}'));
        assert_eq!(a[0]["media_type"], "image/png");
        assert_eq!(a[0]["size_bytes"], 42);
        assert!(a[1]["media_type"].is_null());
        assert!(a[1]["size_bytes"].is_null());
        assert_eq!(data["attachments_truncated"], true);
        assert!(!data.to_string().contains("cdn.example"));
        assert!(!data.to_string().contains("proxy.example"));
    }
    #[test]
    fn absence_is_unknown_and_empty_is_explicit() {
        let mut data = json!({});
        augment(&json!({}), &mut data);
        assert!(data.get("attachments").is_none());
        augment(&json!({"attachments":[]}), &mut data);
        assert_eq!(data["attachments"], json!([]));
        assert_eq!(data["attachments_truncated"], false);
    }
}

/// Return image blocks when magic bytes identify a supported image; all claims in
/// the Discord metadata remain untrusted. Other files use an MCP resource.
fn content_block(mid: &str, index: usize, bytes: &[u8]) -> Value {
    use base64::Engine;
    let mime = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    };
    if let Some(mime) = mime {
        return json!({"type":"image","mimeType":mime,"data":base64::engine::general_purpose::STANDARD.encode(bytes)});
    }
    let uri = format!("discord-attachment://{mid}/{index}");
    if bytes.starts_with(b"%PDF-") {
        return json!({"type":"resource","resource":{"uri":uri,"mimeType":"application/pdf","blob":base64::engine::general_purpose::STANDARD.encode(bytes)}});
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if !text.contains('\0') {
            return json!({"type":"resource","resource":{"uri":uri,"mimeType":"text/plain","text":text}});
        }
    }
    json!({"type":"resource","resource":{"uri":uri,"mimeType":"application/octet-stream","blob":base64::engine::general_purpose::STANDARD.encode(bytes)}})
}

fn valid_cdn_url(url: &url::Url, channel: &str, id: &str) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("cdn.discordapp.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url
            .path()
            .starts_with(&format!("/attachments/{channel}/{id}/"))
}

/// Read an attachment belonging to a freshly verified, previously observed owner DM.
/// The URL is taken only from Discord's authenticated message response, never the caller.
pub async fn read(b: &crate::Bridge, p: &Value) -> anyhow::Result<Value> {
    use anyhow::{bail, Context};
    crate::exact(p, &["message_id", "index"])?;
    let mid = crate::string(p, "message_id")?;
    if !crate::snowflake(mid) {
        bail!("Invalid message");
    }
    let index = p["index"]
        .as_u64()
        .filter(|v| *v < 10)
        .context("Invalid attachment index")? as usize;
    let (channel, author): (String, String) =
        b.db.lock()
            .unwrap()
            .query_row(
                "SELECT channel,author FROM messages WHERE id=?",
                [mid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .context("Source not observed")?;
    if !b.can_respond(&author) {
        bail!("Unauthorized source");
    }
    b.ensure_channel(&channel).await?;
    let message = b
        .discord_get(&format!("channels/{channel}/messages/{mid}"))
        .await?;
    if message["id"].as_str() != Some(mid)
        || message["channel_id"].as_str() != Some(&channel)
        || message["author"]["id"].as_str() != Some(&author)
        || (!b.config.guild_enabled && !message["guild_id"].is_null())
        || message["author"]["bot"].as_bool() == Some(true)
        || !message["webhook_id"].is_null()
    {
        bail!("Message identity mismatch");
    }
    let item = message["attachments"]
        .as_array()
        .and_then(|a| a.get(index))
        .context("Attachment unavailable")?;
    const LIMIT: usize = 20 * 1024 * 1024;
    if item["size"]
        .as_u64()
        .filter(|n| *n < LIMIT as u64)
        .is_none()
    {
        bail!("Attachment exceeds size limit");
    }
    let id = item["id"]
        .as_str()
        .filter(|s| crate::snowflake(s))
        .context("Invalid attachment")?;
    let url = url::Url::parse(item["url"].as_str().context("Attachment unavailable")?)?;
    if !valid_cdn_url(&url, &channel, id) {
        bail!("Invalid attachment location");
    }
    let mut response = b
        .http
        .get(url)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() >= LIMIT {
            bail!("Attachment exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() as u64 != item["size"].as_u64().unwrap() {
        bail!("Attachment size mismatch");
    }
    let mut changed = false;
    let name = filename(&item["filename"], &mut changed).unwrap_or_else(|| "attachment".into());
    Ok(
        json!({"content":[content_block(mid,index,&bytes),{"type":"text","text":format!("Attachment: {name}")}]}),
    )
}

#[cfg(test)]
mod download_tests {
    use super::*;
    #[test]
    fn returns_content_types_based_on_bytes_not_declared_metadata() {
        let png = content_block("333333333333333333", 0, b"\x89PNG\r\n\x1a\nexample");
        assert_eq!(png["type"], "image");
        assert_eq!(png["mimeType"], "image/png");
        let pdf = content_block("333333333333333333", 0, b"%PDF-1.7\nexample");
        assert_eq!(pdf["resource"]["mimeType"], "application/pdf");
        let text = content_block("333333333333333333", 0, "日本語".as_bytes());
        assert_eq!(text["resource"]["text"], "日本語");
        let bytes = content_block("333333333333333333", 0, b"\x00\xff");
        assert_eq!(bytes["resource"]["mimeType"], "application/octet-stream");
    }
    #[test]
    fn only_matching_discord_cdn_attachment_is_accepted() {
        let channel = "123456789012345678";
        let id = "987654321098765432";
        let good = format!("https://cdn.discordapp.com/attachments/{channel}/{id}/file.txt?ex=123");
        assert!(valid_cdn_url(&url::Url::parse(&good).unwrap(), channel, id));
        for bad in [
            good.replace("cdn.discordapp.com", "cdn.discordapp.com.evil.test"),
            good.replace(channel, "123456789012345679"),
            good.replace(id, "987654321098765433"),
            good.replace("https:", "http:"),
            format!("{good}#fragment"),
        ] {
            assert!(!valid_cdn_url(&url::Url::parse(&bad).unwrap(), channel, id));
        }
    }
}
