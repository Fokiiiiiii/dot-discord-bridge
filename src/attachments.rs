//! Bounded untrusted attachment metadata; never fetch or forward attachment URLs.
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
