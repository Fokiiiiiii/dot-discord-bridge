//! Content-preserving Discord chunks. UTF-16 units are deliberately conservative:
//! Discord documents 2,000 characters but does not specify Unicode counting there.
use anyhow::{bail, Result};

pub const MAX_MESSAGE: usize = 2000;
pub const MAX_LOGICAL: usize = 32_000;
pub const MAX_PARTS: usize = 32;

pub fn discord_len(text: &str) -> usize {
    text.encode_utf16().count()
}

#[derive(Clone, Debug)]
struct Fence {
    marker: char,
    count: usize,
    // Preserve the original language/info string (and indentation).
    opener: String,
}
impl Fence {
    fn close(&self) -> String {
        format!("\n{}", self.marker.to_string().repeat(self.count))
    }
    fn reopen(&self) -> String {
        format!("{}\n", self.opener)
    }
}

struct Layout {
    // A fence change becomes effective after its complete delimiter line.
    changes: Vec<(usize, Option<Fence>)>,
    delimiters: Vec<(usize, usize)>,
}
impl Layout {
    fn parse(text: &str) -> Result<Self> {
        let mut changes = Vec::new();
        let mut delimiters = Vec::new();
        let mut active: Option<Fence> = None;
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            let raw = line.trim_end_matches(['\r', '\n']);
            let indent = raw.bytes().take_while(|b| *b == b' ').count();
            let body = &raw[indent..];
            let marker = body.chars().next().unwrap_or(' ');
            let count = body.chars().take_while(|c| *c == marker).count();
            let tail = if matches!(marker, '`' | '~') {
                &body[count..] // Both markers are single-byte ASCII.
            } else {
                ""
            };
            let delimiter = if indent <= 3 && matches!(marker, '`' | '~') && count >= 3 {
                if let Some(fence) = &active {
                    if fence.marker == marker && count >= fence.count && tail.trim().is_empty() {
                        active = None;
                        true
                    } else {
                        false
                    }
                } else if marker != '`' || !tail.contains('`') {
                    // Very long metadata/delimiters cannot be reopened safely within
                    // the message budget; fail rather than corrupt the source.
                    if discord_len(raw) > 256 {
                        bail!("Code fence delimiter/info exceeds 256 UTF-16 units");
                    }
                    active = Some(Fence {
                        marker,
                        count,
                        opener: raw.to_owned(),
                    });
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let end = offset + line.len();
            if delimiter {
                if discord_len(line) > MAX_MESSAGE {
                    bail!("Code fence delimiter exceeds Discord message limit");
                }
                delimiters.push((offset, end));
                changes.push((end, active.clone()));
            }
            offset = end;
        }
        Ok(Self {
            changes,
            delimiters,
        })
    }
    fn state(&self, offset: usize) -> Option<&Fence> {
        let n = self.changes.partition_point(|(at, _)| *at <= offset);
        n.checked_sub(1).and_then(|i| self.changes[i].1.as_ref())
    }
    fn boundary_allowed(&self, offset: usize) -> bool {
        !self
            .delimiters
            .iter()
            .any(|(a, b)| *a < offset && offset < *b)
    }
}

// Higher ranks are preferred, but only within the latter half of a chunk to
// prevent a remote paragraph boundary from producing many tiny messages.
fn preference(text: &str, offset: usize) -> u8 {
    let before = &text[..offset];
    if before.ends_with("\n\n") || before.ends_with("\r\n\r\n") {
        return 4;
    }
    if before.ends_with('\n') {
        return 3;
    }
    let trimmed = before.trim_end_matches(char::is_whitespace);
    let last = trimmed.chars().next_back();
    if matches!(last, Some('。' | '！' | '？'))
        || (matches!(last, Some('.' | '!' | '?')) && trimmed.len() != before.len())
    {
        return 2;
    }
    if before.chars().next_back().is_some_and(char::is_whitespace) {
        return 1;
    }
    0
}

pub fn split(text: &str) -> Result<Vec<String>> {
    if text.is_empty() || text.trim().is_empty() {
        bail!("Reply must contain non-whitespace text");
    }
    let len = discord_len(text);
    if len > MAX_LOGICAL {
        bail!("Logical reply exceeds 32000 UTF-16 units");
    }
    let layout = Layout::parse(text)?;
    let mut boundaries = vec![(0, 0)];
    let mut units = 0;
    for (at, c) in text.char_indices() {
        units += c.len_utf16();
        boundaries.push((at + c.len_utf8(), units));
    }
    let mut output = Vec::new();
    let mut start_index = 0;
    while start_index + 1 < boundaries.len() {
        if output.len() >= MAX_PARTS {
            bail!("Logical reply requires more than 32 parts");
        }
        let (start, start_units) = boundaries[start_index];
        let prefix = layout.state(start).map(Fence::reopen).unwrap_or_default();
        let prefix_units = discord_len(&prefix);
        let mut candidates = Vec::new();
        for (index, &(end, end_units)) in boundaries.iter().enumerate().skip(start_index + 1) {
            let used = prefix_units + end_units - start_units;
            if used > MAX_MESSAGE {
                break;
            }
            if !layout.boundary_allowed(end) {
                continue;
            }
            // Keep a real character in a short trailing whitespace-only remainder.
            // Discord rejects whitespace-only messages; never silently trim it.
            if end < text.len() && layout.state(end).is_none() && text[end..].trim().is_empty() {
                continue;
            }
            let closing = layout.state(end).map(Fence::close).unwrap_or_default();
            if used + discord_len(&closing) <= MAX_MESSAGE {
                candidates.push((index, end, end_units, closing));
            }
        }
        let Some(last) = candidates.last() else {
            bail!("Cannot split code fence within Discord message limit");
        };
        let chosen = if last.1 == text.len() {
            candidates.len() - 1
        } else {
            let half = (last.2 - start_units) / 2;
            candidates
                .iter()
                .enumerate()
                .filter(|(_, c)| c.2 - start_units >= half)
                .max_by_key(|(_, c)| (preference(text, c.1), c.1))
                .map(|(i, _)| i)
                .unwrap()
        };
        let (index, end, _, closing) = &candidates[chosen];
        let part = format!("{prefix}{}{closing}", &text[start..*end]);
        if part.trim().is_empty() {
            bail!("Splitting would produce an empty Discord message");
        }
        debug_assert!(discord_len(&part) <= MAX_MESSAGE);
        output.push(part);
        start_index = *index;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bounded(parts: &[String]) {
        assert!(!parts.is_empty());
        assert!(parts.len() <= MAX_PARTS);
        assert!(parts
            .iter()
            .all(|p| !p.trim().is_empty() && discord_len(p) <= MAX_MESSAGE));
    }
    #[test]
    fn plain_content_is_exact_and_bounded() {
        for text in [
            "a".repeat(2000),
            "a".repeat(2001),
            "日本語😀e\u{301}".repeat(1000),
            "x".repeat(MAX_LOGICAL),
        ] {
            let parts = split(&text).unwrap();
            bounded(&parts);
            assert_eq!(parts.concat(), text);
        }
    }
    #[test]
    fn utf16_astral_limit_and_no_character_corruption() {
        let text = "😀".repeat(1001);
        let parts = split(&text).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].chars().count(), 1000);
        assert_eq!(parts.concat(), text);
    }
    #[test]
    fn preferred_boundaries_preserve_whitespace() {
        for separator in ["\n\n", "\n", ". ", " "] {
            let text = format!("{}{}{}", "a".repeat(1500), separator, "b".repeat(1000));
            let parts = split(&text).unwrap();
            assert_eq!(parts[0], format!("{}{}", "a".repeat(1500), separator));
            assert_eq!(parts.concat(), text);
        }
    }
    #[test]
    fn code_fence_reopens_language_and_closes_each_part() {
        let text = format!("```rust\n{}\n```", "let x = 1;\n".repeat(500));
        let parts = split(&text).unwrap();
        bounded(&parts);
        assert!(parts.len() > 1);
        assert!(parts
            .iter()
            .all(|p| p.starts_with("```rust\n") && p.ends_with("```")));
        let mut reconstructed = parts[0].clone();
        for next in parts.iter().skip(1) {
            reconstructed.truncate(reconstructed.len() - "\n```".len());
            reconstructed.push_str(next.strip_prefix("```rust\n").unwrap());
        }
        assert_eq!(reconstructed, text);
    }
    #[test]
    fn long_code_line_and_unterminated_fence_are_safe() {
        let text = format!("```python\n{}", "😀".repeat(3000));
        let parts = split(&text).unwrap();
        bounded(&parts);
        assert!(parts
            .iter()
            .all(|p| p.starts_with("```python\n") && p.ends_with("\n```")));
    }
    #[test]
    fn tilde_fences_and_longer_delimiters() {
        for marker in ["~~~~", "````"] {
            let text = format!("{marker}js\n{}\n{marker}\n", "hello\n".repeat(600));
            let parts = split(&text).unwrap();
            bounded(&parts);
            assert!(parts
                .iter()
                .all(|p| p.starts_with(&format!("{marker}js\n"))));
        }
    }
    #[test]
    fn inline_backticks_are_not_block_fences() {
        let text = "Example: ```x``` and more. ".repeat(200);
        let parts = split(&text).unwrap();
        assert_eq!(parts.concat(), text);
    }
    #[test]
    fn fences_not_split_and_crlf_preserved() {
        let text = format!(
            "{}\r\n```typescript\r\n{}\r\n```",
            "a".repeat(1990),
            "x".repeat(3000)
        );
        let parts = split(&text).unwrap();
        bounded(&parts);
        assert!(!parts[0].contains("```type"));
        assert!(parts.iter().skip(1).all(|p| p.contains("```typescript")));
    }
    #[test]
    fn trailing_whitespace_is_not_an_empty_message() {
        for tail in ["\n", "  ", "\r\n"] {
            let text = format!("{}{tail}", "x".repeat(MAX_MESSAGE));
            let parts = split(&text).unwrap();
            bounded(&parts);
            assert_eq!(parts.concat(), text);
        }
    }
    #[test]
    fn rejects_empty_oversize_and_pathological_delimiters() {
        for text in [
            "".to_owned(),
            " \n\t".to_owned(),
            "x".repeat(MAX_LOGICAL + 1),
            format!("```{}\nx", "l".repeat(300)),
        ] {
            assert!(split(&text).is_err());
        }
    }
}
