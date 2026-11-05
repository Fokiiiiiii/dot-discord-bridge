# AGENTS.md

## Security & Architecture Invariants

- Preserve single-owner authorization (`DISCORD_OWNER_USER_ID`), optional responder allowlist (`DISCORD_RESPONDERS_FILE`), and fresh Discord channel verification before storing or delivering message content.
- Keep DM destination resolution (`notification_destinations` and `messages`) strictly isolated from guild messages (`is_guild=true`).
- Maintain OAuth 2.1 S256 PKCE, exact resource/redirect binding, hashed token storage, and grant-family revocation checks.
- Preserve per-request DNS pinning and public-IP validation on outbound MCP event callbacks (`src/webhook.rs`).
- Never log secrets, tokens, cookies, raw callback URLs, or message bodies; diagnostic tools (`discord_bridge_status`, `discord_bridge_diagnostics`) must emit closed-vocabulary categories only.
- Record durable pre-send intent before any Discord write (`replies`, `outgoing_*`, `notifications`, `file_sends`) and never blindly retry uncertain writes.

## Verification

Run all checks before committing or releasing:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
git diff --check
```
