# Discord → existing dot bridge (private prototype)

Discord Gateway → persistent local queue → signed MCP Events callback → **your existing dot** → `discord_reply` → Discord.

No Codex runtime, OpenAI API key, or separate AI bot is needed by this application. This implementation is Rust (edition 2021); dependencies are declared in Cargo.toml. This is a single-owner, single-process implementation, not a multi-tenant service.

## What was actually verified

Rust unit-test sources cover filtering/deduplication, authorization, discovery, uncertain replies, revoked-user delivery, callback validation, public-IP policy, signatures, and Gateway helpers. All 25 Rust tests and clippy with warnings denied passed; release build succeeded. See VALIDATION.md. No real Discord or ChatGPT connection, public deployment, or plugin installation has been performed. `plugin-template/` is a **template, not an installed/connected plugin**.

## Setup (requires owner approval before external changes)

1. Choose an always-on host with persistent disk and public HTTPS ingress, plus outbound HTTPS/WebSocket access to Discord and the actual ChatGPT callback hostname. Sites-only hosting is not assumed to support this persistent Gateway process. Run one instance only.
2. In Discord Developer Portal create/use a **bot**, not a user token/self-bot. Enable Message Content Intent. Grant only View Channel, Read Message History, Send Messages in one selected channel; no Administrator. Add it to the server with explicit approval. Threads need separate access and their own allowlisted channel ID.
3. Copy `.env.example` to `.env` **on that host**, set permissions `chmod 600 .env`, fill the bot token, a new random MCP bearer secret, exact channel and authorized Discord user IDs. Do not paste actual tokens into chat or include them in plugin archives. Do not use `source .env` on a file supplied by someone else: it executes shell code. Configure these values through the host's secret/environment settings.
4. `CALLBACK_ALLOWED_HOSTS` must contain the exact hostname from the real platform subscription. Establish that host from trusted connection diagnostics; do not guess or broadly allow arbitrary domains. Keep the callback pending until approved; the bridge fails closed without it. `MCP_ALLOWED_HOSTS` is the exact inbound HTTP Host header (normally your public hostname). The reverse proxy must preserve this header.
5. Install the official stable Rust toolchain using rustup after approval. Run `cargo test --locked` and `cargo build --release --locked`. Start with `umask 077; ./target/release/discord-dot-bridge` and the configured environment. Cargo.lock captures the resolved dependency versions.
6. The application binds only `127.0.0.1:8787`. Put an HTTPS reverse proxy in front, expose only `/mcp`, preserve Authorization and Host, enforce request limits/rate limits, and disable logging credentials and request bodies. Do not expose the internal port publicly. Persist the database on private encrypted disk and back it up securely: it includes webhook signing secrets and Discord text.
7. Replace the URL in `plugin-template/mcp.json` with the verified HTTPS `/mcp` endpoint. Connect as a **private** plugin with API-key/Bearer authentication through the platform UI; put `MCP_BEARER_TOKEN` only in its secure credential field, never in package files. Upload/installation is a separate, explicitly authorized step. Rescan and confirm `discord_reply` and `discord.message.created` are visible.
8. In the existing dot, ask it to subscribe to the exact channel and describe a narrow response policy. Example: “Monitor this channel for my Discord user only and answer ordinary messages there. Never disclose private chat history, files, or secrets; ask me before other actions.” The host creates the callback subscription. Successful HTTP callback delivery alone does not prove the dot replied.
9. Send a harmless live test message. Verify: subscription accepted → callback 2xx → existing dot sees event → one visible Discord reply. Test non-allowed authors/channels, a bot message, duplicate input, unsubscribe, and restart. Keep live testing restricted to the approved channel.

## Security and operational behavior

- Fail-closed channel **and user** allowlists on input and delivery; bot/webhook messages discarded.
- Authenticated Streamable HTTP endpoint, no CORS/browser Origin, explicit Host allowlist, 64 KiB request limit. This is intentionally server-to-server.
- Callback HTTPS + exact hostname allowlist + connection-time public-IP validation, no redirects/proxies, bounded timeout/body size. Standard Webhooks HMAC-SHA256, challenge verification, deterministic subscription IDs, 5-minute key-rotation overlap and verification cache. Subscription lifetime is capped at 24 hours and rounded up to a minimum one-second granularity.
- SQLite persists subscriptions, queue, source messages, and reply records. Owner is the single configured principal. Separate deployment and DB required for a different owner. Changes to allowlists require restart. Remove subscriptions by stopping monitoring; deleting/rotating the MCP credential alone does not remove active subscriptions, so stop the service and clear subscriptions as part of emergency revocation.
- Event retry is bounded (up to eight attempts), at-least-once; event IDs remain stable. Permanent failures are dropped. 410 removes the subscription; 413 is not retried. For production add metrics/dead-letter inspection and alerts; do not put message bodies or secrets in logs.
- One reply per observed source message. Persisted success prevents duplicates. An uncertain send is blocked rather than automatically retried; an operator must inspect Discord before recovery. Discord nonce is supplementary short-term protection only.
- Source messages are kept seven days. Reply content hashes and minimal idempotency results are retained indefinitely; reply text itself is not stored. Establish a tombstone retention policy before sustained use. No attachment download, history fetch, edits, slash commands, or guild administration.
- No protocol replay/cursor. In-memory Discord resume can bridge a reconnect, but a process restart, expired session, or queue failure can miss messages. Do not claim guaranteed delivery. No sharding or high-volume scaling.
- MCP Events draft/platform support may evolve. Current implementation uses documented Streamable HTTP `initialize` with protocol `2025-03-26`; it does not claim MCP 2.0 support. Live interoperability remains to be verified.

## Files and test command

`src/main.rs`: MCP + event delivery + reply tool. `src/gateway.rs`: Discord receiver. `src/webhook.rs`: secure callback delivery. Unit tests live inside each module. `.env.example`: placeholders. `plugin-template/`: private plugin packaging template.

```sh
cargo test --locked
```

## Official references (checked 2026-11-01)

- https://developers.openai.com/plugins/build/mcp-events
- https://docs.discord.com/developers/events/gateway
- https://docs.discord.com/developers/resources/message
- https://docs.discord.com/developers/topics/opcodes-and-status-codes

- Draft protocol reference: https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md
