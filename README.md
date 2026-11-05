# dot-discord-bridge

A lightweight Rust bridge that connects Discord Bot DMs (and optional guild channels) to an MCP client via signed **MCP Events** and **OAuth 2.1 (S256 PKCE)**.

## Features

- **Event Subscription (`discord.dm.created`)**: Receives messages from the configured owner (or allowlisted responders) via Discord Gateway v10, verifies channel ownership via Discord REST, and delivers signed webhook events with recent context and attachment metadata.
- **Replies & Multipart Splitting (`discord_reply`, `discord_edit_reply`, `discord_finish_response`)**: Replies to observed messages in their original channel. Automatically splits long replies (up to 32,000 UTF-16 units) into `<=2,000`-unit chunks while preserving fenced code blocks. Supports in-place edits and bounded typing indicators.
- **Proactive Owner Notifications (`discord_notify_owner`)**: Sends standalone idempotent notifications (with optional owner mention) strictly to the owner's verified 1-on-1 DM.
- **Files & Reactions (`discord_send_file`, `discord_read_attachment`, `discord_react`)**: Sends base64-encoded files (`<20 MiB`), reads attachments (`<20 MiB`) from Discord's CDN, and adds/removes message reactions.
- **Diagnostics & Recovery (`discord_bridge_status`, `discord_bridge_diagnostics`, `discord_retry_failed_inbox`)**: Reports content-free queue counts, notification destination readiness, classified tool failure reasons, and explicit retries for failed inbox lookups.

## Setup

### 1. Configure `.env`

Copy `.env.example` to `deploy/.env` (`chmod 600 deploy/.env`) and set the required values:

```sh
cp .env.example deploy/.env
chmod 600 deploy/.env
```

| Variable | Description |
|---|---|
| `DISCORD_BOT_TOKEN` | Discord Bot token |
| `DISCORD_OWNER_USER_ID` | Single Discord owner user ID (17–20 digit snowflake) |
| `MCP_AUTH_MODE` | `oauth` (default) or `bearer` |
| `OAUTH_ISSUER` | Public HTTPS origin (e.g. `https://discord-mcp.example.com`) |
| `OAUTH_CLIENT_ID` | Predefined OAuth client ID (e.g. `discord-dot-owner`) |
| `OAUTH_CLIENT_SECRET` | Random secret (`>=32` chars, e.g. `openssl rand -hex 32`) |
| `OAUTH_OWNER_APPROVAL_SECRET` | Distinct random secret (`>=32` chars) for the browser consent form |
| `OAUTH_REDIRECT_URIS` | Exact OAuth redirect URI shown by your MCP client |
| `MCP_ALLOWED_HOSTS` | Public hostname serving this bridge |
| `CALLBACK_ALLOWED_HOSTS` | Allowed HTTPS hostname(s) for outbound MCP event webhooks |

Optional variables:

| Variable | Default | Description |
|---|---|---|
| `DISCORD_GUILD_ENABLED` | `false` | Set `true` to allow guild channel messages (requires Bot Message Content Intent) |
| `DISCORD_RESPONDERS_FILE` | unset | Path to JSON array of allowed user ID strings `["222222222222222222", ...]` (include owner ID; reloaded without restart) |
| `TYPING_TIMEOUT_SECS` | `120` | Max typing indicator lease in seconds (`0`–`300`) |
| `RECENT_CONTEXT_LIMIT` | `10` | Recent same-channel messages included in events (`0`–`20`) |

### 2. Run

**Docker Compose:**

```sh
cd deploy
docker compose up -d --build
docker compose exec discord-dm /usr/local/bin/discord-dot-bridge --healthcheck
```

**From Source:**

```sh
cargo test --locked
cargo build --release --locked
umask 077
./target/release/discord-dot-bridge
```

### 3. Reverse Proxy & Client Connection

The service binds to `127.0.0.1:8787`. Forward only the following paths over HTTPS while preserving `Host` and `Authorization` headers (do not expose `/healthz`):

- `/mcp`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/revoke`

Register `<OAUTH_ISSUER>/mcp` in your MCP client using `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`, approve consent in the browser using `OAUTH_OWNER_APPROVAL_SECRET`, and subscribe to `discord.dm.created`.
