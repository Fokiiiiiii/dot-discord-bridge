# Discord DM → existing dot bridge (Rust, private prototype)

**Owner-only, one-to-one Bot DMs. No server-channel monitoring.**

Owner sends a DM to the Discord bot → Gateway `DIRECT_MESSAGES` → durable identifiers-only inbox → verify DM recipient and retrieve message using official Discord REST → SQLite outbox → signed MCP Events → existing dot → `discord_reply` to the same DM and source message.

No separate model, OpenAI API key, or Codex runtime is used. Rust 1.99+, a C compiler for bundled SQLite, one always-on process, persistent private disk, and public HTTPS are required. GitHub is optional for deployment.

## Security boundary

- Set exactly one `DISCORD_OWNER_USER_ID`. Other authors, bot/webhook authors, guild messages, group DMs and unverified channels are rejected.
- The bridge obtains `GET /api/v10/channels/{id}` using the Bot token and requires channel type `1`, no guild, and exactly one recipient matching the owner. Successful checks cache for five minutes, never across restart; queued deliveries and replies recheck when needed.
- Gateway intent is only `DIRECT_MESSAGES (1 << 12)`. Bot DMs are exempt from the privileged Message Content requirement. No server message/privileged content intent is requested.
- `discord.dm.created` subscriptions require the configured `owner_user_id`; a channel ID is not required or manually configured. The DM is learned from the owner's incoming message.
- Replies are only to observed owner messages in that same verified DM. One source message gets one logical reply, split into Discord-sized parts if needed; bridge-owned replies can be edited via their source ID. There is no send-to-arbitrary-recipient tool, unsolicited DM creation, or Discord thread creation. Discord DMs are already the conversation; reply references preserve context.
- Subscription automation must be created in the existing dot with a bounded response policy. Running this bridge alone does not generate replies.

## Setup

1. Choose an approved always-on host with persistent disk and outbound Discord WSS/HTTPS plus HTTPS callback access. Request-only serverless hosting is not assumed compatible.
2. Create/use a Discord **bot**, not a user token/self-bot. The owner must be able to open a DM with it. If Discord requires shared-server presence for discoverability/access, arrange that separately; this bridge still never reads server channels. No Administrator or server-channel read permission is required by this DM design. Bot privacy/DM rules can still prevent delivery.
3. Put `.env.example` values into the host's secure environment configuration. The application does not auto-load `.env`; do not source an untrusted file as shell code. Never paste live secrets into chat or include them in archives.
4. Use a new private `discord-dm.sqlite3` database. This version rejects legacy channel-mode databases and rejects changing the owner of an existing DM database. Keep backups private/encrypted. Start with `umask 077` to protect SQLite files and sidecars.
5. `cargo test --locked`, `cargo build --release --locked`, then run `./target/release/discord-dot-bridge`. It listens only on `127.0.0.1:8787`.
6. Put an HTTPS reverse proxy in front of `/mcp` and the exact OAuth/discovery routes listed in [OAuth setup](OAUTH.md); preserve Host/Authorization, configure request/rate limits, disable credential/body logging. Set `MCP_ALLOWED_HOSTS` to the exact public Host value.
7. Replace the placeholder endpoint in `plugin-template/mcp.json`, configure the predefined OAuth client in the private ChatGPT connection UI, follow [OAuth setup](OAUTH.md), and rescan. Verify `discord_reply` and `discord.dm.created` appear.
8. Ask this existing dot to monitor DMs from the configured owner and define what it may answer. Confirm the actual callback hostname via trusted connection diagnostics, allow only that hostname in `CALLBACK_ALLOWED_HOSTS`, restart/retry subscription if needed. Do not guess callback hosts or broadly allow arbitrary domains.
9. Send a harmless owner DM. Verify Gateway receipt → callback acknowledgment → existing dot execution → a single reply in the same DM. Test another author, group/guild message rejection, duplicates, unsubscribe, and restart.

## Transport and delivery behavior

Streamable HTTP `initialize` protocol `2025-03-26`, OAuth access-token authentication by default (explicit legacy bearer mode for diagnostics), exact inbound Host allowlist, no browser Origin on `/mcp`, 256 KiB MCP body limit. Not MCP 2.0. Events use webhook only; no polling/streaming/replay.

Callback destinations use exact HTTPS hostname allowlists, connection-time public-IP validation/pinning, normal hostname TLS verification, no redirects/proxies, bounded requests. Standard Webhooks HMAC-SHA256, signed verification, deterministic subscription identities, five-minute verification cache and key-rotation overlap. Lifetime is capped at 24 hours and rounded up to one-second granularity.

SQLite persists subscriptions, metadata-only inbox, verified messages, outbox and idempotency results. Owner ID is pinned to the database. Source and confirmed outgoing text retention is seven days; reply hashes, outgoing IDs, write journals and minimal result tombstones persist. Callback retries are bounded (eight attempts), stable IDs and possible duplicate attempts; delivery is not guaranteed and permanent/exhausted outbox failures are dropped. 410 deletes its subscription; 413 never retries. Event response bodies cannot override HTTP status. Production monitoring/dead-letter tooling is not included.

A source message with an uncertain write result is blocked from blind retry. Discord nonce provides only supplementary short-term deduplication. Gateway discovery and read lookups honor 429 delays. The bridge applies a conservative shared in-process REST cooldown after observed read/write 429 responses; this is not a full distributed bucket scheduler. Write errors, including 429, conservatively stop rather than blindly resending. Full route/global rate-limit scheduling is not included.

## Important limitations

- Incoming owner message/channel IDs are committed before advancing the Gateway sequence. No message text is stored until the DM recipient is verified. Network/429/5xx lookup failures are retried with bounded backoff (up to eight attempts); permanent denial/missing/wrong-recipient records become `rejected`, and exhausted retries remain `failed`, never silently deleted. `discord_bridge_status` exposes content-free counts. Pending/failed records survive restarts; completed/rejected metadata is retained seven days. Failed rows require operator inspection/recovery, not blind duplicate sends.
- Active subscriptions are selected when the verified message is hydrated, not when its ID was staged. If a subscription expired or was stopped during retries, no delivery is queued for it. A newly active matching subscription can receive a still-pending earlier message.
- After recipient verification the message body is retrieved from Discord. It reflects the message at lookup time, not necessarily the original pre-edit event text; the occurrence timestamp remains Discord’s original message timestamp. A deleted/inaccessible message cannot be recovered; its rejection is retained. Minimal owner-origin message/channel IDs can temporarily be stored for a group DM before it is identified/rejected, but its content is never stored or forwarded.
- A SQLite staging failure prevents sequence advancement and triggers a reconnect/resume; a processing DB failure stops the worker/process rather than being treated as an authorization error. Disk exhaustion still requires repair. A process crash before an event is durably staged, or loss of the resumable Gateway session, can still lose an event.
- Gateway resume state is in-memory. Process restarts/expired sessions can miss messages; no historical replay. This is not a guaranteed-delivery messaging service.
- Existing queued events whose channel verification temporarily fails use the bounded event retry policy. No data goes to the callback before verification succeeds.
- Attachment metadata is signaled after DM verification, but attachment bytes and URLs are not retrieved or provided; see [feature details](FEATURES.md). No voice, slash commands, incoming-message edits, history backfill, group DMs, server channels, sharding, unauthorized proactive notices, or creation of new or arbitrary DM destinations. Explicitly authorized notices can be sent to the configured owner’s previously observed and freshly verified one-to-one DM.
- Rotating/removing MCP credentials does not cancel existing subscriptions. Emergency revocation: stop the process and remove subscriptions before restarting with changed credentials.
- Private plugin registration, real callback verification, real Discord DMs, and this dot's live reply remain unverified until approved hosting and credentials are provided.

## Validation and files

See VALIDATION.md for executed tests. `src/main.rs`: MCP/persistence/DM authorization/replies; `src/gateway.rs`: DM receiver; `src/webhook.rs`: signed secure callbacks. `plugin-template/` is not an installed plugin. `.env.example` contains placeholders only.

Official references:
- https://docs.discord.com/developers/events/gateway#message-content-intent
- https://docs.discord.com/developers/resources/channel#get-channel
- https://docs.discord.com/developers/resources/message#create-message
- https://docs.discord.com/developers/topics/rate-limits
- https://developers.openai.com/plugins/build/mcp-events

## Discord client features (v0.4.0)

See [feature behavior and limits](FEATURES.md): bounded typing, multipart replies, source-bound edits, reply references, and configurable recent owner-DM context. All existing OAuth/recipient/SSRF/callback controls remain in place.

## Proactive owner notifications

The `discord_notify_owner` MCP tool sends an authorized standalone update only to the configured owner's previously observed and verified DM. Important updates/decisions can explicitly mention only that owner. Stable idempotency keys and a durable pre-send journal prevent blind retries after uncertain writes. See [NOTIFICATIONS.md](NOTIFICATIONS.md) for required parameters, limits and recovery boundaries. No scheduler, new recipient, deployment or configuration change is introduced.

### Recovery tools


`discord_bridge_diagnostics` lists bounded, content-free failed inbox, pending callback and uncertain outgoing metadata. `discord_retry_failed_inbox` is a narrowly scoped, explicit-owner-request retry of a recent failed inbox lookup, not a retry of an uncertain Discord write. Terminal callback failures are not retained. See [recovery behavior and limits](FEATURES.md#recovery-diagnostics-and-failed-inbox-retry).
