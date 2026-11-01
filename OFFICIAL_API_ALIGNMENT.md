# Official API alignment — DM-only + OAuth v0.3.0

Reviewed 2026-11-01 against official Discord documentation and the supported OpenAI MCP Events profile. Not certification or a successful live integration test.

| Area | Implementation | Official reference |
|---|---|---|
| Bot identity | Bot token only; no user-token/self-bot API. | [Authentication](https://docs.discord.com/developers/reference#authentication) |
| Gateway | Authenticated `/api/v10/gateway/bot`, WSS `v=10&encoding=json`, heartbeat/ACK, resume, session-start quota, close codes. | [Gateway](https://docs.discord.com/developers/events/gateway) |
| DM-only intent | `DIRECT_MESSAGES` bit 12 only; no guild or privileged content intent. | [Intents](https://docs.discord.com/developers/events/gateway#list-of-intents) |
| DM content | Messages in DMs with the app are exempt from the privileged Message Content restriction. | [Message Content](https://docs.discord.com/developers/events/gateway#message-content-intent) |
| Recipient verification | `GET /api/v10/channels/{id}`; require DM type `1` and one recipient equal to the configured owner. Group DM type `3` and guild/thread types rejected. | [Get Channel / channel object](https://docs.discord.com/developers/resources/channel#get-channel) |
| Message rehydration | After recipient verification, `GET /channels/{id}/messages/{message.id}` retrieves the persisted message ID. Edited/deleted-message limitations are explicit. | [Get Channel Message](https://docs.discord.com/developers/resources/message#get-channel-message) |
| Replies | Create Message in the same observed DM, source message reference, `fail_if_not_exists`, ≤2,000 characters. | [Create Message](https://docs.discord.com/developers/resources/message#create-message) |
| Mention suppression | Empty allowed_mentions.parse, replied_user false. | [Allowed mentions](https://docs.discord.com/developers/resources/message#allowed-mentions-object) |
| Duplicate defense | Stable nonce/enforce_nonce plus persistent local outcome; uncertain sends are blocked. Discord nonce window is short-term. | [Message parameters](https://docs.discord.com/developers/resources/message#create-message) |
| Rate limits | Gateway discovery honors 429 retry_after. Read lookups honor 429 and retry transient failures with a durable bounded inbox; uncertain writes do not blindly loop; high-volume route/global scheduling is not implemented. | [Rate limits](https://docs.discord.com/developers/topics/rate-limits) |
| Existing dot | `discord.dm.created` filtered by owner_user_id, Streamable HTTP, signed webhook challenge/delivery, subscribe/refresh/unsubscribe. | [MCP Events](https://developers.openai.com/plugins/build/mcp-events) |

DMs do not require creating a Discord thread. The bridge cannot create unsolicited DMs or send to arbitrary user IDs. Bot discoverability, mutual-server/DM privacy restrictions and platform plugin availability are external prerequisites, not bypassed by this code.

The event name/filter changed from the earlier channel prototype. Use a new DM-mode DB and rescan/re-subscribe the plugin; old channel subscriptions are not reused. Live owner-DM → existing-dot → same-DM reply remains to be tested with approved hosting and credentials.

OAuth follows the predefined confidential-client profile: protected-resource and authorization-server discovery, RFC 9207 issuer response, S256 PKCE, exact redirect/resource binding, explicit owner consent, hashed opaque tokens, refresh rotation/reuse and family revocation. See [OAuth setup](OAUTH.md) and [official authentication documentation](https://developers.openai.com/plugins/build/auth). Live ChatGPT connection remains unverified until deployed and consented.

v0.4 additions: typing uses POST /channels/{channel.id}/typing (204; Discord expires the indicator after10s, no stop endpoint); message edits use PATCH and tail removal DELETE only for persisted bridge-owned IDs. Every create/edit explicitly suppresses mentions. The2,000 UTF-16-unit chunk limit is deliberately conservative because Discord's text docs state characters without specifying a Unicode counting unit. Reply/recent context uses verified same-DM retained messages and message_reference/referenced_message semantics; no arbitrary reference fetch.
