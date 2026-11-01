# Official API alignment

Reviewed 2026-11-01 against Discord's official documentation and OpenAI's supported MCP Events profile. This is an implementation review, **not certification or a successful live integration test**.

| Area | Implementation | Official reference |
|---|---|---|
| Bot authentication | `Authorization: Bot …` on Discord REST; bot token in Gateway Identify/Resume. No user tokens or self-bot APIs. | [API authentication](https://docs.discord.com/developers/reference#authentication) |
| Gateway version/format | WSS discovered from authenticated `GET /api/v10/gateway/bot`; `v=10&encoding=json`. | [Gateway](https://docs.discord.com/developers/events/gateway) |
| Intents | Guilds, guild messages, direct messages, Message Content. Message Content must be enabled/approved in Developer Portal. Server-side channel and author filters remain mandatory. | [Gateway intents](https://docs.discord.com/developers/events/gateway#gateway-intents) |
| Connection lifecycle | Hello interval, heartbeat and ACK, sequence/session storage, Resume, Invalid Session, reconnect, fatal close handling, single-shard guard. | [Gateway lifecycle](https://docs.discord.com/developers/events/gateway#connection-lifecycle), [close codes](https://docs.discord.com/developers/topics/opcodes-and-status-codes#gateway-gateway-close-event-codes) |
| Identify limits | Refresh session-start quota before Identify; stop until reset when exhausted; conservatively separate attempts by over five seconds. | [Session start limits](https://docs.discord.com/developers/events/gateway#session-start-limit-object) |
| Message receive | Handle `MESSAGE_CREATE`; ignore bot/webhook authors and non-allowlisted channels/users. | [Gateway events](https://docs.discord.com/developers/events/gateway-events#message-create) |
| Reply | `POST /api/v10/channels/{channel.id}/messages`, content ≤2,000 characters, message reference and `fail_if_not_exists`. | [Create Message](https://docs.discord.com/developers/resources/message#create-message) |
| Mention safety | Empty `allowed_mentions.parse` and `replied_user:false`. | [Allowed mentions](https://docs.discord.com/developers/resources/message#allowed-mentions-object) |
| Duplicate protection | Stable source-message nonce with `enforce_nonce:true`, supplemented by durable SQLite reply records. Discord nonce history is short-term; not an exactly-once guarantee. | [Create Message parameters](https://docs.discord.com/developers/resources/message#create-message) |
| REST rate limits | Gateway discovery handles 429 by the server-provided delay. Reply writes conservatively stop on any non-200, including 429; they do not automatically retry uncertain sends. This prototype has no full shared route/global rate-limit scheduler; high-volume use needs one. | [Rate Limits](https://docs.discord.com/developers/topics/rate-limits) |
| MCP events | Streamable HTTP initialize, events/list, subscribe, unsubscribe; finite persisted subscriptions; exact filtered payload schema; Standard Webhooks signatures/challenge; no polling/streaming/replay claims. | [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events) |

## Explicit limits

- No interactions/slash-command endpoint, voice, attachments, edits, history backfill, sharding, or guild administration.
- One owner/process/bot instance. Permissions and Message Content intent must be configured independently in Discord.
- Restarts can lose Gateway events; subscription cursor is null. Callback acknowledgment only proves receipt, not that the dot replied.
- Live acceptance still requires private plugin registration, permitted public HTTPS hosting, actual callback verification, and a harmless message round trip in the chosen Discord channel.
