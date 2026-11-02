# Discord client features — v0.4.0

This is an extension of the local v0.3 OAuth/DM bridge, not the older GitHub main branch. See BASELINE.md. It does not add another model, Codex runtime, multi-owner access, or production deployment. The sections below describe the implemented feature groups and limits.

## Typing

A successful MCP Events callback acknowledgment starts one best-effort typing lease per owner source message. Discord's typing API is refreshed approximately every eight seconds per DM, not per source; shared REST Retry-After cooldown applies. The lease defaults to 120 seconds, hard maximum300, configurable with TYPING_TIMEOUT_SECS;0 disables it. Callback retries never extend or restart a lease. A callback ACK is not proof that dot processed the event.

Reply attempt, explicit discord_finish_response(message_id,outcome=no_response|failed), timeout, subscription stop/expiry, OAuth grant revocation, terminal callback failure, typing transport failure, and process restart stop renewal. A reply arriving before callback ACK suppresses later typing. Concurrent sources share the channel indicator; finishing one source does not stop another pending source. Discord has **no stop-typing API**: the UI may remain for up to about ten seconds after the last request, and an already in-flight renewal may finish. The bridge cannot detect a remote model failure unless dot calls the completion tool; the fixed timeout is the fallback. Persisted stop markers prevent retries from reviving it.

## Long logical replies

Use discord_reply with the original owner message_id and the entire text. Limits:32,000 UTF-16 units/logical response, at most32 parts, each at most2,000 UTF-16 units including synthetic fence wrappers. Discord documents2,000 characters but does not specify the Unicode unit; UTF-16 counting is a conservative implementation policy. Astral emoji count as2, Unicode scalar values are not cut; grapheme clusters (combining/ZWJ sequences) can cross boundaries.

Paragraph/newline/sentence/space boundaries are preferred in the latter half of a chunk. Original whitespace/content is preserved except inserted newline+closing/reopening code fences. Line-start backtick/tilde fences of3+ delimiters, up to3 leading spaces, preserve language/info tags. Inline backticks are not treated as block delimiters. Unmatched fences are safely closed perpart. Fence metadata over256 units and unsplittable pathological/blank-only output fail closed. This is not a full Markdown parser and makes no rich-embed/attachment guarantee.

All parts reference the same owner source, suppress mentions, and have distinct short nonces. SQLite commits the logical operation and each write intent before external writes, stores confirmed IDs after each response, and retains uncertain state across restart. Same logical send retry returns its recorded result without sending duplicates. A partial send can leave some parts visible; the rest are **not** blindly retried. Discord nonce deduplication is only supplementary and short-lived.

## Reply edits

discord_edit_reply accepts only the original message_id and replacement logical text. It never accepts a channel ID or outgoing target ID from the caller. The bridge revalidates the source owner/DM and resolves only its own persisted outgoing IDs. Existing parts are PATCHed, growth adds parts, and shrink removes known surplus parts. POST and PATCH always suppress allowed_mentions. Operations serialize within this single process.

Multipart edits are **not atomic on Discord**: earlier parts may be changed when a later request fails. Persisted pending/uncertain operations block further automatic send/edit attempts until operator inspection. Read discord_bridge_status outgoing_uncertain; do not delete journal rows or change the source ID to bypass protection. Repeating the last completed edit returns its recorded result. Retrying an original send after a later edit never restores old text. External manual deletion/editing can make local cached context stale; it is not automatically reconciled.

## Reply and recent context

Event data adds reply_to, recent_context, text_truncated, recent_context_truncated. Explicit unavailable/deleted/cached statuses distinguish references; no arbitrary reference REST fetch occurs. Only same-channel owner messages or confirmed bridge-owned outgoing IDs contribute text. Guild/group/other-user/forward snapshots are not imported. Context is untrusted data, never authorization or system instructions.

RECENT_CONTEXT_LIMIT defaults10 and caps20;0 disables recent history, not reply_to. Counts are physical messages/parts, not logical turns. Source text is bounded to16,000 UTF-16 units with explicit truncation. Each historical/reference text is bounded2,000 units; recent text combined16,000. Historical source timestamps use local receipt time; outgoing timestamps use last confirmed update, so editing changes its position. Seven-day retention applies; no account-wide/private dot chat history is consulted. Only successfully completed outgoing operations enter context; partial/uncertain output is excluded. Truncation flags warn when content/count budgets omit information.

## Validation and rollout boundary

Tests use synthetic data and mock Discord writes; localhost OAuth/MCP tests do not call Discord. Live typing appearance, multipart rendering, actual Discord rate limits/edits, ARM64 rebuild and existing-dot behavior require an approved deployment and owner test. Database changes are additive. Preserve the v0.3 backup before deploying; do not replace the newer local source with GitHub main. OAuth secrets and callback allowlists are unchanged by this feature work.

Official API references: [typing](https://docs.discord.com/developers/resources/channel#trigger-typing-indicator), [message create/edit/reference](https://docs.discord.com/developers/resources/message), [rate limits](https://docs.discord.com/developers/topics/rate-limits).

## Attachment awareness (metadata only)

After the owner and one-to-one DM are verified, newly queued `discord.dm.created` events may contain optional `attachments` and `attachments_truncated` fields when Discord supplies an attachments array. This includes attachment-only messages whose `text` is empty. Each of up to 10 entries contains `filename`, `media_type`, and `size_bytes` (any may be null if unavailable or invalid). Filenames are clipped to 255 UTF-16 units and control, line-separator, and potentially deceptive formatting characters are removed. Media types are restricted to a simple ASCII type/subtype of at most 128 bytes; sizes are nonnegative integers representable safely in JSON. `attachments_truncated` is true if entries were omitted or any metadata was clipped, stripped, or invalid. An absent field means unknown, not necessarily no attachments. Empty arrays mean none were reported. Existing queued events remain valid without these fields.

All metadata is **untrusted input**, not instructions; the MIME type is a claim, not content verification. The bridge does not include attachment IDs, URLs, thumbnails or file bytes, download content, or grant the assistant access to attachments. Metadata is present only in the bounded queued event and is not copied to the source-message history. It is subject to the existing callback and queue delivery policies; it must not be logged. The user must provide accessible content through another approved route if analysis of the file itself is needed.

## Recovery diagnostics and failed inbox retry

`discord_bridge_diagnostics` returns bounded, content-free lists (maximum 50 each, with truncation flags) of retained failed inbox lookups, pending callback deliveries, and incomplete/uncertain outgoing jobs. Inbox and outgoing records use the observed source message ID; each pending callback has a stable derived delivery ID. Reasons are coarse categories. No message text, callback URL, credential, content hash or attachment data is returned. Terminal callback failures are still dropped under the existing policy, and therefore **cannot be listed or retried** with this tool. A pending callback is not proof of delivery or processing. The diagnostics are not a connectivity or end-to-end health check.

Only upon an explicit owner instruction, `discord_retry_failed_inbox(message_id)` atomically requeues a previously staged owner inbox record that is in the `failed` state, no more than seven days old, and not already ingested. A pending, rejected, completed, other-owner, older, or arbitrary ID is refused. The existing worker then repeats DM recipient and message identity checks and its bounded lookup policy; it selects currently active matching subscriptions when hydration succeeds. This may deliver an earlier message to a newer active subscription. A revoked or expired grant is not revived; normal delivery-time grant checks continue. An inaccessible or deleted Discord message cannot be recovered. The operation does not guarantee delivery or restore events never staged.

The retry does **not** reset or send an incomplete/uncertain outgoing operation, retry callback dead letters, or change deduplication. Inspect Discord before any operator action on uncertain writes. The tool is authenticated like other MCP tools, but explicit owner intent is a behavioral requirement for the calling assistant, not a second server-side approval check.

## Discord presence (bridge state only)

The Gateway advertises a static, content-free presence. On a new Identify it starts as `Bridge starting`; after Discord's READY/RESUMED, it samples local SQLite state:

- `Bridge connected` (online): the Gateway session is active and neither a pending inbox item nor queued callback nor retained failed inbox item is found. This is **not** an end-to-end health guarantee.
- `Bridge work queued` (idle): at least one inbox item is pending or callback is queued, including retry delays. It does not claim that dot is thinking.
- `Inbox needs attention` (do not disturb): at least one inbox item has exhausted retries and is retained as failed; this takes precedence over queued work.
- `Bridge status unknown` (do not disturb): the state query fails.

Updates are latest-state coalesced, at most once every 20 seconds across Gateway reconnects within a process; short-lived states may never appear and an older label may remain until the next update. A new session is refreshed after READY, subject to the same interval. While disconnected the bridge cannot send a reconnect status; Discord controls its visible availability and the last status can be stale. If the process exits, it cannot advertise its failure. The label does not capture every error, callback exhaustion, model activity, subscription health, or delivery outcome. It never contains message content, IDs, tokens, or error details. Discord client rendering and live Gateway behavior remain unverified.

Gateway protocol reference: https://docs.discord.com/developers/events/gateway-events#update-presence

Notification write uncertainty is tracked separately; inspect `notifications_pending` from `discord_bridge_status` and follow [notification safety guidance](NOTIFICATIONS.md). Recovery tools do not reset, resend, or list notification writes.
