# Discord client features — v0.4.0

This is an extension of the local v0.3 OAuth/DM bridge, not the older GitHub main branch. See BASELINE.md. It does not add another model, Codex runtime, multi-owner access, or production deployment. Only the five described feature groups are implemented.

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
