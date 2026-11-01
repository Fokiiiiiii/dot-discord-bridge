# Private owner OAuth setup (not yet deployed)

This implements a single preconfigured confidential OAuth client for this bridge, not a general identity provider. **It authorizes possession of the separate owner approval secret plus explicit browser consent. It does not attest a particular dot's internal identity.** Only initiate and approve the intended private ChatGPT connection; do not share its client secret or owner approval secret. No public registration, password accounts, CIMD fetching, or DCR endpoint is provided.

## Configuration and secret onboarding

`MCP_AUTH_MODE=oauth` is the default. Configure `OAUTH_ISSUER=https://discord-mcp.foki.sh`, an explicit `OAUTH_CLIENT_ID` such as `discord-dot-owner`, separate high-entropy random `OAUTH_CLIENT_SECRET` and `OAUTH_OWNER_APPROVAL_SECRET` (each generated from at least 32 cryptographically random bytes, e.g. 64 hex characters; the parser enforces a 32-character minimum, not entropy), and `OAUTH_REDIRECT_URIS` containing only the exact HTTPS redirect displayed by ChatGPT connection management. Never reuse the Discord Bot token. Secret generation, transfer, and deployment are separate approved operations; this repository contains placeholders only.

In ChatGPT **Plugins → + → Add custom MCP server**, use `https://discord-mcp.foki.sh/mcp`, choose OAuth with a predefined client, and enter the client ID and client secret in its secure setup fields. Prefer `client_secret_basic`; `client_secret_post` is also supported. The issuer advertises RFC 9207 and includes `iss` in successful authorization redirects. ChatGPT may consequently show `https://chatgpt.com/connector_platform_oauth_redirect`; **copy what the management page actually shows**, do not infer or wildcard it. Redirect configuration is distinct from `CALLBACK_ALLOWED_HOSTS` for MCP Events.

The owner approval secret belongs **only in the password field on the bridge's HTTPS consent page**, after verifying the hostname and initiating the intended connection. It is not the OAuth client secret and is not entered in ChatGPT's client-secret field. Closing the consent page denies approval. The form has a one-use cookie-bound nonce, same-origin POST check, five-minute lifetime, no external assets, no referrer, no-store responses, and frame blocking. Concurrent authorization tabs overwrite the single browser cookie; restart the intended flow if that happens.

Do not embed any secret in `mcp.json`, URLs, CLI arguments, chat, screenshots, or logs. A manifest declaration alone does not save credentials or complete consent. The included template describes the predefined OAuth client; replace its placeholders only after verifying the actual connection.

## Exact public routes

Forward only these paths to `http://127.0.0.1:8787`, preserving the original public Host and Authorization header:

- `/mcp`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/oauth/authorize` (GET and same-origin form POST)
- `/oauth/token` (POST)
- `/oauth/revoke` (POST)

Set `MCP_ALLOWED_HOSTS=discord-mcp.foki.sh`. Do not expose `/healthz`, port 8787, or other paths. Updating the prior `/mcp`-only Cloudflare Tunnel ingress is a separately approved network configuration change. Configure proxy rate limits without CAPTCHA/interactive Access challenges on machine discovery/token/MCP routes. Never record Authorization, Cookie, form/request bodies, authorization query strings, or response Location headers (contain codes/state). Do not broadly disable existing WAF/Access policies.

## Protocol and revocation

Protected-resource metadata advertises `https://discord-mcp.foki.sh/mcp` as the **exact resource**, with scope `discord:dm`. Authorization and token requests must carry that resource. S256 PKCE is mandatory; plain PKCE and wildcard redirects are rejected. Authorization codes last two minutes, are one-use, and bind redirect/resource/client/challenge. Replay of a consumed code revokes its issued grant family. Access tokens last 15 minutes. Refresh tokens rotate and last 30 days from issue; reuse revokes the entire grant family, including access tokens and event authorization. Token hashes are stored in SQLite, never plaintext tokens. Successful refresh extends the renewable grant; there is no absolute maximum session lifetime.

`POST /oauth/revoke` accepts form field `token` and authenticated client credentials, and revokes its entire grant family. Unknown tokens return success. Reauthorize after revocation. Changing issuer/client credentials/owner approval secret/redirect allowlist invalidates old grants. Preserve the private database across restart; do not delete it to implement revocation. Consumed-code hashes, used refresh-token tombstones and revoked-family records are retained for replay detection; plan private disk maintenance instead of deleting them casually.

Each subscription is persisted with its authorization grant family. Revocation stops subsequent deliveries for that family even if another grant exists; unbound legacy subscriptions fail closed in OAuth mode until explicitly resubscribed. A network request already sent before revocation may complete. Single-owner tools can manage the owner's subscriptions; this is not a multi-user service. Token checks occur before MCP processing; already-started operations may finish.

The consent endpoint caps retained failed-attempt bookkeeping at ten/hour, but a correct owner secret is accepted even after that budget is exhausted. The key comparison happens first: this is **not** protection for a human password; a cryptographically random 256-bit approval key is required. The public 100-pending-request cap can still be exhausted for up to five minutes, temporarily denying new setup. Per-source proxy rate limiting and operational monitoring remain necessary. Approval-secret rotation invalidates grants, but does not automatically re-establish dot subscriptions.

`MCP_AUTH_MODE=bearer` explicitly selects the old manual-diagnostics-only mode and requires `MCP_BEARER_TOKEN`; OAuth and static Bearer are never accepted together. Do not switch a running OAuth deployment to bypass revocation.

## Verification before declaring success

1. Offline tests, lint, release build, independent security review.
2. Approved ARM64 build, persistent private storage, exact HTTPS route configuration.
3. No-auth `/mcp` returns 401 with protected-resource metadata challenge; discovery returns expected issuer/resource/PKCE/client methods.
4. Live predefined-client connection, owner approval, token exchange and refresh; verify no sensitive request data in proxy/application logs.
5. Resolve actual MCP Events callback hostname through trusted diagnostics, allow exactly it, and verify signed challenge.
6. Owner DM → this existing dot → one reply in the same DM; unauthorized sender rejection, revoke, restart and resubscribe tests.

Local tests do not prove the current ChatGPT UI or real callback/token behavior until the live flow succeeds. No additional model/API key or Codex runtime is introduced.

Official references: [OpenAI authentication](https://developers.openai.com/plugins/build/auth), [private connection flow](https://developers.openai.com/plugins/deploy/connect-chatgpt), [manifest authentication](https://developers.openai.com/plugins/build/plugins).
