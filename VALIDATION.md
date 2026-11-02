# Validation record

Date: 2026-11-01

- Official Rust stable 1.99.1 installed with user authorization into isolated workspace paths. No existing shell profile changed.
- Dependencies fetched by Cargo; exact versions recorded in Cargo.lock.
- Rust unit tests: 43 cases passed (offline; test secrets are synthetic).
- `cargo fmt` applied.
- `cargo clippy --locked -- -D warnings`: passed, no warnings.
- `cargo build --release --locked`: passed; Linux x86_64 binary built.
- Public endpoint, live Discord Gateway, real callback challenge, plugin discovery, and existing-dot-to-Discord round trip: NOT TESTED; requires approved hosting/credentials/integration.
- No real tokens read, no bot created or invited, no plugin uploaded, no external service changed.

The initial Python proof-of-concept is not included in this Rust deliverable. Its results are not counted as Rust verification.

## DM-only v0.2.0

Owner-only recipient/author checks, group/guild/bot rejection, DM-only intent, cache expiry/restart, legacy DB rejection and owner pinning tested. Independent review found no critical authorization bypass. The earlier drop-on-lookup-failure behavior was replaced by a durable metadata-only inbox: transient failures retry, permanent rejection and exhausted failures remain distinguishable, and DB errors propagate. No real Discord credentials or external state changes used.

## Deployment preparation (not deployment)

- Debian 12 ARM64 Dockerfile uses official Rust 1.99.1 Bookworm build image and Debian Bookworm runtime, non-root UID10001, private persistent named volume, host-loopback-only listener.
- Compose YAML parsed and required isolation/persistence fields checked locally.
- localhost health route tested as part of the real HTTP lifecycle test; it verifies process/SQLite, not Discord connectivity.
- Docker/ARM64 image build and runtime NOT TESTED: this development executor is x86_64 and has no Docker command. No files copied to the user server and no server state changed.

## Durable DM ingestion

Gateway sequence advances only after synchronous SQLite metadata commit. Offline tests cover failure-before-sequence, metadata-only staging/dedup, pending state across restart, transient vs permanent vs exhausted failures, verified idempotent completion, DB-error propagation, safe status counts, and Retry-After bounds. No message content is retained before recipient verification.

## OAuth v0.3.0 (2026-11-01)

- 57 offline Rust tests PASS; fmt check and all-target Clippy with warnings denied PASS; release x86_64 build PASS.
- New tests cover PKCE/redirect/resource/state/issuer binding, cookie+Origin consent, wrong-secret denial, rotation/replay/revocation, persistent hashed tokens, config-change invalidation, OAuth/static-Bearer separation, grant-specific callback cancellation and legacy subscription fail-closed.
- Real localhost HTTP test exercises discovery → consent form → code exchange → refresh → authenticated MCP → revocation → 401, with synthetic test-only credentials. It does not exercise browser CSP enforcement or public TLS.
- Independent source review addressed grant binding, CSP redirect compatibility, Basic challenges, bound denial redirects, replay family invalidation, and owner login despite exhausted failed-attempt budget.
- Live ChatGPT OAuth, public TLS/Cloudflare ingress, actual Events callback and Discord round trip remain NOT VERIFIED for this OAuth change. No production secrets generated, no deployment or push performed by this implementation task.
- Public pending-authorization capacity remains a temporary availability risk; use approved per-source edge rate limiting. See OAUTH.md for remaining conditions.

## Discord client feature extension v0.4.0 (2026-11-01)

- Final integrated suite: **94/94 offline tests PASS**. `cargo fmt --check`, all-target Clippy with warnings denied, and locked offline release build PASS (Linux x86_64).
- Baseline preserved: original local v0.3 had57 tests; GitHub main was older v0.1 channel-mode source. See BASELINE.md. OAuth/Gateway/webhook source hashes remain identical; Cargo.lock dependency graph unchanged (only root package version changed).
- Coverage added: Unicode/fence splitting and whitespace, mocked multipart writes/growth/shrink/partial failures, per-write journal and real DB reopen quarantine, source-bound legacy ownership migration, 429/known-deleted response handling, context owner/channel/retention/bounds, typing ACK/retry/completion/timeout/restart/owner/OAuth revocation and channel interval.
- HTTP regression verifies32,000 Japanese characters fit bounded256KiB MCP requests and excess still413. Additive payload schema keeps old queued four-field events valid.
- Independent read-only review found and resolved HTTP byte-limit/long-Unicode incompatibility and old-queue schema compatibility. Restart journal regression also caught a missing intent insert before it was fixed. Final candidate has no unresolved blocking review finding under documented assumptions.
- No live Discord requests, credential access, production changes, deployment or GitHub push. Actual typing UI, multipart Markdown rendering, live edits, ARM64 rebuild, and real dot behavior remain deployment-time verification.

## Consent denial diagnostics (2026-11-01)

- OAuth targeted tests14/14 and full offline suite97/97 PASS; all-target Clippy with warnings denied PASS.
- Added static-only first-failure categories for consent JSON403. Tests cover all seven categories, missing Origin/cookie, DB read/write failure and rollback, exact unchanged generic response/no-store behavior. Existing success, wrong-secret303 denial, CSRF, PKCE and revocation tests remain passing.
- No credential/header/request values or raw errors enter the diagnostic emitter. No deployment, credential inspection or security setting change performed. Actual live403 cause remains unconfirmed until approved deployment reports a category.

## Consent GET referrer policy fix (2026-11-01)

- Targeted OAuth tests16/16; full offline suite99/99; Clippy all-targets warnings denied PASS.
- Only consent GET HTML gets strict-origin. Regression asserts metadata/resource/error/303 responses retain no-referrer; missing/null/hostile Origin still rejects without issuing a code. Existing exact Host/cookie/secret and diagnostic tests continue passing.
- Fetch/Referrer Policy standards verified: native non-CORS POST under no-referrer serializes Origin as null; strict-origin sends at most origin, never the authorization URL path/query.
- Native browser fixture attempted with synthetic non-secret form only, but cloud browser could not connect to executor loopback (ERR_CONNECTION_REFUSED). Fixture was stopped; no external exposure or workaround used. Therefore native-browser behavior and no-query-leak observation remain NOT empirically verified in this task; server header regression and normative standard support the change.
- No deployment, credential access or security-setting modification.

## Subscription diagnostics (2026-11-01)

- Fixed-category stderr markers only: `events_subscribe category=received`, optional `verification_started`, then `accepted` or first failing stage. No URL, hostname, signing secret, authorization value, identifiers, payload or raw error is emitted.
- Rejections classify grant, event, arguments, owner, delivery, callback_policy (URL/HTTPS/exact allowlist), secret, cursor, ttl, verification_transport, verification_timeout, verification_dns, verification_destination (non-public DNS), verification_response (body/JSON), verification_status (non-2xx), verification_challenge, database.
- `received` proves entry into the authenticated, routed subscribe handler. Its absence does NOT prove no network request arrived: HTTP Host/auth/body/envelope validation or a notification without ID may stop before this marker. `verification_started` means verification was attempted, not necessarily that DNS/TLS or callback HTTP succeeded. A cached verification may go directly from received to accepted. Categories are not request-correlated; concurrent entries can interleave.
- Regression tests drive invalid event/owner/arguments/delivery/URL/secret/cursor/TTL, unchanged DB failure, cached success, fixed transport classification, non-2xx/malformed response/wrong or missing challenge and valid challenge. No real callback or Discord requests used. Existing security decisions and public responses unchanged.
- Verification: full offline suite102/102 PASS; cargo fmt --check, all-target Clippy with warnings denied, and release build PASS. No deployment, credential access or production DB inspection.

## Callback policy hostname diagnostic (2026-11-02; NOT built here)

- Restored exact reviewed baseline archive SHA256 `8b743e26a1194773301fa9add30be458fa251fac3e199a226c3f0a06575581b6` into an isolated directory. Historical test results above describe that earlier environment, not this new patch.
- On an events/subscribe callback-policy rejection only, an additional line may expose `events_subscribe callback_policy_denied_hostname=<normalized DNS hostname>`. This deliberately supersedes the prior no-hostname diagnostic policy for this one authorized troubleshooting case. All other diagnostics remain fixed categories.
- Value is URL-parser normalized, ASCII DNS-label validated and capped at 253 bytes. HTTPS/default443/no userinfo/no fragment are required. Raw URL/path/query, credentials, IP literals, headers, signing secrets, message data and IDs are never emitted. Invalid URL shapes produce no hostname line. Existing allowlist rejection and public response remain unchanged; no DNS request occurs in this helper.
- Two additional Rust tests cover normalized case/IDNA, excluded path/query, trailing-dot handling, unchanged actual allowlist, credentials/fragments/ports, IP representations, control/backslash/encoded-newline injection, invalid DNS labels and length bounds.
- Current environment has no cargo, rustc or rustfmt. New tests, full suite, fmt, Clippy and build are UNVERIFIED; no toolchain installation attempted. Source-only artifact must be built/tested before deployment. No deployment, secrets, production DB or configuration access.
- Independent read-only review: no blocking privacy, injection, allowlist or error-propagation finding. Review is source-level only, not an executed build/test result.

## Verification phase diagnostics (2026-11-02; NOT built here)

- Verification callbacks only emit fixed lines `callback_verification phase=dns_start|dns_success|request_start|headers_received|body_complete` and, on timeout, `callback_verification timeout_phase=dns|request|body`. Each actual line contains exactly one listed value. No URL/host/IP/secret/body/headers/IDs or raw error can enter these markers. Ordinary event deliveries emit none of these lines.
- DNS success means lookup completed, before the existing public-IP validation; it does not assert the destination is allowed. Request phase includes connect/TLS/request upload/wait for headers and cannot distinguish these internally or prove IPv6 is responsible. Headers received does not mean 2xx or accepted challenge. Body complete means a successful-status bounded body finished reading, before JSON/challenge validation. Non-2xx bodies remain intentionally unread. Concurrent requests can interleave markers.
- Existing timeout limits, public errors, DNS pinning, IP/URL allowlists, proxy/redirect/TLS settings, signatures and response-body bounds are unchanged.
- Added static-vocabulary/verification-only test and synthetic local HTTP mock that returns 200 headers then stalls, requiring body timeout to preserve `callback_timeout`. Existing localhost tests cover response bounds/permanent status handling. This does not constitute full outbound HTTPS challenge E2E coverage; existing MCP lifecycle test caches verification. No SSRF bypass introduced for testing.
- cargo/rustc/rustfmt remain absent: new/full tests, fmt, Clippy and build UNVERIFIED in this environment. Run in the Mac build environment before any deployment. No deployment, production requests, credentials or configuration access.
- Independent source review reports no blocking findings; phase positions and retained guards/errors inspected. Test does not capture stderr; the logging emitter accepts only static enum text.

## Proactive owner notification extension (2026-11-02; NOT built here)

- New authenticated `discord_notify_owner` tool with fixed configured owner, no destination arguments, explicit importance/owner-mention control and a single-message 2000 UTF-16-unit cap including the automatic owner tag. Existing reply/edit/event/security behavior retained.
- Notification journals persist hash-only intent before POST; completed identical requests return recorded result, changed-key content conflicts reject, pending/uncertain writes never blindly replay. Content-free status adds notifications_pending/done counts.
- Durable owner/channel-ID registry is populated only by validated owner-DM ingestion or a newly verified migration candidate. It survives message retention and restart. Multiple distinct candidates fail closed. Every new notification fetches a fresh channel descriptor without using the normal cached recipient check (explicit synthetic fixtures are compiled only in tests). Stored notification text is not retained.
- Added ten module tests plus three integration tests: mention controls, Unicode and owner-tag length boundaries, arbitrary-destination rejection, payload conflicts, invalid returned IDs, pre-write persistence, disk restart/quarantine, registry retention and ambiguity, owner-only ingestion/registry retention, tool schema/routing and status counts. Expected source test count119; this is NOT an execution result.
- No Rust toolchain in this environment. New/full tests, fmt, Clippy and release build remain UNVERIFIED. Run cargo fmt, cargo test --locked --offline, cargo clippy --all-targets --locked --offline -- -D warnings and cargo build --release --locked --offline in the Mac build environment before deployment. No live Discord, credentials, production configuration or deployment accessed.
- Registry upgrade seeds existing owner message channel IDs at startup before cleanup; regression closes/reopens DB then deletes message rows. A transaction rechecks the unique destination after fresh verification before recording intent, rejecting concurrent ambiguity or replacement.
- Independent source review: no outstanding blocking findings after startup-migration and post-verification ambiguity fixes. This is not a build or test-execution claim.

## Presence extension (2026-11-02)


- Added offline unit cases for static payloads, coalescing/rate spacing, multi-item queue semantics, failure precedence, and database-query failure; these tests were **not run** in this workspace because a Rust toolchain was not available on PATH or found in the workspace.
- `cargo test --locked`, `cargo fmt --check`, Clippy and release build: **not run** for this extension. Earlier validation entries do not validate the changed source.
- SQLite state-projection queries passed against a synthetic in-memory database; patch dry-run and archive integrity check passed.
- Discord presence rendering, reconnection behavior, rate limits and live integration: **not tested**. No credentials or production state used.

## Integrated source validation (2026-11-02)

- Merged notification, attachment metadata, recovery, and presence changes into the verified notification source archive. Conflicting module declarations and documentation were manually combined; existing Gateway, DM authorization, outgoing journal and notification controls were preserved in the source.
- Added unexecuted cross-feature assertions for tool discovery, attachment metadata plus owner-DM notification destination, and recovery driving presence state. Patch and archive integrity checks and static integration checks do not replace compilation or end-to-end tests. Rust toolchain unavailable: no integrated tests, formatting, Clippy, or release build were run. No live Discord or deployment was performed.
