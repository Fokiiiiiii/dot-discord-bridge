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
