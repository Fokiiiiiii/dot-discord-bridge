# Integration report — 2026-11-02

Base: `discord-dot-bridge-owner-notifications-source.zip`, SHA-256 `7231ad5a21719d04dc87a7cbe3fb5d725141dff58596699f42ac148ce9cbf561`.

Merged: attachment metadata, recovery diagnostics and failed-inbox retry, and Gateway presence. The owner-notification code remains present. Overlapping `src/main.rs` module declarations and tools/ingest flow were combined; conflicting README, FEATURES and VALIDATION additions were preserved. Plugin guidance was expanded for untrusted attachment metadata and explicit-owner-only recovery. Source tests now include cross-feature assertions; these have not been executed.

Static checks confirmed module declarations, tool routing, attachment augmentation after owner/DM checks, and Gateway presence wiring. Notification implementation, OAuth, outbound journal, webhook, typing, context and dependency files remain byte-identical to the notification base. This is not a security audit or proof of behavior. SQLite projection queries were separately exercised against synthetic data.

**Not run:** Rust compile, tests, formatter, Clippy, release build, real Discord/API integration, or deployment. Rust tooling was unavailable. The integration is not deployment-ready until those checks pass in the target build environment. Previous baseline validation entries are historical, not evidence for this merged version.

README clarification: explicitly authorized proactive notices to the previously observed and freshly verified owner DM are supported; unauthorized notices and creation of new or arbitrary DM destinations are not. No code changed for this clarification.
