# Feature extension baseline — 2026-11-01

Authoritative starting point: local Rust v0.3.0, 57/57 offline tests pass.
GitHub `Fokiiiiiii/dot-discord-bridge` main inspected read-only: Cargo.toml v0.1.0 (blob ba4b01ef2124f567361d7c3903b318a5c1d63c56), src/main.rs blob fb9192d8ebe7f4d42c17b58addce7a3d72d5b7ae, old channel-mode discord.message.created and no OAuth module.
Local is newer and must not be overwritten with main. Preserve owner-only DMs, OAuth, durable metadata inbox, REST cooldown, callback signatures, SSRF checks and uncertain-write quarantine.

Initial local SHA256:
- main.rs ebe2d3e32d4cca6f848c8d8211ad933f1a0bef69b0923bc25ca6ccdfa2137322
- oauth.rs b06a20f6e32479b5bba46c8a2196876a6046b5cda64ad72b8d5d422ca578cbe4
- gateway.rs 5affa787e8abe9a81d73d6fd26672e525e1e5143be24f66e30b179d127e17fee
- webhook.rs 1cb343bbf1159a757abeb8ebb165edf35d0385e7a44a9c5b9b4cf22f393da08f

Only five user-described features are in scope: bounded typing, long-reply splitting, bridge-owned reply edits, reply context, recent context. No production changes, credential access, or GitHub push in this task.
