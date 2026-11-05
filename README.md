# dot-discord-bridge

Discord Bot の 1対1 DM（および任意で許可したサーバーチャンネル）を、署名付き **MCP Events** と **OAuth 2.1 (S256 PKCE)** で既存の AI エージェント（Dot / ChatGPT MCP クライアント）へ安全に接続する Rust 製軽量ブリッジです。

- **単一バイナリ・省リソース**: Rust + 同梱 SQLite (WAL) + Rustls で動作し、Raspberry Pi (ARM64) 本番環境でメモリ使用量 **約 9.6 MiB**・アイドル CPU **0.0%**。
- **厳格な境界防御**: 送信者検証・DM 宛先検証・リクエスト単位の DNS ピニング（SSRF 防止）・送信前ジャーナルによる冪等保証・秘密情報を含まない閉じた診断カテゴリを備えています。

---

## 機能・MCP ツール一覧

### イベント (`events/subscribe`)

| イベント名 | 説明 |
|---|---|
| `discord.dm.created` | 許可ユーザーからの DM（または `DISCORD_GUILD_ENABLED=true` 時のサーバーメッセージ）を受信した際に署名付き Webhook で通知。直近会話コンテキスト・返信元・添付メタデータを含む。 |

### ツール (`tools/call`)

| ツール名 | 用途 |
|---|---|
| `discord_reply` | 受信した `message_id` に対して返信（最大 32,000 UTF-16 単位。コードブロックを維持したまま 2,000 単位以下へ自動分割）。 |
| `discord_edit_reply` | 送信済みの論理返信を元の `message_id` 指定で編集（分割パートの増減も自動調整）。 |
| `discord_finish_response` | 返信不要（`no_response`）または生成失敗（`failed`）時にタイピング表示リースを即座に終了。 |
| `discord_react` | 受信メッセージへのリアクション絵文字の追加（`add`）・削除（`remove`）。 |
| `discord_send_file` | 受信メッセージへ Base64 ファイル（最大 20 MiB）を冪等キー付きで添付返信。 |
| `discord_read_attachment` | 受信メッセージの添付ファイル（最大 20 MiB）を Discord 公式 CDN から検証・取得。 |
| `discord_notify_owner` | オーナーの 1対1 DM へ能動通知を送信（`idempotency_key` による重複防止、`mention_owner` 対応）。 |
| `discord_bridge_status` | 本文を含まない受信・送信キュー件数、通知先 DM 状態、直近のツールエラー概要を取得。 |
| `discord_bridge_diagnostics` | 失敗した受信 lookup、保留中コールバック、不確定書き込み、直近 10 件のツール失敗分類（`tool` / `stage` / `reason` / `at`）を取得。 |
| `discord_retry_failed_inbox` | 一時障害で `failed` になった受信メッセージの再取得を明示的に再試行。 |

---

## クイックスタート（セットアップ手順）

### 1. 事前準備

1. **Discord Bot の作成**: Discord Developer Portal で Bot を作成し、Bot Token を取得します（オーナーが Bot と 1対1 DM を開ける状態にしてください）。
2. **秘密鍵の生成**: OAuth クライアント用とオーナー同意画面用に、独立した 32 バイト以上のランダム文字列を 2 つ生成します。
   ```sh
   openssl rand -hex 32
   openssl rand -hex 32
   ```

### 2. 環境変数ファイル (`deploy/.env`) の作成

`.env.example` を `deploy/.env` にコピーし、権限を `600` に設定して値を記入します。

```sh
cp .env.example deploy/.env
chmod 600 deploy/.env
```

主な必須設定：

| 変数名 | 内容 |
|---|---|
| `DISCORD_BOT_TOKEN` | Discord Bot トークン |
| `DISCORD_OWNER_USER_ID` | オーナーの Discord ユーザー ID（17〜20桁の数値 1件） |
| `OAUTH_ISSUER` | ブリッジの公開 HTTPS ベース URL（例: `https://discord-mcp.example.com`） |
| `OAUTH_CLIENT_ID` | 任意のクライアント識別子（例: `discord-dot-owner`） |
| `OAUTH_CLIENT_SECRET` | クライアント秘密鍵（32文字以上） |
| `OAUTH_OWNER_APPROVAL_SECRET` | ブラウザ同意画面に入力するオーナー承認鍵（32文字以上・上記と別値） |
| `OAUTH_REDIRECT_URIS` | クライアント画面に表示される正確な Redirect URI |
| `MCP_ALLOWED_HOSTS` | ブリッジの公開ホスト名（例: `discord-mcp.example.com`） |
| `CALLBACK_ALLOWED_HOSTS` | MCP Events 配信先として許可するコールバックホスト名 |

オプション設定：

| 変数名 | デフォルト | 内容 |
|---|---|---|
| `DISCORD_GUILD_ENABLED` | `false` | `true` にするとサーバーチャンネルでの受信・返信を許可（Bot に Message Content Intent が必要） |
| `DISCORD_RESPONDERS_FILE` | 未設定 | 追加で反応を許可するユーザー ID リスト JSON（`deploy/responders.example.json` 参照。再起動なしで即時反映） |
| `TYPING_TIMEOUT_SECS` | `120` | タイピング表示の最大維持秒数（0〜300） |
| `RECENT_CONTEXT_LIMIT` | `10` | イベントに含める同一 DM 直近メッセージ数（0〜20） |

### 3. コンテナまたはバイナリの起動

**Docker Compose（推奨）**:

```sh
cd deploy
docker compose up -d --build
docker compose exec discord-dm /usr/local/bin/discord-dot-bridge --healthcheck
```

**ソースから直接ビルド・起動する場合**:

```sh
cargo test --locked
cargo build --release --locked
umask 077
./target/release/discord-dot-bridge
```

### 4. HTTPS リバースプロキシの公開パス

ブリッジは `127.0.0.1:8787` のみで待ち受けます。Cloudflare Tunnel や Nginx 等の HTTPS リバースプロキシから、`Host` と `Authorization` ヘッダを保持して以下のパスのみを転送してください（`/healthz` は外部公開しないでください）：

- `/mcp`
- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`
- `/oauth/authorize`
- `/oauth/token`
- `/oauth/revoke`

### 5. クライアント接続と動作確認

1. `plugin-template/mcp.json` の URL を公開ホスト名に合わせてクライアントへ登録し、`OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` を入力します。
2. ブラウザ同意画面で `OAUTH_OWNER_APPROVAL_SECRET` を入力して承認します。
3. エージェント側で `discord.dm.created` を購読し、Bot へ DM を送信して返信・通知（`discord_notify_owner`）が動作することを確認します。

---

## 運用・トラブルシューティング

問題が発生した際は、`discord_bridge_status` または `discord_bridge_diagnostics` を呼び出すことで、秘密情報や会話本文を一切露出せずに原因を特定できます。

- `notification_destination_status`:
  - `ready`: オーナーの 1対1 DM チャンネルが 1 件に確定しており、`discord_notify_owner` が送信可能。
  - `missing_owner_dm`: まだオーナーからの DM が観測されていない（先にオーナーから Bot へ 1 通 DM を送ると解決）。
  - `ambiguous_multiple_dm_channels`: 複数の DM チャンネル候補が存在し安全のため停止中。
- `last_tool_failure` / `recent_tool_failures`:
  - 直近のツールエラーが発生段階（`stage`: `validation`, `destination`, `idempotency`, `discord_lookup`, `transport_or_confirm` 等）と理由（`reason`: `invalid_idempotency_key`, `missing_owner_dm_destination`, `key_or_pending_conflict`, `discord_rate_limited` 等）で即座に判別できます。

---

## ベンチマーク (v0.5.0)

`cargo test --release --locked -- --nocapture benchmark_core_paths` による実測値および Raspberry Pi (ARM64) 本番稼働時のリソース指標：

| 計測項目 | レイテンシ (1回あたり) | スループット |
|---|---|---|
| 短文メッセージ分割 (`splitter::split`, 1パート) | **0.79 µs** | ~1,265,000 ops/s |
| 長文 Markdown + コードフェンス分割 (15,000文字 → 8パート) | **190.21 µs** | ~5,250 ops/s |
| メッセージ受信 + 文脈構築 (`stage_raw` + 500件履歴検索 + outbox) | **138.66 µs** | ~7,210 msgs/s |
| OAuth 2.1 Bearer 検証 + Grant Family 有効性確認 | **11.33 µs** | ~88,200 checks/s |
| 定期 Prune (`typing::prune` + `outgoing::prune`, 250件リース) | **6.18 µs** | ~161,800 ops/s |
| 診断 RPC 往復 (`discord_bridge_status` + `discord_bridge_diagnostics`) | **232.77 µs** | ~4,295 pairs/s |

| リソース指標 (Raspberry Pi ARM64 本番コンテナ `deploy-discord-dm-1`) | 実測値 |
|---|---|
| リリースバイナリサイズ (`discord-dot-bridge`) | **9.2 MiB** |
| 常駐メモリ使用量 (RSS) | **9.6 MiB** (`9,840 KB`) |
| アイドル時 CPU 使用率 | **0.0% 〜 0.05%** |
