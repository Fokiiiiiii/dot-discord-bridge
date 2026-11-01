# Rust版 Discord ⇄ dot 接続

## 作成済み

- Discordの許可チャンネル・許可ユーザーの新着メッセージを受信
- MCP Events の署名付き webhook で既存の dot へ配送
- dot が `discord_reply` で元メッセージに返信
- SQLite 永続化・再送・二重返信防止・送信結果不明時の停止
- Rust のソース、単体テスト、Cargo.lock、プラグインテンプレート

別のAIモデル、OpenAI APIキー、Codex実行環境は運用に不要です。現状は開発・ローカル検証段階で、本番接続済みではありません。

## 次に決めるもの

1. 常時起動できる設置先（VPS等）と公開HTTPSドメイン
2. 許可するDiscordチャンネルID・ユーザーID
3. Discord Bot Token（**通常ユーザーのTokenではありません**）
4. MCP接続用の新しいランダムなBearer secret
5. 実際の購読で使われるChatGPT側callback hostname（確認後に限定許可）

秘密情報は設置先の `.env` / secret設定へ。チャット貼り付け・ZIP同梱は不要です。`.env.example` は雛形です。アプリ自身は `.env` を読み込まないため、ホストの環境変数機能で渡してください。

## 起動

Rust 1.99以上、Cコンパイラ（同梱SQLiteビルド用）が必要です。

```sh
cargo test --locked
cargo build --release --locked
umask 077
./target/release/discord-dot-bridge
```

localhost:8787 にのみ待受します。HTTPSリバースプロキシの設定と秘密情報の投入が別途必要です。外部への公開・Bot招待・プラグイン登録・自動返信開始は、対象を確認してから行ってください。

`plugin-template/mcp.json` のURLを実際の公開URLに差し替え、非公開プラグインとして登録し、接続画面でBearer認証を設定します。既存のdotに「このチャンネルの自分のメッセージを監視し、許可した範囲で返信」と依頼して購読します。

## 制限

テキストのみ、1人の所有者・1プロセス・1シャード向け。返信は1件につき1回・2000文字以内。添付ファイル取得やサーバー管理機能はありません。プロセス停止中に発生したメッセージの完全復元は保証しません。実機では「受信→dot起動→Discord返信」の往復を必ず確認してください。

セキュリティ設定と詳細手順は README.md を参照してください。
