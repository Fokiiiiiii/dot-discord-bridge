# DiscordのDM専用版（Rust）

**自分とBotの1対1 DMだけ**をこのdotへつなぎます。サーバーチャンネルやグループDMは監視しません。

## 動き

1. 自分がDiscord BotへDMする。
2. Rustサービスが送信者のowner user IDと、DMのtype=1・recipientが自分だけであることを公式APIで確認。
3. `discord.dm.created` を署名付きMCP Eventsでこのdotへ送る。
4. 購読時に許可した方針でdotが考え、同じDMの元メッセージへ返信。

DMチャンネルIDは自動的に取得するため設定不要です。DMでは新しいDiscordスレッドを作らず、同じ1対1会話を使います。別モデルやOpenAI APIキーは使いません。

## 必要な設定

- 常駐できる設置先・永続ディスク・公開HTTPS URL
- Discord **Bot** Token
- 自分のDiscord user ID：`DISCORD_OWNER_USER_ID`（1個のみ）
- OAuth client ID、専用client secret、別のowner承認secret（それぞれ32ランダムbytes以上から生成）
- 実際のChatGPT OAuth redirect URI（完全一致allowlist）
- 実際のChatGPT callback hostname

秘密値は設置先のsecret機能/環境変数に設定します。`.env.example` は雛形で、アプリは `.env` を自動読込しません。チャット貼り付けやZIP同梱は不要です。

BotへDMできる状態はDiscord側で用意する必要があります。必要なら共有サーバーでBotを見つけてDMを開きますが、サービス側はサーバー投稿を読みません。Message Content privileged intentはBotとのDMでは不要です。

```sh
cargo test --locked
cargo build --release --locked
umask 077
./target/release/discord-dot-bridge
```

[OAuth設定](OAUTH.md) の `/mcp` とOAuth/discovery経路をlocalhost:8787からHTTPSリバースプロキシで公開し、非公開プラグインとして接続します。このdotでowner DMの購読と返信方針を指定してから往復テストします。GitHubへのpushは接続の前提ではありません。

## 安全性と制限

他人・Bot・サーバー投稿・グループDM・未検証recipientには反応しません。返信先は受信済みの自分のDMに固定。1メッセージ1論理返信。32,000 UTF-16単位までの論理返信を各2,000単位以下へ自動分割し、元メッセージIDで自分の返信だけ編集可能。添付や音声は扱いません。

旧チャンネル版DBは再利用不可。新しい `discord-dm.sqlite3` を使います。DBのowner変更も拒否します。再起動時はrecipient検証を再実行します。

受信時は本文を保存せずmessage/channel IDをSQLiteへ先に記録します。recipient確認と本文取得の一時障害は再試行し、上限到達もfailed記録を残します。権限不一致・削除済みはrejectedとして区別します。`discord_bridge_status`で本文を出さず状態件数を確認できます。DB障害は握り潰さず停止/再接続します。再取得する本文は編集後のものになる場合があり、削除済み本文や停止中の全イベント復元は保証しません。

本物のBot Token・公開URLでの接続と、このdotからの返信はまだ未検証です。詳しい運用条件は README.md に記載しています。

OAuthはownerが許可した接続を認可しますが、特定dot内部IDを暗号的に証明する機能ではありません。秘密発行・配置・ネットワーク設定変更は別途承認作業です。従来の固定Bearerは明示的な診断modeのみで、OAuthと同時には受け付けません。

`TYPING_TIMEOUT_SECS=120`（最大300、0で無効）、`RECENT_CONTEXT_LIMIT=10`（最大20、0でrecent履歴無効）。無返信時はdotが `discord_finish_response` を呼んでtyping更新を止めます。詳しくは FEATURES.md。
