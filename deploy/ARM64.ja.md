# Debian 12 ARM64への配置案（未実行）

対象: Debian 12 ARM64、Docker/systemd利用可のホスト。**このファイルは手順案で、デプロイ済みではありません。**

## イメージ

Dockerfileは公式 `rust:1.99.1-bookworm` → `debian:bookworm-slim` のマルチステージ構成です。公式RustイメージはARM64対応。対象ARM64ホスト上でネイティブビルドするため、x86_64で生成したバイナリはコピーしません。Cargo.lock固定でテスト→releaseビルドします。

本作業環境はx86_64でDockerコマンドがないため、このDockerビルド/ARM64実行は未検証です。実行時は承認済みホストで次を確認します。タグは可変なので、本番固定用digestを実pull後に記録してください。

```sh
cd deploy
# .envを安全に作成し、Bot token/owner ID/MCP認証/callback/Hostを設定
chmod 600 .env
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
docker compose exec discord-dm /usr/local/bin/discord-dot-bridge --healthcheck
```

`.env`はdeployディレクトリ内。内容を画面へ出す `docker compose config`（--quietなし）や `docker inspect` の共有は避けてください。Docker管理者はコンテナ環境変数へアクセスできるので、ホスト管理権限を限定します。

## ネットワーク

Linuxの `network_mode: host` を使い、Rustはホストの **127.0.0.1:8787のみ**に待受します。Docker port公開設定はありません。既存HTTPSリバースプロキシから `/mcp` と [OAuth設定](../OAUTH.md) に明記したOAuth/discovery経路だけ転送し、Host/Authorizationを保持してください。OAuth同意フォームは同一origin POSTです。`/healthz` を外部公開しません。プロキシ設定・証明書取得・firewall変更は別の承認作業です。

RustはDiscord Gateway/RESTと承認したcallbackへ外向き通信します。DM受信にDiscord側の公開webhook受口は不要です。MCPの公開HTTPSは必要です。

## 保護と永続化

- UID/GID 10001、rootで実行しない
- read-only root filesystem、capabilities全削除、no-new-privileges
- `/data` はnamed volume `dm-data`、SQLiteを保持
- 起動umask 077、`/data` mode700
- 一度に1コンテナのみ。スケールしない
- `docker compose down` はvolumeを保持。**`down -v`は禁止（DB消去）**
- owner変更や旧チャンネル版DBの流用は拒否。別ownerには新しい専用volumeを用意
- WAL利用中のDBを単一ファイルだけコピーしない。停止中にvolume全体をprivate backupするかSQLite backup APIを利用

## ヘルスと本当の稼働確認

`--healthcheck` / localhost `/healthz` はHTTPプロセスとSQLite SELECT 1の確認です。**Discord接続、購読、callback、dot返信を保証しません。** Docker healthcheckはunhealthyを表示するだけで自動再起動を保証しません。プロセス終了はrestart policyの対象です。

最終確認はownerがBotへDMして、同じDMへこのdotから返信が戻ること。他人/グループDM/サーバー投稿を拒否すること、監視停止と再起動を確認してください。実tokenや会話本文をログへ出さないことも点検します。

公式イメージ: https://hub.docker.com/_/rust/
