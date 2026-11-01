# このdotへの接続で残っていること（DM専用）

1. 常駐Rustサービス＋永続DB＋公開HTTPSを置くホストを確定。
2. Botへ自分がDMできる状態を用意。Bot Tokenと自分のuser IDを設置先へ安全投入。チャンネルID・サーバーチャンネル権限・Message Content intent設定は不要。
3. [OAuth手順](OAUTH.md) に従い、専用client secretと別のowner承認secretを安全投入。実画面に表示されたredirect URIを完全一致で登録し、HTTPS `/mcp` とOAuth/discovery経路を公開。
4. `plugin-template/` のURLを差し替え、OAuthの事前登録clientとして非公開プラグインを接続し、ownerがHTTPS同意画面で許可する。
5. `discord.dm.created` を `owner_user_id` で購読し、返信してよい範囲を指定。callback実hostnameを確認・限定許可。
6. 自分からBotへ無害なDM→このdotが同じDMに返信する往復を検証。

コードとlocalhostのMCP HTTP経路はテスト済みですが、本物のcallback/Discord受信・返信は未検証です。localhost購読テストはcallback検証済みfixtureを使い、実サービスを呼びません。

GitHubは必須ではありません。先に設置先が決まれば接続作業へ進めます。秘密値をチャットへ貼る必要はありません。
