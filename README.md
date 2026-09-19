# mtastscheck

MTA-STS（RFC 8461）と TLS-RPT（RFC 8460）の設定を確認するスクリプトです。
Python 標準ライブラリだけで動き、外部パッケージのインストールは不要です。

DNSは DoH（`dns.google`）で引くため、ローカルのリゾルバ設定に影響されません。

## 使い方

```
git clone https://github.com/ac5net/mtastscheck.git
cd mtastscheck
python3 mtastscheck.py example.jp [example2.jp ...]
```

`_mta-sts.<domain>` と `_smtp._tls.<domain>` の TXT を引き、
MTA-STS が設定されていれば
`https://mta-sts.<domain>/.well-known/mta-sts.txt` からポリシーを取得して中身を検査します。

## 調べた結果（2026年8月14日時点）

主要30ドメインを調べたところ、**MTA-STS を設定していたのは2件だけ**でした。

```
海外系 10件中 2件
  あり : google.com, microsoft.com
  なし : apple.com, amazon.com, cloudflare.com, github.com,
         salesforce.com, zoom.us, slack.com, okta.com

日本企業系 20件中 0件
  nifty.com, cybozu.com, moneyforward.com, mercari.com, ntt.com,
  kddi.com, yahoo.co.jp, rakuten.co.jp, biglobe.ne.jp, ocn.ne.jp,
  so-net.ne.jp, sakura.ad.jp, freee.co.jp, line.me, softbank.jp,
  jal.co.jp, ana.co.jp, mufg.jp, smbc.co.jp, japanpost.jp
```

DNS応答の内訳は NXDOMAIN が21件、NOERROR だが Answer 無しが7件で、
**30件中28件が「TXTレコードが返ってこない」パターン**でした。

## 踏んだ落とし穴

### 1. `mx` は複数行ある

ポリシーは `key: value` が並ぶだけの形式なので、素朴に dict へ詰めたくなります。
`google.com` のポリシーは `mx` が3行あるため、それをやると最後の1行しか残りません。

**例外は出ません。** そのうえで MX の照合を実装すると、正しい MX が不一致と判定されます。

### 2. DoH の応答に `Answer` キーが無い

`j['Answer']` と書くと `KeyError` で止まります。

NXDOMAIN だけを想定して `Status == 3` を弾いても足りません。
**ドメインは存在するがサブドメインの TXT が無い**場合、
DNS は NOERROR を返しつつ `Answer` を含めません。今回は7件ありました。

未設定ドメインを数えることが主目的のスクリプトなので、
主目的の入力で必ず落ちる実装になっていました。`j.get('Answer', [])` を使います。

### 3. Content-Type の完全一致比較

RFC 8461 3.2 は、ポリシーの media type が `text/plain` であることの検証を推奨（SHOULD）しています。
Web サーバが利用者に任意パスのコンテンツを置かせている場合に、
偽のポリシーを掴まされるのを防ぐためです。

`ctype == 'text/plain'` と書くと `charset` 付きで False になります。
`;` で切って小文字化してから比べます。

### 4. urllib は既定でリダイレクトを追う

RFC 8461 3.3 にこうあります。

> HTTP 3xx redirects MUST NOT be followed

ポリシーの取得先を別ホストへ飛ばせると検証の意味が無くなるためです。
ところが `urllib.request` は既定で 3xx を追跡するので、
**素直に書くと RFC 違反になる**側でした。`HTTPRedirectHandler` を差し替えています。

同じ節で、ポリシー取得に HTTP キャッシュを使うことも MUST NOT とされています。

### 外した予想

「CRLF 区切りだから、LF しか無いポリシーで壊れるはず」と予想していましたが、
`splitlines()` と `strip()` が吸収してしまい**バグになりませんでした。**
`fixtures/lf-only.txt` がそのケースです。

## テスト

```
python3 test_bugs.py
```

ネットワークに出ないのでオフラインで実行できます。
`fixtures/` は 2026年8月14日に実際に取得した応答とポリシーをそのまま置いたものです。

## 解説記事

RFC 8461 の要件の読み合わせ、30ドメインの調査手順、出力の読み方はブログに書いています。

https://ac-5.net/security/mta-sts-tls-rpt-check/

## ライセンス

MIT
