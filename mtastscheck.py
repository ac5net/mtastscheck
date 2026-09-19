#!/usr/bin/env python3
"""mtastscheck.py - MTA-STS / TLS-RPT の設定を確認する

使い方:
    ./mtastscheck.py example.jp [example2.jp ...]

DNSはDoH（dns.google）で引くため、ローカルのリゾルバ設定に影響されません。
"""
import sys, json, ssl, urllib.request, urllib.error

TIMEOUT = 10
UA = 'mtastscheck/1.0'


def doh(name, rtype='TXT'):
    """DNS over HTTPS で問い合わせる。戻り値は (status, [レコード文字列])"""
    url = 'https://dns.google/resolve?name=%s&type=%s' % (name, rtype)
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            j = json.load(r)
    except Exception as e:
        return ('ERR:%s' % type(e).__name__, [])
    # NXDOMAIN(3) でも NOERROR(0) でも Answer が無いことがある。
    # j['Answer'] と直接書くと KeyError で落ちる
    answers = [a.get('data', '') for a in j.get('Answer', [])]
    return (j.get('Status'), answers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """RFC 8461 3.3: HTTP 3xx redirects MUST NOT be followed"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def fetch_policy(domain):
    """ポリシーを取得する。戻り値は (HTTPステータス, Content-Type, 本文, エラー)

    注意: urllib は既定で 3xx を黙って追跡するが、RFC 8461 3.3 は
    ポリシー取得でのリダイレクト追跡を禁止している（MUST NOT）。
    ここでは追跡せず、3xx はエラーとして報告する。
    """
    url = 'https://mta-sts.%s/.well-known/mta-sts.txt' % domain
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            return (r.status, r.headers.get('Content-Type', ''), r.read().decode('utf-8', 'replace'), None)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return (e.code, '', '', 'HTTP %d リダイレクト。RFC 8461 3.3 は追跡を禁止（MUST NOT）' % e.code)
        return (e.code, e.headers.get('Content-Type', ''), '', 'HTTP %d' % e.code)
    except ssl.SSLCertVerificationError as e:
        # 証明書は mta-sts.<ドメイン> に対して有効でなければならない（RFC 8461 3.3）
        return (None, '', '', '証明書検証エラー: %s' % e.verify_message)
    except Exception as e:
        return (None, '', '', '%s: %s' % (type(e).__name__, e))


def parse_policy(body):
    """ポリシーを辞書にする。mx は複数行あるのでリストで保持する"""
    policy = {'mx': []}
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        key, sep, value = line.partition(':')
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == 'mx':
            policy['mx'].append(value)
        else:
            policy[key] = value
    return policy


def check(domain):
    print('=' * 56)
    print(domain)
    print('=' * 56)

    # 1) _mta-sts TXT レコード
    status, recs = doh('_mta-sts.' + domain)
    sts = [r for r in recs if 'STSv1' in r]
    if not sts:
        print('  MTA-STS TXT : なし（DNS status=%s）' % status)
    else:
        print('  MTA-STS TXT : %s' % sts[0])
        fields = dict(
            (p.split('=', 1)[0].strip().lower(), p.split('=', 1)[1].strip())
            for p in sts[0].split(';') if '=' in p
        )
        if 'id' not in fields:
            print('    [警告] id フィールドが無い。RFC 8461 3.1 で必須')
        else:
            print('    id = %s（ポリシー更新時はこの値も変える必要がある）' % fields['id'])
        if len(sts) > 1:
            print('    [警告] STSv1 のTXTが %d 件ある。1件にすること' % len(sts))

    # 2) TLS-RPT
    status, recs = doh('_smtp._tls.' + domain)
    rpt = [r for r in recs if 'TLSRPTv1' in r]
    print('  TLS-RPT     : %s' % (rpt[0] if rpt else 'なし（DNS status=%s）' % status))

    if not sts:
        print('  → MTA-STS 未設定のためポリシー取得はスキップ')
        return

    # 3) ポリシー取得
    code, ctype, body, err = fetch_policy(domain)
    if err:
        print('  ポリシー取得: 失敗 - %s' % err)
        return
    print('  ポリシー取得: HTTP %s / Content-Type: %s' % (code, ctype))

    # media type は text/plain であることを確認する（RFC 8461 3.2）
    # charset 等のパラメータが付くので、前方一致で見る
    media = ctype.split(';')[0].strip().lower()
    if media != 'text/plain':
        print('    [警告] media type が text/plain ではない: %s' % media)

    p = parse_policy(body)
    print('  version : %s' % p.get('version', '(なし)'))
    print('  mode    : %s' % p.get('mode', '(なし)'))
    print('  max_age : %s' % p.get('max_age', '(なし)'))
    print('  mx      : %d件' % len(p['mx']))
    for m in p['mx']:
        print('      %s' % m)

    # 必須フィールドの検査（RFC 8461 3.2）
    for k in ('version', 'mode', 'max_age'):
        if k not in p:
            print('    [警告] 必須フィールド %s が無い' % k)
    if p.get('mode') != 'none' and not p['mx']:
        print('    [警告] mode が none 以外なのに mx が1件も無い')
    try:
        if int(p.get('max_age', 0)) < 86400:
            print('    [注意] max_age が 86400 未満。運用が安定したら伸ばす')
    except ValueError:
        print('    [警告] max_age が数値ではない')
    if p.get('mode') == 'testing':
        print('    [情報] mode=testing。ポリシー違反でも配送は継続される')
    if p.get('mode') == 'none':
        print('    [情報] mode=none。MTA-STS を無効化する意味になる')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    for d in sys.argv[1:]:
        check(d)
    return 0


if __name__ == '__main__':
    sys.exit(main())
