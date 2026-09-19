#!/usr/bin/env python3
"""記事で扱った落とし穴を、直っていることで確認するテスト

    python3 test_bugs.py

ネットワークに出ないので、オフラインでも実行できます。
fixtures/ は 2026-08-14 に実際に取得した応答をそのまま置いたものです。
"""
import json
import mtastscheck as m

fails = []


def check(name, got, want):
    if got == want:
        print('ok   %s' % name)
    else:
        print('FAIL %s\n       got  %r\n       want %r' % (name, got, want))
        fails.append(name)


def load(p):
    return open('fixtures/' + p, encoding='utf-8').read()


# --- 落とし穴1: mx は複数行ある -------------------------------------------
# key/value を素朴に dict へ詰めると、最後の1行しか残らない。例外は出ない。
google = m.parse_policy(load('google.txt'))
check('mx を3件とも保持している', len(google['mx']), 3)
check('mx の1件目', google['mx'][0], 'smtp.google.com')
check('mx の3件目', google['mx'][2], '*.aspmx.l.google.com')
check('mode を読めている', google['mode'], 'enforce')
check('max_age を読めている', google['max_age'], '86400')

ms = m.parse_policy(load('microsoft.txt'))
check('ワイルドカード1件のみのポリシー', ms['mx'], ['*.mail.protection.outlook.com'])

# CRLF ではなく LF だけのポリシーも読めること
# （「CRLF区切りだからLFで壊れるはず」と予想したが、実際には壊れなかった）
lf = m.parse_policy(load('lf-only.txt'))
check('LFのみのポリシーも読める', lf['mode'], 'testing')


# --- 落とし穴2: DoH の応答に Answer キーが無い -----------------------------
# j['Answer'] と書くと KeyError。未設定ドメインを調べるのが主目的なので、
# 主目的の入力で必ず落ちる実装になってしまう。
def answers_of(fixture):
    j = json.loads(load(fixture))
    return [a.get('data', '') for a in j.get('Answer', [])]


check('NXDOMAIN で落ちない', answers_of('nxdomain.json'), [])
check('NOERROR かつ Answer 無しで落ちない', answers_of('noerror-noanswer.json'), [])
check('設定ありは値を取れる',
      answers_of('ok.json'), ['v=STSv1; id=20210803T010101;'])

# 旧実装が本当に落ちることも確認しておく
try:
    json.loads(load('nxdomain.json'))['Answer']
    check('旧実装は KeyError になる', 'no error', 'KeyError')
except KeyError:
    print('ok   旧実装は KeyError になる')


# --- 落とし穴3: Content-Type の完全一致比較 --------------------------------
# RFC 8461 3.2 は media type が text/plain であることの検証を推奨（SHOULD）。
def media_type(ctype):
    return ctype.split(';')[0].strip().lower()


for raw in ('text/plain',
            'text/plain; charset=utf-8',
            'TEXT/PLAIN; charset=UTF-8',
            '  text/plain  '):
    check('media type を取り出せる: %r' % raw, media_type(raw), 'text/plain')

check('完全一致比較なら落ちること',
      'text/plain; charset=utf-8' == 'text/plain', False)


# --- 落とし穴4: RFC 8461 3.3 はリダイレクト追跡を禁止 ------------------------
# urllib は既定で 3xx を追跡する。ハンドラを差し替えていることを確認する。
handler = m._NoRedirect()
check('3xx を追跡しない',
      handler.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/'),
      None)

print()
if fails:
    print('%d failed' % len(fails))
    raise SystemExit(1)
print('all passed')
