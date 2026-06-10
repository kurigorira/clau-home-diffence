#!/usr/bin/env python3
"""漏洩パスワード確認ツール（Have I Been Pwned / Pwned Passwords）。

入力したパスワードが過去のデータ侵害で流出した既知のものに含まれていないかを調べる。
**k-匿名（k-Anonymity）方式**を使うので、パスワードそのものやその完全なハッシュは
ネットに送らない。送るのは SHA-1 ハッシュ（40桁）の先頭5桁だけで、サーバは該当する
候補一覧（末尾35桁）を返す。突き合わせは手元で行う。

使い方:
    python3 check-pwned-password.py            # 画面に表示されない形でパスワード入力を促す
    python3 check-pwned-password.py --stdin    # 標準入力から1行読む（自動化用）

終了コード: 0=漏洩なし, 2=漏洩あり, 1=エラー。
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import sys
import urllib.error
import urllib.request
from typing import Callable, Dict, Optional

API_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"


# ---------------------------------------------------------------------------
# 純粋ロジック（テスト対象）— ネットワークには触れない
# ---------------------------------------------------------------------------
def sha1_hex(password: str) -> str:
    """パスワードの SHA-1 を大文字16進40桁で返す（HIBP の仕様に合わせる）。"""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(sha1: str) -> tuple[str, str]:
    """SHA-1(40桁) を (先頭5桁プレフィックス, 末尾35桁サフィックス) に分割する。"""
    sha1 = sha1.upper()
    return sha1[:5], sha1[5:]


def parse_range_response(body: str) -> Dict[str, int]:
    """range API の応答（"SUFFIX:COUNT" の改行区切り）を {suffix: count} に変換する。"""
    counts: Dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        suffix = suffix.strip().upper()
        try:
            counts[suffix] = int(count.strip().replace(",", ""))
        except ValueError:
            continue
    return counts


def count_for_password(password: str, fetch_range: Callable[[str], str]) -> int:
    """パスワードの漏洩回数を返す（0 なら未漏洩）。

    fetch_range(prefix) はプレフィックスに対する range API 応答テキストを返す関数。
    テストではこれをモックに差し替えることで、ネットワーク無しに検証できる。
    """
    prefix, suffix = split_hash(sha1_hex(password))
    counts = parse_range_response(fetch_range(prefix))
    return counts.get(suffix, 0)


# ---------------------------------------------------------------------------
# I/O 層
# ---------------------------------------------------------------------------
def http_fetch_range(prefix: str) -> str:
    req = urllib.request.Request(
        API_RANGE_URL.format(prefix=prefix),
        headers={"User-Agent": "HomeWatch-PwnedCheck/1.0", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="漏洩パスワード確認 (HIBP k-匿名)")
    parser.add_argument("--stdin", action="store_true",
                        help="標準入力から1行読む（自動化用。端末では使わない）")
    args = parser.parse_args(argv)

    if args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("確認したいパスワード（画面に表示されません）: ")

    if not password:
        sys.stderr.write("パスワードが空です。\n")
        return 1

    try:
        count = count_for_password(password, http_fetch_range)
    except (urllib.error.URLError, OSError) as exc:
        sys.stderr.write(f"通信エラー: {exc}\n")
        return 1

    if count > 0:
        print(f"⚠ 危険: このパスワードは既知の漏洩に {count:,} 回出現しています。")
        print("  すぐに変更し、他サービスで使い回している場合はそちらも変更してください。")
        return 2
    print("✓ このパスワードは既知の漏洩には見つかりませんでした（安全の保証ではありません）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
