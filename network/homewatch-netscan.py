#!/usr/bin/env python3
"""HomeWatch netscan — 自宅LANの在線端末を発見し、未知の端末（侵入候補）をアラートする。

常時稼働の機器（Raspberry Pi など）で cron / systemd timer から定期実行する想定。
追加パッケージへの依存はなし（Python3 標準ライブラリのみ）。OS 標準の
`ip neigh` / `arp -a` を使い、可能なら ping スイープで ARP テーブルを温める。

検知データはローカルにのみ保存し、外部へ送信しない（任意の Webhook を明示設定した場合を除く）。

使い方:
    # 初回: 今つながっている端末を「既知」として登録（自分の家の端末だけが居る状態で実行）
    python3 homewatch-netscan.py --init

    # 以降: 定期スキャン（未知の端末が現れたら通知＋ログ）
    python3 homewatch-netscan.py --scan

ロジック（パース・差分）は I/O から分離してあり、tests/test_netscan.py で検証できる。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# パスの既定値
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KNOWN_PATH = os.path.join(_HERE, "known-devices.json")
DEFAULT_LOG_PATH = os.path.join(_HERE, "homewatch-netscan.log")

# MAC アドレスらしき文字列（区切りは : または -）
_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
# IPv4 アドレス
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# 解決できなかった/無効なエントリで現れる値
_INVALID_MACS = {"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "incomplete"}


# ---------------------------------------------------------------------------
# 純粋ロジック（テスト対象）— ここでは一切 I/O を行わない
# ---------------------------------------------------------------------------
def normalize_mac(mac: str) -> str:
    """MAC を小文字・コロン区切り・各オクテット2桁ゼロ詰めに正規化する。

    "0:1A-2b:3:44:5" のような不揃いな表記も受け付ける。無効なら "" を返す。
    """
    if not mac:
        return ""
    raw = mac.strip().lower().replace("-", ":")
    parts = raw.split(":")
    if len(parts) != 6:
        return ""
    out = []
    for p in parts:
        if not re.fullmatch(r"[0-9a-f]{1,2}", p):
            return ""
        out.append(p.zfill(2))
    norm = ":".join(out)
    return "" if norm in _INVALID_MACS else norm


def parse_ip_neigh(output: str) -> Dict[str, str]:
    """`ip neigh`（Linux）の出力を {mac: ip} に変換する。

    例の行: "192.168.1.5 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    REACHABLE/STALE/DELAY/PROBE のみ採用し、FAILED/INCOMPLETE は除外する。
    """
    devices: Dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        upper = line.upper()
        if "FAILED" in upper or "INCOMPLETE" in upper:
            continue
        if "LLADDR" not in upper:
            continue
        ip_match = _IPV4_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac:
            devices.setdefault(mac, ip_match.group(1))
    return devices


def parse_arp_a(output: str) -> Dict[str, str]:
    """`arp -a`（macOS/Linux/Windows）の出力を {mac: ip} に変換する。

    例の行: "? (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            "host (192.168.1.7) at <incomplete> on eth0"  -> 除外
    """
    devices: Dict[str, str] = {}
    for line in output.splitlines():
        if "incomplete" in line.lower():
            continue
        ip_match = _IPV4_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if mac:
            devices.setdefault(mac, ip_match.group(1))
    return devices


def find_new_devices(
    current: Dict[str, str], known: Dict[str, str]
) -> List[Dict[str, str]]:
    """現在の在線端末 {mac: ip} のうち、既知一覧 {mac: name} に無いものを返す。

    戻り値は [{"mac": ..., "ip": ...}] の MAC 昇順リスト。
    """
    new = []
    for mac, ip in current.items():
        if mac not in known:
            new.append({"mac": mac, "ip": ip})
    return sorted(new, key=lambda d: d["mac"])


def merge_known(known: Dict[str, str], devices: Dict[str, str]) -> Dict[str, str]:
    """既知一覧に、まだ登録の無い端末を "unnamed-<mac末尾>" として追加した辞書を返す。"""
    merged = dict(known)
    for mac in devices:
        if mac not in merged:
            merged[mac] = "unnamed-" + mac.replace(":", "")[-4:]
    return merged


# ---------------------------------------------------------------------------
# I/O 層（OS コマンド・ファイル・通知）— テストではモックする
# ---------------------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 30) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout or ""
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ""


def ping_sweep(cidr: str, timeout: int = 1) -> None:
    """CIDR 内の各 IP に 1 発 ping を投げて ARP テーブルを温める（応答は無視）。

    /24 より広いレンジは時間がかかるためスキップする。
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return
    if net.num_addresses > 256:
        return
    is_windows = sys.platform.startswith("win")
    count_flag = "-n" if is_windows else "-c"
    wait_flag = "-w" if is_windows else "-W"
    procs = []
    for host in net.hosts():
        cmd = ["ping", count_flag, "1", wait_flag, str(timeout), str(host)]
        try:
            procs.append(
                subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            )
        except (OSError, ValueError):
            break
    for p in procs:
        try:
            p.wait(timeout=timeout + 2)
        except subprocess.SubprocessError:
            p.kill()


def discover(cidr: Optional[str] = None) -> Dict[str, str]:
    """利用可能な手段で在線端末 {mac: ip} を取得する。

    優先順: arp-scan（最も確実） > ping スイープ + ip neigh/arp -a。
    """
    if shutil.which("arp-scan"):
        out = _run(["arp-scan", "--localnet", "--quiet"], timeout=60)
        devices = parse_arp_a(out)
        if devices:
            return devices

    if cidr:
        ping_sweep(cidr)

    if shutil.which("ip"):
        devices = parse_ip_neigh(_run(["ip", "neigh"]))
        if devices:
            return devices

    if shutil.which("arp"):
        return parse_arp_a(_run(["arp", "-a"]))

    return {}


def load_known(path: str) -> Dict[str, str]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    devices = data.get("devices", data) if isinstance(data, dict) else {}
    out: Dict[str, str] = {}
    for mac, name in devices.items():
        norm = normalize_mac(mac)
        if norm:
            out[norm] = str(name)
    return out


def save_known(path: str, known: Dict[str, str]) -> None:
    payload = {
        "_comment": "MAC アドレス -> 端末名。新規端末はここに追記すると以後アラートされません。",
        "updated_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "devices": dict(sorted(known.items())),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def write_log(path: str, record: dict) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def desktop_notify(title: str, body: str) -> None:
    """notify-send があればデスクトップ通知。無ければ標準エラーへ。"""
    if shutil.which("notify-send"):
        _run(["notify-send", "-u", "critical", title, body], timeout=10)
    else:
        sys.stderr.write(f"[HomeWatch] {title}: {body}\n")


# ---------------------------------------------------------------------------
# コマンド
# ---------------------------------------------------------------------------
def cmd_init(args) -> int:
    devices = discover(args.cidr)
    if not devices:
        sys.stderr.write(
            "在線端末を取得できませんでした。権限（root/sudo）や --cidr 指定を確認してください。\n"
        )
        return 1
    known = merge_known(load_known(args.known), devices)
    save_known(args.known, known)
    print(f"{len(devices)} 台を既知端末として登録しました -> {args.known}")
    print("名前は known-devices.json を編集して分かりやすく変更できます。")
    return 0


def cmd_scan(args) -> int:
    known = load_known(args.known)
    if not known:
        sys.stderr.write(
            "既知端末リストが空です。まず `--init` でベースラインを作成してください。\n"
        )
        return 1
    current = discover(args.cidr)
    new_devices = find_new_devices(current, known)
    timestamp = _dt.datetime.now().astimezone().isoformat(timespec="seconds")

    if new_devices:
        for dev in new_devices:
            record = {
                "time": timestamp,
                "event": "unknown_device",
                "severity": "alert",
                "mac": dev["mac"],
                "ip": dev["ip"],
            }
            write_log(args.log, record)
        macs = ", ".join(f"{d['ip']} ({d['mac']})" for d in new_devices)
        desktop_notify(
            "HomeWatch: 未知の端末を検出",
            f"自宅ネットワークに見覚えのない端末が {len(new_devices)} 台います: {macs}",
        )
        print(f"ALERT: 未知の端末 {len(new_devices)} 台 — {macs}")
        return 2

    write_log(
        args.log,
        {"time": timestamp, "event": "scan_ok", "severity": "info",
         "known_seen": len([m for m in current if m in known])},
    )
    print(f"OK: 在線 {len(current)} 台、すべて既知端末です。")
    return 0


def build_parser() -> argparse.ArgumentParser:
    # 共通オプションを親パーサにまとめ、サブコマンドの前後どちらでも指定できるようにする
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--known", default=DEFAULT_KNOWN_PATH,
                        help="既知端末リスト(JSON)のパス")
    common.add_argument("--log", default=DEFAULT_LOG_PATH,
                        help="アラートログ(JSON Lines)のパス")
    common.add_argument("--cidr", default=None,
                        help="ping スイープ対象の CIDR 例: 192.168.1.0/24")

    parser = argparse.ArgumentParser(
        description="HomeWatch 自宅LAN 侵入検知スキャナ", parents=[common]
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", parents=[common],
                   help="現在の在線端末を既知として登録").set_defaults(func=cmd_init)
    sub.add_parser("scan", parents=[common],
                   help="スキャンして未知端末を検出").set_defaults(func=cmd_scan)
    # --init / --scan のフラグ形式も許容
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 利便性のため --init / --scan を init / scan に読み替える
    argv = [a.lstrip("-") if a in ("--init", "--scan") else a for a in argv]
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
