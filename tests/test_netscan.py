"""homewatch-netscan の純粋ロジック（パース・差分・正規化）の単体テスト。

ネットワークにも OS コマンドにも触れない。合成データのみで検証する。
pytest でも `python3 -m unittest` でも実行できる。
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULE_PATH = os.path.join(_HERE, "..", "network", "homewatch-netscan.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("homewatch_netscan", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ns = _load_module()


class TestNormalizeMac(unittest.TestCase):
    def test_lowercases_and_colons(self):
        self.assertEqual(ns.normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_zero_pads_octets(self):
        self.assertEqual(ns.normalize_mac("0:1a:2:3:44:5"), "00:1a:02:03:44:05")

    def test_rejects_broadcast_and_zero(self):
        self.assertEqual(ns.normalize_mac("ff:ff:ff:ff:ff:ff"), "")
        self.assertEqual(ns.normalize_mac("00:00:00:00:00:00"), "")

    def test_rejects_malformed(self):
        self.assertEqual(ns.normalize_mac("not-a-mac"), "")
        self.assertEqual(ns.normalize_mac("aa:bb:cc:dd:ee"), "")
        self.assertEqual(ns.normalize_mac(""), "")


class TestParseIpNeigh(unittest.TestCase):
    SAMPLE = (
        "192.168.1.1 dev wlan0 lladdr aa:bb:cc:11:22:33 REACHABLE\n"
        "192.168.1.5 dev wlan0 lladdr AA:BB:CC:44:55:66 STALE\n"
        "192.168.1.9 dev wlan0  FAILED\n"
        "192.168.1.10 dev wlan0 lladdr 00:00:00:00:00:00 INCOMPLETE\n"
        "\n"
    )

    def test_parses_reachable_and_stale(self):
        devices = ns.parse_ip_neigh(self.SAMPLE)
        self.assertEqual(devices["aa:bb:cc:11:22:33"], "192.168.1.1")
        self.assertEqual(devices["aa:bb:cc:44:55:66"], "192.168.1.5")

    def test_skips_failed_and_incomplete(self):
        devices = ns.parse_ip_neigh(self.SAMPLE)
        self.assertNotIn("00:00:00:00:00:00", devices)
        self.assertEqual(len(devices), 2)


class TestParseArpA(unittest.TestCase):
    SAMPLE = (
        "? (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0\n"
        "router.lan (192.168.1.254) at a:b:c:d:e:f on eth0\n"
        "? (192.168.1.7) at <incomplete> on eth0\n"
    )

    def test_parses_entries(self):
        devices = ns.parse_arp_a(self.SAMPLE)
        self.assertEqual(devices["aa:bb:cc:11:22:33"], "192.168.1.1")
        # 不揃いな表記もゼロ詰め正規化される
        self.assertEqual(devices["0a:0b:0c:0d:0e:0f"], "192.168.1.254")

    def test_skips_incomplete(self):
        devices = ns.parse_arp_a(self.SAMPLE)
        self.assertEqual(len(devices), 2)


class TestFindNewDevices(unittest.TestCase):
    def test_returns_unknown_macs_sorted(self):
        known = {"aa:bb:cc:11:22:33": "router"}
        current = {
            "aa:bb:cc:11:22:33": "192.168.1.1",   # 既知
            "de:ad:be:ef:00:02": "192.168.1.50",  # 未知
            "de:ad:be:ef:00:01": "192.168.1.40",  # 未知
        }
        new = ns.find_new_devices(current, known)
        self.assertEqual([d["mac"] for d in new],
                         ["de:ad:be:ef:00:01", "de:ad:be:ef:00:02"])
        self.assertEqual(new[0]["ip"], "192.168.1.40")

    def test_empty_when_all_known(self):
        known = {"aa:bb:cc:11:22:33": "router"}
        current = {"aa:bb:cc:11:22:33": "192.168.1.1"}
        self.assertEqual(ns.find_new_devices(current, known), [])


class TestMergeKnown(unittest.TestCase):
    def test_adds_unnamed_for_new(self):
        known = {"aa:bb:cc:11:22:33": "router"}
        devices = {"aa:bb:cc:11:22:33": "192.168.1.1",
                   "de:ad:be:ef:12:34": "192.168.1.60"}
        merged = ns.merge_known(known, devices)
        self.assertEqual(merged["aa:bb:cc:11:22:33"], "router")  # 既存名は保持
        self.assertEqual(merged["de:ad:be:ef:12:34"], "unnamed-1234")


class TestKnownFileRoundTrip(unittest.TestCase):
    def test_save_and_load(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "known.json")
            ns.save_known(path, {"AA:BB:CC:11:22:33": "router"})
            loaded = ns.load_known(path)
            self.assertEqual(loaded, {"aa:bb:cc:11:22:33": "router"})

    def test_load_missing_returns_empty(self):
        self.assertEqual(ns.load_known("/no/such/file.json"), {})


if __name__ == "__main__":
    unittest.main()
