"""check-pwned-password の純粋ロジックの単体テスト。

range API への通信はモックに差し替え、ネットワーク無しで検証する。
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODULE_PATH = os.path.join(_HERE, "..", "tools", "check-pwned-password.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("check_pwned", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cp = _load_module()


class TestHashing(unittest.TestCase):
    def test_sha1_known_value(self):
        # "password" の SHA-1（HIBP でよく使われる検証値）
        self.assertEqual(
            cp.sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        )

    def test_split_hash(self):
        prefix, suffix = cp.split_hash(cp.sha1_hex("password"))
        self.assertEqual(prefix, "5BAA6")
        self.assertEqual(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        self.assertEqual(len(prefix), 5)
        self.assertEqual(len(suffix), 35)


class TestParseRangeResponse(unittest.TestCase):
    def test_parses_suffix_counts(self):
        body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\r\n"
        counts = cp.parse_range_response(body)
        self.assertEqual(counts["1E4C9B93F3F0682250B6CF8331B7EE68FD8"], 99)

    def test_ignores_garbage_lines(self):
        counts = cp.parse_range_response("garbage\n\nABC:notanumber\nDEF:5\n")
        self.assertEqual(counts, {"DEF": 5})


class TestCountForPassword(unittest.TestCase):
    def test_breached_password_returns_count(self):
        # "password" のサフィックスを含む応答を返すモック
        def fake_fetch(prefix):
            self.assertEqual(prefix, "5BAA6")  # 先頭5桁だけが渡る = k-匿名
            return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471\nXXXX:1\n"

        self.assertEqual(cp.count_for_password("password", fake_fetch), 3730471)

    def test_safe_password_returns_zero(self):
        def fake_fetch(prefix):
            return "0000000000000000000000000000000000A:2\n"

        self.assertEqual(cp.count_for_password("a-very-unique-passphrase", fake_fetch), 0)

    def test_only_prefix_is_sent(self):
        """完全なハッシュやパスワードがモックに渡らない（k-匿名）ことを確認。"""
        seen = {}

        def fake_fetch(prefix):
            seen["prefix"] = prefix
            return ""

        cp.count_for_password("hunter2", fake_fetch)
        self.assertEqual(len(seen["prefix"]), 5)
        self.assertNotIn("hunter2", seen["prefix"])


if __name__ == "__main__":
    unittest.main()
