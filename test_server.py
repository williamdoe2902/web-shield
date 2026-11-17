import unittest

import server


class TargetScopeTests(unittest.TestCase):
    def test_accepts_loopback_targets(self):
        self.assertTrue(server.is_loopback_url("http://127.0.0.1:3000"))
        self.assertTrue(server.is_loopback_url("https://[::1]/app"))
        self.assertTrue(server.is_loopback_url("http://localhost"))

    def test_rejects_nonlocal_or_ambiguous_targets(self):
        targets = (
            "https://example.com",
            "http://192.168.1.20",
            "file:///etc/passwd",
            "http://user:pass@127.0.0.1",
            "http://localhost.example.com",
        )
        for target in targets:
            with self.subTest(target=target):
                self.assertFalse(server.is_loopback_url(target))

    def test_same_origin_includes_scheme_host_and_port(self):
        self.assertTrue(server.same_origin("http://localhost:3000", "http://localhost:3000/path"))
        self.assertFalse(server.same_origin("http://localhost:3000", "http://localhost:3001"))
        self.assertFalse(server.same_origin("http://localhost", "https://localhost"))


if __name__ == "__main__":
    unittest.main()
