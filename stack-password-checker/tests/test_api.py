import os
import tempfile
import unittest

from backend.app import create_app

GOOD = {"level": "strong", "score": 94, "passed": 5, "length": 14}


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DB_PATH": os.path.join(self.tmp.name, "t.db"), "TESTING": True,
                               "RATE_LIMIT_ENABLED": False, "MAX_HISTORY": 3})
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_page_and_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        r.close()

    def test_history_roundtrip(self):
        self.assertEqual(self.c.get("/api/history").get_json()["items"], [])
        r = self.c.post("/api/history", json=GOOD)
        self.assertEqual(r.status_code, 201)
        item = r.get_json()["item"]
        self.assertEqual(item["level"], "strong")
        items = self.c.get("/api/history").get_json()["items"]
        self.assertEqual([i["id"] for i in items], [item["id"]])
        self.assertEqual(self.c.delete(f"/api/history/{item['id']}").status_code, 204)
        self.assertEqual(self.c.delete(f"/api/history/{item['id']}").status_code, 404)

    def test_history_is_per_browser(self):
        self.c.post("/api/history", json=GOOD)
        other = self.app.test_client()
        self.assertEqual(other.get("/api/history").get_json()["items"], [])

    def test_rejects_extra_fields_and_never_reflects_them(self):
        r = self.c.post("/api/history", json={**GOOD, "password": "hunter2-SECRET"})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("hunter2", r.get_data(as_text=True))
        self.assertEqual(self.c.get("/api/history").get_json()["items"], [])

    def test_validation(self):
        for bad in ({**GOOD, "level": "ultra"}, {**GOOD, "score": 101}, {**GOOD, "length": 0},
                    {**GOOD, "passed": 6}, {**GOOD, "score": "9"}, {**GOOD, "score": True}, [1, 2]):
            self.assertEqual(self.c.post("/api/history", json=bad).status_code, 400, bad)

    def test_trim_to_max(self):
        for _ in range(5):
            self.c.post("/api/history", json=GOOD)
        self.assertEqual(len(self.c.get("/api/history").get_json()["items"]), 3)

    def test_clear(self):
        self.c.post("/api/history", json=GOOD)
        self.assertEqual(self.c.delete("/api/history").status_code, 204)
        self.assertEqual(self.c.get("/api/history").get_json()["items"], [])

    def test_cross_origin_blocked(self):
        r = self.c.post("/api/history", json=GOOD, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_analyze_endpoint(self):
        r = self.c.post("/api/analyze", json={"password": "Blue-Fox#4821x"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["level"], "strong")
        self.assertNotIn("Blue-Fox", r.get_data(as_text=True))
        self.assertEqual(self.c.post("/api/analyze", json={"password": "x" * 129}).status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", json={"password": 5}).status_code, 400)

    def test_analyze_can_be_disabled(self):
        self.app.config["ENABLE_ANALYZE_API"] = False
        self.assertEqual(self.c.post("/api/analyze", json={"password": "abc"}).status_code, 404)

    def test_rate_limit(self):
        self.app.config["RATE_LIMIT_ENABLED"] = True
        self.app.config["WRITE_PER_MIN"] = 2
        codes = [self.c.post("/api/history", json=GOOD).status_code for _ in range(3)]
        self.assertEqual(codes, [201, 201, 429])

    def test_database_has_no_password_column(self):
        import sqlite3
        self.c.post("/api/history", json=GOOD)
        con = sqlite3.connect(self.app.config["DB_PATH"])
        cols = [r[1] for r in con.execute("PRAGMA table_info(history)")]
        con.close()
        self.assertEqual(cols, ["id", "client_id", "ts", "level", "score", "passed", "length_chars"])


if __name__ == "__main__":
    unittest.main()


class PagesAndPrivacyTests(unittest.TestCase):
    """Every tool page is served, with a strict CSP, and no page loads third-party scripts."""
    PAGES = ["index.html", "text-crypto.html", "hash.html", "file-hash.html", "file-crypto.html", "verify.html"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"DB_PATH": os.path.join(self.tmp.name, "t.db"), "TESTING": True, "RATE_LIMIT_ENABLED": False})
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_pages_and_scripts_served(self):
        import re
        for page in self.PAGES:
            r = self.c.get("/" + page)
            self.assertEqual(r.status_code, 200, page)
            html = r.get_data(as_text=True)
            r.close()
            self.assertNotIn("<script>", html, page)                       # no inline scripts (CSP would block them)
            for src in re.findall(r'<script[^>]+src="([^"]+)"', html):
                self.assertFalse(src.startswith(("http:", "https:", "//")), f"{page} loads external script {src}")
                s = self.c.get("/" + src)
                self.assertEqual(s.status_code, 200, f"{page} -> {src}")
                s.close()

    def test_csp_blocks_other_origins_and_allows_worker_and_blob_previews(self):
        r = self.c.get("/file-hash.html")
        csp = r.headers["Content-Security-Policy"]
        r.close()
        for needle in ("script-src 'self';", "worker-src 'self'", "img-src 'self' data: blob:", "connect-src 'self'", "object-src 'none'"):
            self.assertIn(needle, csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)

    def test_no_endpoint_accepts_encryption_or_file_data(self):
        for path in ("/api/encrypt", "/api/decrypt", "/api/hash", "/api/upload", "/api/files"):
            self.assertIn(self.c.post(path, json={"text": "x", "password": "y"}).status_code, (404, 405), path)

    def test_hash_tools_do_not_call_the_backend(self):
        import re
        for js in ("text-crypto.js", "hash.js", "file-hash.js", "file-crypto.js", "verify.js", "stack-crypto.js", "stack-hash.js", "hash-worker.js"):
            code = (self.app.static_folder and open(os.path.join(self.app.static_folder, "js", js), encoding="utf-8").read())
            self.assertIsNone(re.search(r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|localStorage|sessionStorage|document\.cookie|console\s*\.\s*(log|info|warn|error|debug|trace)", code), js)
