"""Deployment checks: the Vercel entry point, and behaviour when no server database is available."""
import importlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

from backend.app import create_app

ROOT = Path(__file__).resolve().parent.parent


class EntryPointTests(unittest.TestCase):
    def test_pyproject_entrypoint_resolves_to_a_flask_app(self):
        conf = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        module, _, attr = conf["tool"]["vercel"]["entrypoint"].partition(":")
        self.assertEqual((module, attr), ("run", "app"))
        from flask import Flask
        self.assertIsInstance(getattr(importlib.import_module(module), attr), Flask)

    def test_pyproject_has_project_table_matching_requirements(self):
        # Vercel runs `uv lock`, which fails without a [project] table.
        conf = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = conf["project"]
        for key in ("name", "version", "requires-python", "dependencies"):
            self.assertIn(key, project)
        reqs = [ln.strip() for ln in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")]
        self.assertEqual(sorted(r.replace(" ", "") for r in project["dependencies"]),
                         sorted(r.replace(" ", "") for r in reqs))

    def test_no_conflicting_entry_points(self):
        for name in ("app.py", "index.py", "server.py", "main.py", "wsgi.py", "vercel.json"):
            self.assertFalse((ROOT / name).exists(), name)


class HistoryDisabledTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "never-created", "t.db")
        self.app = create_app({"DB_PATH": self.db, "HISTORY_ENABLED": False, "TESTING": True})
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_history_api_answers_503_and_creates_no_database(self):
        body = {"level": "strong", "score": 94, "passed": 5, "length": 14}
        self.assertEqual(self.c.get("/api/history").status_code, 503)
        self.assertEqual(self.c.post("/api/history", json=body).status_code, 503)
        self.assertEqual(self.c.delete("/api/history").status_code, 503)
        self.assertEqual(self.c.delete("/api/history/abc").status_code, 503)
        self.assertFalse(os.path.exists(os.path.dirname(self.db)))

    def test_pages_assets_and_health_still_work(self):
        for path in ("/", "/index.html", "/css/style.css", "/js/script.js", "/js/config.js", "/assets/logo.png",
                     "/text-crypto.html", "/hash.html", "/file-hash.html", "/file-crypto.html", "/verify.html"):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 200, path)
            self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"], path)
            r.close()
        self.assertEqual(self.c.get("/api/health").get_json(), {"status": "ok"})


class SimulatedVercelTests(unittest.TestCase):
    """Import run:app in a fresh process with VERCEL=1, as Vercel does."""

    def test_vercel_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = os.path.join(tmp, "readonly-area")
            code = (
                "import json, os\n"
                "from run import app\n"
                "c = app.test_client()\n"
                "r = c.get('/api/health')\n"
                "out = {'home': c.get('/').status_code, 'health': r.status_code,\n"
                "       'history': c.get('/api/history').status_code,\n"
                "       'cookie_secure': app.config['COOKIE_SECURE'],\n"
                "       'db_dir_created': os.path.exists(os.environ['STACK_DB_PATH'].rsplit(os.sep, 1)[0])}\n"
                "print(json.dumps(out))\n"
            )
            env = dict(os.environ, VERCEL="1", STACK_DB_PATH=os.path.join(db_dir, "h.db"))
            for k in ("STACK_HISTORY_ENABLED", "STACK_COOKIE_SECURE"):
                env.pop(k, None)
            res = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True,
                                 timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)
            out = json.loads(res.stdout.strip().splitlines()[-1])
            self.assertEqual(out, {"home": 200, "health": 200, "history": 503, "cookie_secure": True,
                                   "db_dir_created": False})


if __name__ == "__main__":
    unittest.main()
