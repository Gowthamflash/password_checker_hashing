"""Runs the JavaScript unit tests (hashing + encryption libraries) with Node's built-in test runner.
Skipped automatically when Node.js is not installed."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which("node"), "node not installed")
class JsTests(unittest.TestCase):
    def test_node_suite(self):
        files = sorted(str(p) for p in (ROOT / "tests" / "js").glob("*.test.js"))
        r = subprocess.run(["node", "--test", *files], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-1500:])


if __name__ == "__main__":
    unittest.main()
