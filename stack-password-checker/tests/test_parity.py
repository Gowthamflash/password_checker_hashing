"""Checks that backend/analyzer.py and the browser analyzer in frontend/js/script.js agree.
Skipped automatically when Node.js is not installed."""
import json
import random
import shutil
import string
import subprocess
import unittest
from pathlib import Path

from backend.analyzer import analyze

ROOT = Path(__file__).resolve().parent.parent
JS = (ROOT / "frontend" / "js" / "script.js").read_text(encoding="utf-8")
CODE = JS.split("/*ANALYZER_START*/")[1].split("/*ANALYZER_END*/")[0]


@unittest.skipUnless(shutil.which("node"), "node not installed")
class Parity(unittest.TestCase):
    def test_same_results(self):
        rnd = random.Random(7)
        fixed = ["", "a", "dragon7", "Winter2024", "password", "Password123!", "Blue-Fox#4821x", "aaaaaaaaaaaaaaaa",
                 "abcdefghijkl", "correct horse battery staple", "Tr0ub4dor&3", "qwerty123456", "Aa1!Aa1!Aa1!",
                 "p@ssw0rd", "Zażółć-gęślą-1Jaźń!", "ünïcödé-Pässwörd9", "1234567890123", "xyxyxyxy"]
        pools = [string.ascii_lowercase, string.ascii_letters + string.digits, string.printable.strip()]
        rand = ["".join(rnd.choice(rnd.choice(pools)) for _ in range(rnd.randint(1, 40))) for _ in range(300)]
        cases = fixed + rand
        script = CODE + "\nconst c=JSON.parse(require('fs').readFileSync(0,'utf8'));" \
            "console.log(JSON.stringify(c.map(p=>{const a=analyze(p);return [a.score,a.level,a.passed,a.classes,a.warn.join(','),a.bits,a.time]})));"
        out = subprocess.run(["node", "-e", script], input=json.dumps(cases), capture_output=True, text=True, check=True)
        js = json.loads(out.stdout)
        for pw, j in zip(cases, js):
            r = analyze(pw)
            py = [r["score"], r["level"], r["passed"], r["classes"], ",".join(r["warnings"]), r["entropy_bits"], r["guess_time"]]
            self.assertEqual(py, j, repr(pw))


if __name__ == "__main__":
    unittest.main()
