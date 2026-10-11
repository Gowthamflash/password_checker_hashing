"""The 9-item navigation: every entry exists, and every target page or anchor exists."""
import re
import unittest
from pathlib import Path

FRONT = Path(__file__).resolve().parent.parent / "frontend"
EXPECTED = ["Dashboard", "Checker", "Text Crypto", "Hash", "File Hash", "File Crypto", "Verify", "History",
            "About Security"]


class NavigationTests(unittest.TestCase):
    def test_nav_entries_and_targets(self):
        js = (FRONT / "js" / "common.js").read_text(encoding="utf-8")
        block = js[js.index("const PAGES = ["):js.index("];", js.index("const PAGES = ["))]
        entries = re.findall(r"\['([\w-]+)', '([^']+)', '([^']+)'\]", block)
        self.assertEqual([e[2] for e in entries], EXPECTED)
        for _id, href, label in entries:
            page, _, anchor = href.partition("#")
            html = (FRONT / page).read_text(encoding="utf-8")
            if anchor:
                self.assertIn(f'id="{anchor}"', html, label)


if __name__ == "__main__":
    unittest.main()
