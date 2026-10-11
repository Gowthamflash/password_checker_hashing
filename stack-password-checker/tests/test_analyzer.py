import unittest

from backend.analyzer import analyze


class AnalyzerTests(unittest.TestCase):
    def test_empty(self):
        r = analyze("")
        self.assertEqual((r["level"], r["score"], r["passed"]), ("none", 0, 0))

    def test_strong(self):
        r = analyze("Blue-Fox#4821x")
        self.assertEqual((r["level"], r["passed"]), ("strong", 5))
        self.assertGreaterEqual(r["score"], 75)

    def test_common_is_weak_even_with_all_classes(self):
        r = analyze("Password123!")
        self.assertEqual(r["level"], "weak")
        self.assertIn("common", r["warnings"])

    def test_short_is_weak(self):
        self.assertEqual(analyze("aB3$")["level"], "weak")

    def test_leet_variant_is_common(self):
        self.assertIn("common", analyze("p@ssw0rd")["warnings"])

    def test_checks(self):
        r = analyze("abcDEF123!!!")
        self.assertEqual(r["checks"], [True, True, True, True, True])

    def test_result_never_contains_password(self):
        r = analyze("Sup3r-Secret#Value")
        self.assertNotIn("Sup3r", repr(r))


if __name__ == "__main__":
    unittest.main()
