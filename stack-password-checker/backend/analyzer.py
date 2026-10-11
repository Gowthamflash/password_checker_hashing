"""Password strength analysis (Python port of the browser analyzer in frontend/js/script.js).

Keep the two implementations in sync if you change the rules. tests/test_parity.py compares them.

Run as a CLI (password is read with getpass, never from argv, so it stays out of shell history):
    python -m backend.analyzer
"""
from __future__ import annotations

import math
import re
import unicodedata

COMMON = frozenset((
    "password,123456,12345678,123456789,qwerty,abc123,letmein,monkey,dragon,football,iloveyou,admin,welcome,login,"
    "princess,sunshine,master,shadow,superman,trustno1,baseball,passw0rd,whatever,hello,freedom,starwars,batman,access,flower,111111,000000,"
    "123123,654321,1q2w3e4r,qazwsx,zaq12wsx,michael,jordan,harley,hunter,ranger,soccer,summer,winter,spring,autumn,secret,changeme,welcome1,"
    "pokemon,cookie,charlie,mustang,computer,internet,test,guest,root,pass,stack,qwertyuiop,asdfghjkl,iloveu,biteme,lovely,ashley,bailey"
).split(","))

LEET = {"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "1": "i", "!": "i"}
ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _round(x: float) -> int:
    """JavaScript-style Math.round (halves go up), so results match the browser."""
    return math.floor(x + 0.5)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _is_common(pw: str) -> bool:
    lower = pw.lower()
    leet = "".join(LEET.get(c, c) for c in lower)

    def trim(s: str) -> str:
        return re.sub(r"^[^a-z]+", "", re.sub(r"[^a-z]+$", "", s))

    return any(s and s in COMMON for s in (lower, leet, trim(lower), trim(leet)))


def _has_sequence(pw: str) -> bool:
    s = pw.lower()
    for i in range(len(s) - 2):
        a, b, c = ord(s[i]), ord(s[i + 1]), ord(s[i + 2])
        if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
            return True
    for row in ROWS:
        for i in range(len(row) - 3):
            w = row[i:i + 4]
            if w in s or w[::-1] in s:
                return True
    return False


def guess_time(bits: float) -> str:
    try:
        sec = (2.0 ** bits) / 2 / 1e10
    except OverflowError:
        return "billions of years"
    if sec < 1:
        return "under a second"
    if sec < 60:
        return _plural(_round(sec), "second")
    minutes = sec / 60
    if minutes < 60:
        return _plural(_round(minutes), "minute")
    hours = minutes / 60
    if hours < 24:
        return _plural(_round(hours), "hour")
    days = hours / 24
    if days < 30:
        return _plural(_round(days), "day")
    if days < 365:
        return _plural(_round(days / 30.44), "month")
    years = days / 365.25
    if years < 100:
        return _plural(_round(years), "year")
    if years < 1e3:
        return "centuries"
    if years < 1e6:
        return "thousands of years"
    if years < 1e9:
        return "millions of years"
    return "billions of years"


def analyze(pw: str) -> dict:
    """Return a strength report. The password itself is never included in the result."""
    n = len(pw)
    cats = [unicodedata.category(c) for c in pw]
    has = {
        "upper": "Lu" in cats,
        "lower": "Ll" in cats,
        "num": "Nd" in cats,
        "special": any(c[0] not in ("L", "N") for c in cats),
    }
    checks = [n >= 12, has["upper"], has["lower"], has["num"], has["special"]]
    passed = sum(checks)
    classes = sum(has.values())
    if n == 0:
        return {"length": 0, "score": 0, "level": "none", "label": "—", "checks": checks, "passed": 0,
                "classes": 0, "has": has, "warnings": [], "entropy_bits": 0, "guess_time": "—"}

    warn = []
    if _is_common(pw):
        warn.append("common")
    if re.search(r"(.)\1{2,}", pw):
        warn.append("repeat")
    if _has_sequence(pw):
        warn.append("seq")
    if re.search(r"(19|20)[0-9]{2}\Z", pw):
        warn.append("year")
    if re.match(r"(.{2,6})\1+\Z", pw):
        warn.append("block")

    uniq = len(set(pw))
    score = passed * 12 + min(30, max(0, n - 4) * 2.5) + min(10, (uniq / n) * 10)
    if "repeat" in warn:
        score -= 10
    if "seq" in warn:
        score -= 10
    if "year" in warn:
        score -= 8
    if "block" in warn:
        score -= 25
    if uniq == 1:
        score = min(score, 5)
    if "common" in warn:
        score = min(score, 12)
    if n < 8:
        score = min(score, 39)
    if passed < 5:
        score = min(score, 74)
    score = max(0, min(100, _round(score)))

    level = "weak" if score < 40 else "medium" if score < 75 else "strong"
    pool = ((26 if has["lower"] else 0) + (26 if has["upper"] else 0)
            + (10 if has["num"] else 0) + (33 if has["special"] else 0)) or 10
    bits = n * math.log2(pool)
    if "common" in warn:
        bits = min(bits, 14)
    elif warn:
        bits *= 0.75
    bits = _round(bits)

    return {"length": n, "score": score, "level": level, "label": level.upper(), "checks": checks,
            "passed": passed, "classes": classes, "has": has, "warnings": warn,
            "entropy_bits": bits, "guess_time": guess_time(bits)}


def _main() -> None:  # pragma: no cover - interactive helper
    import getpass
    r = analyze(getpass.getpass("Password (hidden): "))
    print(f"\nStrength : {r['label']}\nScore    : {r['score']}/100\nLength   : {r['length']}")
    print(f"Checks   : {r['passed']}/5 passed  (12+ chars, upper, lower, number, special)")
    print(f"Entropy  : ~{r['entropy_bits']} bits\nGuess    : {r['guess_time']} (rough estimate)")
    if r["warnings"]:
        print("Warnings :", ", ".join(r["warnings"]))


if __name__ == "__main__":
    _main()
