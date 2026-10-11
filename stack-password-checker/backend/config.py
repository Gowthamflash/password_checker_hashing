"""Central configuration. Override any value with an environment variable."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


# Vercel sets VERCEL=1 at build and run time. Its deployed filesystem is read-only (only /tmp is
# writable, and /tmp is not shared between instances or kept between cold starts).
ON_VERCEL = bool(os.environ.get("VERCEL"))


class Config:
    # --- server ---
    HOST = os.environ.get("STACK_HOST", "127.0.0.1")
    PORT = int(os.environ.get("STACK_PORT", "5000"))
    DEBUG = _flag("STACK_DEBUG", "0")

    # --- paths ---
    FRONTEND_DIR = str(BASE_DIR / "frontend")
    DB_PATH = os.environ.get("STACK_DB_PATH", str(BASE_DIR / "data" / "history.db"))

    # --- history ---
    MAX_HISTORY = int(os.environ.get("STACK_MAX_HISTORY", "30"))  # records kept per browser
    # Server-side (SQLite) history. On Vercel it is OFF by default because SQLite cannot persist there;
    # the history API then answers 503 and the website keeps history in the browser (localStorage).
    HISTORY_ENABLED = _flag("STACK_HISTORY_ENABLED", "0" if ON_VERCEL else "1")

    # --- analysis ---
    MAX_PASSWORD_LENGTH = 128
    # POST /api/analyze is for scripts and tools. The website does NOT use it
    # (the browser analyzes locally). Set to 0 to switch it off completely.
    ENABLE_ANALYZE_API = _flag("STACK_ENABLE_ANALYZE_API", "1")

    # --- security ---
    COOKIE_SECURE = _flag("STACK_COOKIE_SECURE", "1" if ON_VERCEL else "0")  # set to 1 when served over HTTPS (default on Vercel)
    MAX_CONTENT_LENGTH = 4096  # bytes; requests here are tiny
    RATE_LIMIT_ENABLED = _flag("STACK_RATE_LIMIT", "1")
    ANALYZE_PER_MIN = int(os.environ.get("STACK_ANALYZE_PER_MIN", "60"))
    WRITE_PER_MIN = int(os.environ.get("STACK_WRITE_PER_MIN", "120"))
