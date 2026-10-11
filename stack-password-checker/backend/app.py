"""Stack Password Checking and Hashing - Flask application.

Privacy design
--------------
* The website analyzes passwords in the browser. It never sends a password to this server.
* Text/file encryption, decryption and hashing also run only in the browser (Web Crypto API). This server has
  no endpoint that receives plaintext, encryption passwords, keys or file contents.
* The server stores history SUMMARIES only (level, score, checks passed, length) in SQLite.
* POST /api/history rejects any field it does not expect, so a password cannot be stored by accident.
* POST /api/analyze exists for scripts/tools. It does not log or store the password, but it does
  receive it, so only use it locally or over HTTPS. Disable with STACK_ENABLE_ANALYZE_API=0.
"""
from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from secrets import token_urlsafe

from flask import Flask, g, jsonify, request, send_from_directory

from . import database as db
from .analyzer import analyze
from .config import Config

CLIENT_COOKIE = "stack_cid"
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
LEVELS = {"weak", "medium", "strong"}
HISTORY_FIELDS = {"level", "score", "passed", "length"}

# No inline scripts and no third-party scripts, so nothing outside this site can read what you type.
# worker-src: the streaming file-hash worker. img-src blob:: local previews of images you select.
# connect-src 'self': the page can only talk to this server (history summaries), never to other sites.
CSP = ("default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class RateLimiter:
    """Small in-memory sliding-window limiter (per process). Use a shared store if you run many workers."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, bucket: str, ip: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, ip)]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 10000:  # keep memory bounded
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > window]:
                    self._hits.pop(k, None)
            return True


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def create_app(overrides: dict | None = None) -> Flask:
    cfg = Config()
    app = Flask(__name__, static_folder=cfg.FRONTEND_DIR, static_url_path="")
    app.config.from_object(cfg)
    if overrides:
        app.config.update(overrides)
    if app.config["HISTORY_ENABLED"]:
        db.init_db(app.config["DB_PATH"])
    limiter = RateLimiter()

    # ---------- helpers ----------
    def get_con():
        if "db" not in g:
            g.db = db.connect(app.config["DB_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_con(_exc):
        con = g.pop("db", None)
        if con is not None:
            con.close()

    def error(status: int, message: str):
        return jsonify({"error": message}), status

    def limited(bucket: str, limit: int):
        if app.config["RATE_LIMIT_ENABLED"] and not limiter.allow(bucket, request.remote_addr or "?", limit):
            return error(429, "Too many requests. Please slow down.")
        return None

    # ---------- request hooks ----------
    @app.before_request
    def api_guards():
        if not request.path.startswith("/api/"):
            return None
        g.client_id = None
        cookie = request.cookies.get(CLIENT_COOKIE, "")
        if CLIENT_ID_RE.match(cookie):
            g.client_id = cookie
        else:
            g.new_client_id = token_urlsafe(18)
            g.client_id = g.new_client_id
        if request.path.startswith("/api/history") and not app.config["HISTORY_ENABLED"]:
            # No server database on this deployment (e.g. Vercel). The website falls back to browser storage.
            return error(503, "Server-side history is not enabled on this deployment.")
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("Origin")
            if origin and origin.split("://", 1)[-1] != request.host:
                return error(403, "Cross-origin requests are not allowed.")
        return None

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
            new_id = g.get("new_client_id")
            if new_id:
                resp.set_cookie(CLIENT_COOKIE, new_id, max_age=60 * 60 * 24 * 365, httponly=True,
                                samesite="Lax", secure=app.config["COOKIE_SECURE"])
        return resp

    # ---------- pages ----------
    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    # ---------- API ----------
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.get("/api/history")
    def list_history():
        return jsonify({"items": db.list_history(get_con(), g.client_id)})

    @app.post("/api/history")
    def add_history():
        if (r := limited("write", app.config["WRITE_PER_MIN"])):
            return r
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return error(400, "Send a JSON object.")
        if set(body) != HISTORY_FIELDS:
            # Never echo field names or values back: a stray 'password' field must not be reflected or kept.
            return error(400, "Body must contain exactly: level, score, passed, length.")
        level, score, passed, length = (body[k] for k in ("level", "score", "passed", "length"))
        if level not in LEVELS or not all(_is_int(v) for v in (score, passed, length)):
            return error(400, "Invalid field types or level.")
        if not (0 <= score <= 100 and 0 <= passed <= 5 and 1 <= length <= 128):
            return error(400, "A value is out of range.")
        item = db.add_record(get_con(), g.client_id, level, score, passed, length, app.config["MAX_HISTORY"])
        return jsonify({"item": item}), 201

    @app.delete("/api/history/<rec_id>")
    def delete_history(rec_id: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", rec_id):
            return error(400, "Invalid id.")
        if not db.delete_record(get_con(), g.client_id, rec_id):
            return error(404, "Record not found.")
        return "", 204

    @app.delete("/api/history")
    def clear_history():
        db.clear_history(get_con(), g.client_id)
        return "", 204

    @app.post("/api/analyze")
    def analyze_api():
        if not app.config["ENABLE_ANALYZE_API"]:
            return error(404, "Not found.")
        if (r := limited("analyze", app.config["ANALYZE_PER_MIN"])):
            return r
        body = request.get_json(silent=True)
        pw = body.get("password") if isinstance(body, dict) else None
        if not isinstance(pw, str):
            return error(400, 'Send JSON like {"password": "..."}.')
        if len(pw) > app.config["MAX_PASSWORD_LENGTH"]:
            return error(400, f"Password is longer than {app.config['MAX_PASSWORD_LENGTH']} characters.")
        return jsonify(analyze(pw))

    # ---------- errors ----------
    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api/"):
            return error(404, "Not found.")
        return "Not found", 404

    @app.errorhandler(405)
    def bad_method(_e):
        return error(405, "Method not allowed.")

    @app.errorhandler(413)
    def too_big(_e):
        return error(413, "Request too large.")

    @app.errorhandler(500)
    def server_error(_e):
        return error(500, "Server error.")

    return app
