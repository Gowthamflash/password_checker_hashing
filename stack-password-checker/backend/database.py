"""Tiny SQLite layer. Stores ONLY analysis summaries, never passwords."""
from __future__ import annotations

import secrets
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id           TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    ts           INTEGER NOT NULL,          -- milliseconds since epoch (set by the server)
    level        TEXT NOT NULL CHECK (level IN ('weak','medium','strong')),
    score        INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    passed       INTEGER NOT NULL CHECK (passed BETWEEN 0 AND 5),
    length_chars INTEGER NOT NULL CHECK (length_chars BETWEEN 1 AND 128)
);
CREATE INDEX IF NOT EXISTS idx_history_client ON history (client_id, ts DESC);
"""


def connect(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(path, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = connect(path)
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()


def _row(r: sqlite3.Row) -> dict:
    return {"id": r["id"], "ts": r["ts"], "level": r["level"], "score": r["score"],
            "passed": r["passed"], "length": r["length_chars"]}


def list_history(con: sqlite3.Connection, client_id: str) -> list[dict]:
    rows = con.execute("SELECT * FROM history WHERE client_id=? ORDER BY ts DESC, rowid DESC", (client_id,))
    return [_row(r) for r in rows]


def add_record(con: sqlite3.Connection, client_id: str, level: str, score: int, passed: int,
               length: int, max_records: int) -> dict:
    rec_id = secrets.token_urlsafe(8)
    ts = int(time.time() * 1000)
    con.execute("INSERT INTO history (id, client_id, ts, level, score, passed, length_chars) VALUES (?,?,?,?,?,?,?)",
                (rec_id, client_id, ts, level, score, passed, length))
    con.execute(
        "DELETE FROM history WHERE client_id=? AND id NOT IN "
        "(SELECT id FROM history WHERE client_id=? ORDER BY ts DESC, rowid DESC LIMIT ?)",
        (client_id, client_id, max_records))
    con.commit()
    return {"id": rec_id, "ts": ts, "level": level, "score": score, "passed": passed, "length": length}


def delete_record(con: sqlite3.Connection, client_id: str, rec_id: str) -> bool:
    cur = con.execute("DELETE FROM history WHERE client_id=? AND id=?", (client_id, rec_id))
    con.commit()
    return cur.rowcount > 0


def clear_history(con: sqlite3.Connection, client_id: str) -> int:
    cur = con.execute("DELETE FROM history WHERE client_id=?", (client_id,))
    con.commit()
    return cur.rowcount
