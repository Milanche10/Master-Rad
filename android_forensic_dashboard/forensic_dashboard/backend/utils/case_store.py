"""
case_store.py — Persistent Multi-Case Store (P0)
────────────────────────────────────────────────
Lokalna, trajna baza slučajeva. Zamenjuje in-memory SESSIONS dict koji se
gubio na restart. Sve na disku, bez cloud-a.

Struktura na disku (default backend/cases/, env AFD_CASES_DIR):
  cases/
    cases.db                      SQLite: cases, runs, module_results, errors
    <case_id>/<run_id>/<mod>.json snapshot rezultata svakog modula (immutable)

Model:
  - Case  : jedna istraga (case_number, title, examiner).
  - Run   : jedan analitički prolaz nad dump-om (immutable). input_fingerprint
            + result_hash omogućavaju "isti ulaz → isti izlaz" proveru.
  - Svaki rerun je NOVI run — prethodni ostaju netaknuti (versioning).

Konkurentnost: SQLite sa check_same_thread=False + kratke transakcije.
"""

import os
import json
import time
import uuid
import sqlite3
import threading
from pathlib import Path

CASES_DIR = Path(os.environ.get("AFD_CASES_DIR", Path(__file__).resolve().parent.parent / "cases"))
_DB_PATH = CASES_DIR / "cases.db"
_LOCK = threading.Lock()
_conn = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _connect():
    global _conn
    if _conn is not None:
        return _conn
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY, case_number TEXT, title TEXT,
            examiner TEXT, created_at TEXT, status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY, case_id TEXT, dump_path TEXT,
            input_fingerprint TEXT, tool_version TEXT, result_hash TEXT,
            created_at TEXT, status TEXT DEFAULT 'completed'
        );
        CREATE TABLE IF NOT EXISTS module_results (
            run_id TEXT, module TEXT, status TEXT, artifact_count INTEGER,
            alert_count INTEGER, path TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS errors (
            run_id TEXT, module TEXT, exc_type TEXT, message TEXT,
            traceback TEXT, ts TEXT
        );
    """)
    _conn.commit()
    return _conn


# ─── CASES ────────────────────────────────────────────────────────────────

def create_case(case_number: str = "", title: str = "", examiner: str = "") -> dict:
    case_id = "case_" + uuid.uuid4().hex[:12]
    row = (case_id, case_number, title, examiner, _now(), "active")
    with _LOCK:
        _connect().execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?)", row)
        _connect().commit()
    return {"case_id": case_id, "case_number": case_number, "title": title,
            "examiner": examiner, "created_at": row[4], "status": "active"}


def get_case(case_id: str):
    with _LOCK:
        r = _connect().execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    return dict(r) if r else None


def list_cases() -> list:
    with _LOCK:
        rows = _connect().execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def archive_case(case_id: str):
    with _LOCK:
        _connect().execute("UPDATE cases SET status='archived' WHERE case_id=?", (case_id,))
        _connect().commit()


# ─── RUNS ─────────────────────────────────────────────────────────────────

def save_run(case_id: str, dump_path: str, results: dict,
             input_fingerprint: str = "", tool_version: str = "1.0",
             result_hash: str = "") -> str:
    """
    Perzistuj jedan analitički prolaz. Snapshot svakog modula ide u zaseban
    JSON fajl (immutable). Vraća run_id.
    """
    run_id = "run_" + uuid.uuid4().hex[:12]
    run_dir = CASES_DIR / case_id / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with _LOCK:
        c = _connect()
        c.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
                  (run_id, case_id, dump_path, input_fingerprint, tool_version,
                   result_hash, _now(), "completed"))
        for module, data in (results or {}).items():
            snap = run_dir / f"{module}.json"
            try:
                snap.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            c.execute("INSERT INTO module_results VALUES (?,?,?,?,?,?,?)",
                      (run_id, module, data.get("status", "?"),
                       len(data.get("artifacts") or []), len(data.get("alerts") or []),
                       str(snap), _now()))
        c.commit()
    return run_id


def list_runs(case_id: str) -> list:
    with _LOCK:
        rows = _connect().execute(
            "SELECT * FROM runs WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall()
    return [dict(r) for r in rows]


def load_run_results(run_id: str) -> dict:
    """Rehidratacija rezultata iz snapshot fajlova."""
    with _LOCK:
        rows = _connect().execute(
            "SELECT module, path FROM module_results WHERE run_id=?", (run_id,)).fetchall()
    out = {}
    for r in rows:
        try:
            out[r["module"]] = json.loads(Path(r["path"]).read_text(encoding="utf-8"))
        except Exception:
            continue
    return out


def save_error(run_id: str, module: str, exc_type: str, message: str, tb: str = ""):
    with _LOCK:
        _connect().execute("INSERT INTO errors VALUES (?,?,?,?,?,?)",
                           (run_id, module, exc_type, message, tb, _now()))
        _connect().commit()


def list_errors(run_id: str) -> list:
    with _LOCK:
        rows = _connect().execute("SELECT * FROM errors WHERE run_id=?", (run_id,)).fetchall()
    return [dict(r) for r in rows]
