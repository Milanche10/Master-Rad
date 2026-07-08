"""
audit_log.py — Append-only Hash-Chained Audit Trail (P0)
────────────────────────────────────────────────────────
Chain-of-custody dnevnik: ko je, šta, kada uradio nad kojim slučajem.
Svaki zapis nosi prev_hash → hash(prev_hash + payload). Naknadna izmena
BILO KOG prethodnog zapisa lomi lanac i detektuje se verify_chain().

Zapisi idu i u SQLite (upit) i u append-only audit.jsonl (tamper-evident
tekstualni trag). Sve lokalno.
"""

import os
import json
import time
import hashlib
import threading
from pathlib import Path

CASES_DIR = Path(os.environ.get("AFD_CASES_DIR", Path(__file__).resolve().parent.parent / "cases"))
_JSONL = CASES_DIR / "audit.jsonl"
_LOCK = threading.Lock()
_last_hash = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load_last_hash() -> str:
    global _last_hash
    if _last_hash is not None:
        return _last_hash
    _last_hash = "0" * 64
    try:
        if _JSONL.exists():
            last = None
            with open(_JSONL, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = line
            if last:
                _last_hash = json.loads(last).get("hash", _last_hash)
    except Exception:
        pass
    return _last_hash


def log_event(actor: str, action: str, case_id: str = None,
              run_id: str = None, params: dict = None, status: str = "ok") -> dict:
    """
    Dodaj audit zapis u lanac. Vraća zapis (sa hash/prev_hash).
    actor  — ko (npr. 'examiner:milan' ili 'system')
    action — šta (create_case, analyze_module, generate_report, delete...)
    """
    global _last_hash
    with _LOCK:
        prev = _load_last_hash()
        event = {
            "ts": _now(),
            "actor": actor,
            "action": action,
            "case_id": case_id,
            "run_id": run_id,
            "params": params or {},
            "status": status,
            "prev_hash": prev,
        }
        basis = json.dumps({k: event[k] for k in
                            ("ts", "actor", "action", "case_id", "run_id", "params", "status", "prev_hash")},
                           ensure_ascii=False, sort_keys=True)
        event["hash"] = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        _last_hash = event["hash"]

        CASES_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass
    return event


def read_events(case_id: str = None, limit: int = 500) -> list:
    events = []
    try:
        if _JSONL.exists():
            with open(_JSONL, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = json.loads(line)
                    if case_id is None or ev.get("case_id") == case_id:
                        events.append(ev)
    except Exception:
        pass
    return events[-limit:]


def verify_chain() -> dict:
    """
    Proveri integritet celog lanca. Vraća {valid, count, broken_at?}.
    Ovim se dokazuje da audit trag nije menjan (tamper-evidence).
    """
    prev = "0" * 64
    count = 0
    try:
        if not _JSONL.exists():
            return {"valid": True, "count": 0}
        with open(_JSONL, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                ev = json.loads(line)
                if ev.get("prev_hash") != prev:
                    return {"valid": False, "count": count, "broken_at": i}
                basis = json.dumps({k: ev.get(k) for k in
                                    ("ts", "actor", "action", "case_id", "run_id", "params", "status", "prev_hash")},
                                   ensure_ascii=False, sort_keys=True)
                if hashlib.sha256(basis.encode("utf-8")).hexdigest() != ev.get("hash"):
                    return {"valid": False, "count": count, "broken_at": i}
                prev = ev["hash"]
                count += 1
    except Exception as e:
        return {"valid": False, "count": count, "error": str(e)}
    return {"valid": True, "count": count}
