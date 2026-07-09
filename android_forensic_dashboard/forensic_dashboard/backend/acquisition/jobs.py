"""
jobs.py — Asinhroni menadžer akvizicionih poslova
──────────────────────────────────────────────────
Duge operacije (kopiranje SD/USB, adb pull) rade u pozadinskoj niti da UI
ostane responzivan. Svaki posao ima: progres %, poruku, žive logove, status,
i podršku za OTKAZIVANJE. Endpointi anketiraju stanje (/api/acquire/job/{id}).

In-memory (kao i SESSIONS) — poslovi su vezani za tekuće pokretanje aplikacije;
sam dokazni materijal (Evidence/, manifest, logovi) je trajno na disku.
"""

import threading
import traceback
from datetime import datetime, timezone

JOBS: dict = {}
_LOCK = threading.Lock()
MAX_LOG_LINES = 500


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Progress:
    """Prosleđuje se target funkciji; ona javlja napredak i proverava otkazivanje."""

    def __init__(self, job_id: str):
        self.job_id = job_id

    def update(self, pct: int, message: str = ""):
        with _LOCK:
            j = JOBS.get(self.job_id)
            if not j:
                return
            j["progress"] = max(0, min(100, int(pct)))
            if message:
                j["message"] = message

    def log(self, message: str):
        with _LOCK:
            j = JOBS.get(self.job_id)
            if not j:
                return
            j["logs"].append(f"[{_now()}] {message}")
            if len(j["logs"]) > MAX_LOG_LINES:
                # zadrži prvih 50 (početak) + poslednjih (MAX-50) radi konteksta
                j["logs"] = j["logs"][:50] + j["logs"][-(MAX_LOG_LINES - 50):]

    def cancelled(self) -> bool:
        with _LOCK:
            j = JOBS.get(self.job_id)
            return bool(j and j.get("cancel"))


def start_job(source: str, target, **kwargs) -> str:
    """
    Pokreni posao u pozadinskoj niti. `target(progress, **kwargs) -> dict`.
    Sve iz kwargs (uklj. examiner) prosleđuje se target funkciji. Rezultat se
    snima u job['result']; izuzetak → status 'error'. Vraća job_id.
    """
    job_id = "job_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    with _LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "source": source,
            "examiner": kwargs.get("examiner", ""),
            "status": "running",   # running | done | error | cancelled
            "progress": 0,
            "message": "Pokretanje akvizicije…",
            "logs": [f"[{_now()}] Posao {job_id} pokrenut (izvor: {source})."],
            "result": None,
            "error": None,
            "case_id": None,
            "started_at": _now(),
            "finished_at": None,
            "cancel": False,
        }
    progress = Progress(job_id)

    def _run():
        try:
            result = target(progress, **kwargs)
            with _LOCK:
                j = JOBS.get(job_id)
                if not j:
                    return
                if j.get("cancel"):
                    j["status"] = "cancelled"
                    j["message"] = "Akvizicija otkazana."
                else:
                    j["status"] = "done"
                    j["progress"] = 100
                    j["message"] = "Akvizicija završena."
                    j["result"] = result
                    if isinstance(result, dict):
                        j["case_id"] = result.get("case_id")
                j["finished_at"] = _now()
        except Exception as e:
            with _LOCK:
                j = JOBS.get(job_id)
                if j:
                    j["status"] = "error"
                    j["error"] = str(e)
                    j["message"] = f"Greška: {e}"
                    j["logs"].append(f"[{_now()}] GREŠKA: {e}")
                    j["logs"].append(traceback.format_exc())
                    j["finished_at"] = _now()

    threading.Thread(target=_run, daemon=True, name=job_id).start()
    return job_id


def get_job(job_id: str, log_tail: int = 100) -> dict | None:
    with _LOCK:
        j = JOBS.get(job_id)
        if not j:
            return None
        out = {k: v for k, v in j.items() if k != "logs"}
        out["logs"] = j["logs"][-log_tail:]
        out["log_count"] = len(j["logs"])
    return out


def cancel_job(job_id: str) -> bool:
    with _LOCK:
        j = JOBS.get(job_id)
        if not j:
            return False
        if j["status"] == "running":
            j["cancel"] = True
            j["message"] = "Otkazivanje zatraženo…"
            j["logs"].append(f"[{_now()}] Otkazivanje zatraženo od korisnika.")
            return True
    return False


def list_jobs() -> list:
    with _LOCK:
        return [{k: v for k, v in j.items() if k != "logs"} for j in JOBS.values()]
