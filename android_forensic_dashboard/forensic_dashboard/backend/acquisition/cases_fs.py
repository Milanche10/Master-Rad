"""
cases_fs.py — Filesystem scaffold forenzičkog slučaja (Evidence Management Layer)
──────────────────────────────────────────────────────────────────────────────
Svaka akvizicija pravi slučaj na disku po fiksnoj strukturi:

  Case_2026_0001/
    Evidence/
      Device/ Files/ Media/ Documents/ SMS/ Contacts/
      CallLogs/ Applications/ Metadata/ SIM/ SDCard/ USB/
    Analysis/
    Reports/
    Exports/
    Logs/
    case.json           ← metapodaci slučaja (ID, datum, izvor, uređaj, veštak)

Root svih slučajeva: env AFD_EVIDENCE_DIR, inače %LOCALAPPDATA%/AndroidForensicDashboard/cases_fs
(uvek upisiv folder — NE Program Files, gde spakovana .exe aplikacija ne sme da piše).

Napomena: `Evidence/` je namerno u Android-FS-kompatibilnom rasporedu za telefon
(data/data/..., data/media/0/...), pa POSTOJEĆI DumpResolver/analitički engine
radi nad `Evidence/` bez ikakve izmene. Za SIM/SD/USB koristi se poddirektorijum
(SIM/ SDCard/ USB/) — ti izvori imaju i sopstvene, namenske izveštaje.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def _evidence_root() -> Path:
    env = os.environ.get("AFD_EVIDENCE_DIR")
    if env:
        return Path(env)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "AndroidForensicDashboard" / "cases_fs"
    # Linux/macOS fallback
    return Path(os.environ.get("AFD_CASES_DIR", Path.home() / ".afd")) / "cases_fs"


EVIDENCE_ROOT = _evidence_root()

# Poddirektorijumi svakog slučaja (spec-kompatibilno + dodatni izvori)
CASE_SUBDIRS = [
    "Evidence/Device",
    "Evidence/Files",
    "Evidence/Media",
    "Evidence/Documents",
    "Evidence/SMS",
    "Evidence/Contacts",
    "Evidence/CallLogs",
    "Evidence/Applications",
    "Evidence/Metadata",
    "Evidence/SIM",
    "Evidence/SDCard",
    "Evidence/USB",
    "Analysis",
    "Reports",
    "Exports",
    "Logs",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def allocate_case_id(when=None) -> str:
    """
    Sledeći ID oblika Case_<GODINA>_<NNNN>. Skenira postojeće foldere i
    inkrementira redni broj za tekuću godinu (deterministički, bez preskoka).
    `when` (datetime) se može proslediti radi determinizma u testovima.
    """
    year = (when or datetime.now(timezone.utc)).strftime("%Y")
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    prefix = f"Case_{year}_"
    max_n = 0
    try:
        for d in EVIDENCE_ROOT.iterdir():
            if d.is_dir() and d.name.startswith(prefix):
                tail = d.name[len(prefix):]
                if tail.isdigit():
                    max_n = max(max_n, int(tail))
    except Exception:
        pass
    return f"{prefix}{max_n + 1:04d}"


def case_dir(case_id: str) -> Path:
    return EVIDENCE_ROOT / case_id


def create_case_folder(source: str, examiner: str = "", device_info: dict = None,
                       case_id: str = None, when=None) -> dict:
    """
    Napravi kompletan folder slučaja i case.json. Vraća putanje + metapodatke.
    `source` je jedan od: mobile, sim, sdcard, usb, dump.
    """
    cid = case_id or allocate_case_id(when=when)
    root = case_dir(cid)
    for sub in CASE_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)

    meta = {
        "case_id": cid,
        "source": source,
        "examiner": examiner or "nepoznat",
        "device_info": device_info or {},
        "created_at": now_iso(),
        "evidence_path": str(root / "Evidence"),
        "reports_path": str(root / "Reports"),
        "exports_path": str(root / "Exports"),
        "logs_path": str(root / "Logs"),
        "status": "acquiring",
        "hashes": {},          # popunjava se posle (manifest summary)
        "history": [{"ts": now_iso(), "event": "case_created", "source": source}],
    }
    write_case_meta(cid, meta)
    append_log(cid, f"Slučaj {cid} kreiran (izvor: {source}, veštak: {meta['examiner']}).")
    return meta


def meta_path(case_id: str) -> Path:
    return case_dir(case_id) / "case.json"


def write_case_meta(case_id: str, meta: dict):
    try:
        meta_path(case_id).write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def read_case_meta(case_id: str) -> dict | None:
    try:
        return json.loads(meta_path(case_id).read_text(encoding="utf-8"))
    except Exception:
        return None


def update_case_meta(case_id: str, **fields) -> dict | None:
    meta = read_case_meta(case_id)
    if meta is None:
        return None
    meta.update(fields)
    hist = meta.setdefault("history", [])
    hist.append({"ts": now_iso(), "event": "updated", "fields": list(fields.keys())})
    write_case_meta(case_id, meta)
    return meta


def append_log(case_id: str, message: str):
    """Dodaj red u Logs/acquisition.log (chain-of-custody trag akvizicije)."""
    try:
        log = case_dir(case_id) / "Logs" / "acquisition.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"[{now_iso()}] {message}\n")
    except Exception:
        pass


def list_fs_cases() -> list:
    """Svi slučajevi na disku (za central case manager)."""
    out = []
    try:
        for d in sorted(EVIDENCE_ROOT.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            m = read_case_meta(d.name)
            if m:
                out.append({
                    "case_id": m.get("case_id"),
                    "source": m.get("source"),
                    "examiner": m.get("examiner"),
                    "created_at": m.get("created_at"),
                    "status": m.get("status"),
                    "device": (m.get("device_info") or {}).get("model")
                              or (m.get("device_info") or {}).get("name"),
                    "path": str(d),
                })
    except Exception:
        pass
    return out
