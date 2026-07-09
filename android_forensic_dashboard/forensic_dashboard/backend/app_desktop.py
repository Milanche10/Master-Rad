"""
app_desktop.py — Ulazna tačka za spakovanu (PyInstaller/MSI) desktop aplikaciju.
─────────────────────────────────────────────────────────────────────────────
Pokreće ugrađeni uvicorn server (FastAPI servira i UI iz ../build) i otvara
pregledač na http://127.0.0.1:8000. Kada je aplikacija instalirana u Program
Files (read-only), podaci slučajeva/audit se čuvaju u KORISNIČKI-UPISIVOM
folderu (%LOCALAPPDATA%\\AndroidForensicDashboard), NE u instalacionom.

Bitno: promenljive okruženja se postavljaju PRE importa 'main' (jer case_store
čita AFD_CASES_DIR pri importu).
"""

import os
import sys
import time
import threading
import webbrowser
from pathlib import Path

# Windows konzola je često cp1252 → srpska slova u print-u bi oborila app.
# Prebaci stdout/stderr na UTF-8 (bez rušenja ako nije podržano).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Korisnički-upisiv folder za podatke (slučajevi, audit) ────────────────
if sys.platform.startswith("win"):
    _DATA = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "AndroidForensicDashboard"
elif sys.platform == "darwin":
    _DATA = Path.home() / "Library" / "Application Support" / "AndroidForensicDashboard"
else:
    _DATA = Path.home() / ".android_forensic_dashboard"

os.environ.setdefault("AFD_CASES_DIR", str(_DATA / "cases"))
try:
    (_DATA / "cases").mkdir(parents=True, exist_ok=True)
except Exception:
    pass

HOST = os.environ.get("AFD_HOST", "127.0.0.1")
PORT = int(os.environ.get("AFD_PORT", "8000"))


def _open_browser():
    time.sleep(2.5)
    try:
        webbrowser.open(f"http://{HOST}:{PORT}")
    except Exception:
        pass


def main():
    # Import tek ovde — posle podešavanja env-a.
    import uvicorn
    from main import app  # noqa: F401  (FastAPI app; servira i UI iz ../build)

    print("=" * 56)
    print("  Android Forensic Dashboard")
    print(f"  Otvori u pregledacu: http://{HOST}:{PORT}")
    print("  (zatvori ovaj prozor za zaustavljanje aplikacije)")
    print("=" * 56)

    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
