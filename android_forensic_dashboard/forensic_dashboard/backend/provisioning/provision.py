"""
provision.py — preuzimanje i instalacija runtime zavisnosti iz aplikacije
──────────────────────────────────────────────────────────────────────────
Funkcije ovde su namerno usklađene sa acquisition.jobs.Progress ugovorom
(target(progress, **kwargs) -> dict), pa se instalacija pokreće kao pozadinski
posao sa napretkom, logom i otkazivanjem — isto kao akvizicija.
"""

import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

WINDOWS = sys.platform.startswith("win")
_CREATE_NO_WINDOW = 0x08000000 if WINDOWS else 0

APP_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "AndroidForensicDashboard"
TOOLS_DIR = APP_DIR / "tools"


# ═══════════════════════════════════════════════════════════════════════════
# adb (Android platform-tools)
# ═══════════════════════════════════════════════════════════════════════════

def _adb_name() -> str:
    return "adb.exe" if WINDOWS else "adb"


def _platform_tools_url() -> str:
    if WINDOWS:
        suf = "windows"
    elif sys.platform == "darwin":
        suf = "darwin"
    else:
        suf = "linux"
    return f"https://dl.google.com/android/repository/platform-tools-latest-{suf}.zip"


def bundled_adb() -> Path | None:
    """adb spakovan uz aplikaciju (PyInstaller: _MEIPASS/tools/platform-tools)."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        cand = Path(base) / "tools" / "platform-tools" / _adb_name()
        if cand.exists():
            return cand
    return None


def provisioned_adb() -> Path | None:
    """adb koji je aplikacija ranije sama preuzela u TOOLS_DIR."""
    cand = TOOLS_DIR / "platform-tools" / _adb_name()
    return cand if cand.exists() else None


def find_adb() -> str | None:
    """Nađi adb: spakovan uz app → ranije preuzet → PATH → ANDROID_HOME."""
    for p in (bundled_adb(), provisioned_adb()):
        if p:
            return str(p)
    w = shutil.which("adb")
    if w:
        return w
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(env)
        if base:
            c = Path(base) / "platform-tools" / _adb_name()
            if c.exists():
                return str(c)
    return None


def _download(url: str, dst: Path, progress=None, base_pct=5, span=78):
    req = urllib.request.Request(url, headers={"User-Agent": "AndroidForensicDashboard"})
    with urllib.request.urlopen(req, timeout=90) as r, open(dst, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        while True:
            if progress and progress.cancelled():
                raise RuntimeError("Otkazano od strane korisnika.")
            chunk = r.read(262144)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if progress and total:
                pct = base_pct + int(done / total * span)
                progress.update(min(base_pct + span, pct),
                                f"Preuzeto {done // 1048576} MB / {total // 1048576} MB")


def ensure_adb(progress=None) -> dict:
    """
    Obezbedi adb. Ako već postoji (spakovan/preuzet/PATH) → vrati putanju.
    Inače preuzmi zvanične Google platform-tools i raspakuj u TOOLS_DIR.
    """
    existing = find_adb()
    if existing:
        if progress:
            progress.update(100, "adb je već dostupan.")
            progress.log(f"adb pronađen: {existing}")
        return {"ok": True, "path": existing, "already": True}

    url = _platform_tools_url()
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    zpath = TOOLS_DIR / "platform-tools.zip"
    if progress:
        progress.update(4, "Preuzimanje Android platform-tools (adb)…")
        progress.log(f"Izvor: {url}")
    _download(url, zpath, progress, base_pct=5, span=78)

    if progress:
        progress.update(86, "Raspakivanje platform-tools…")
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(TOOLS_DIR)
    try:
        zpath.unlink()
    except Exception:
        pass

    adb = provisioned_adb()
    if adb and not WINDOWS:
        try:
            os.chmod(adb, 0o755)
        except Exception:
            pass
    if not adb:
        raise RuntimeError("adb nije pronađen posle raspakivanja platform-tools.")
    if progress:
        progress.update(100, "adb je spreman.")
        progress.log(f"adb instaliran: {adb}")
    return {"ok": True, "path": str(adb), "already": False}


# ═══════════════════════════════════════════════════════════════════════════
# Ollama + AI model (za AI zaključak)
# ═══════════════════════════════════════════════════════════════════════════

def _ollama_default_exe() -> Path | None:
    if WINDOWS:
        cand = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Ollama" / "ollama.exe"
        return cand if cand.exists() else None
    return None


def ollama_exe() -> str | None:
    w = shutil.which("ollama")
    if w:
        return w
    d = _ollama_default_exe()
    return str(d) if d else None


def ollama_installed() -> bool:
    return ollama_exe() is not None


def _ollama_host() -> str:
    return os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")


def ollama_running() -> bool:
    try:
        urllib.request.urlopen(_ollama_host() + "/api/tags", timeout=2)
        return True
    except Exception:
        return False


def list_ollama_models() -> list:
    try:
        import json
        with urllib.request.urlopen(_ollama_host() + "/api/tags", timeout=3) as r:
            data = json.loads(r.read())
        return [m.get("name") for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


def ensure_ollama(progress, model: str = "qwen3:32b") -> dict:
    """
    Instaliraj Ollama (ako fali) i preuzmi AI model. Model ume da bude VELIK
    (GB) — poziva se samo na izričit zahtev korisnika. Napredak se čita iz
    izlaza `ollama pull`.
    """
    exe = ollama_exe()
    if not exe:
        if not WINDOWS:
            raise RuntimeError("Automatska instalacija Ollama je podržana na Windows-u. "
                               "Na Linux/macOS instaliraj sa https://ollama.com pa ponovi.")
        progress.update(3, "Preuzimanje Ollama instalera…")
        setup = TOOLS_DIR / "OllamaSetup.exe"
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        _download("https://ollama.com/download/OllamaSetup.exe", setup, progress, base_pct=3, span=30)
        progress.update(35, "Instalacija Ollama (tiho)…")
        progress.log("Pokretanje OllamaSetup.exe /VERYSILENT")
        try:
            subprocess.run([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
                           timeout=900, creationflags=_CREATE_NO_WINDOW)
        except Exception as e:
            raise RuntimeError(f"Instalacija Ollama nije uspela: {e}")
        exe = ollama_exe()
        if not exe:
            raise RuntimeError("Ollama je (verovatno) instaliran, ali izvršni fajl nije pronađen. "
                               "Restartuj aplikaciju ili instaliraj ručno sa https://ollama.com.")
    else:
        progress.log(f"Ollama je već instaliran: {exe}")

    progress.update(45, f"Preuzimanje AI modela '{model}' - VELIKO, moze dugo trajati...")
    progress.log(f"ollama pull {model}")
    try:
        p = subprocess.Popen([exe, "pull", model], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                             errors="replace", creationflags=_CREATE_NO_WINDOW)
    except Exception as e:
        raise RuntimeError(f"Ne mogu da pokrenem 'ollama pull': {e}")

    for line in p.stdout:
        line = (line or "").strip()
        if line:
            progress.log(line)
        if progress.cancelled():
            try:
                p.terminate()
            except Exception:
                pass
            raise RuntimeError("Otkazano od strane korisnika.")
    rc = p.wait()
    if rc != 0:
        raise RuntimeError(f"'ollama pull {model}' nije uspeo (izlazni kod {rc}).")
    progress.update(100, f"AI model '{model}' je spreman.")
    progress.log(f"Model {model} preuzet i spreman za AI zakljucak.")
    return {"ok": True, "model": model, "exe": exe}


# ═══════════════════════════════════════════════════════════════════════════
# Zbirni status (za Setup panel)
# ═══════════════════════════════════════════════════════════════════════════

def status(model: str = None) -> dict:
    model = model or os.environ.get("AI_MODEL", "qwen3:32b")
    adb = find_adb()
    models = list_ollama_models()
    return {
        "platform": sys.platform,
        "adb": {
            "found": adb is not None,
            "path": adb,
            "bundled": bundled_adb() is not None,
            "hint": "" if adb else "Klikni 'Instaliraj adb' - aplikacija preuzme platform-tools.",
        },
        "ollama": {
            "installed": ollama_installed(),
            "running": ollama_running(),
            "exe": ollama_exe(),
            "models": models,
            "model": model,
            "model_ready": model in models,
            "hint": "" if (model in models) else
                    "Klikni 'Instaliraj AI' - preuzima Ollama + model (VELIKO).",
        },
    }
