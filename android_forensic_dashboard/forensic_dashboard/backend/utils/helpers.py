"""
helpers.py
──────────
Zajedničke pomoćne funkcije za sve module:
- Konverzija Android timestamp-ova u ISO 8601 UTC
- Standardizovana struktura artefakta i nalaza
- Detekcija Base64, enkripcije i sumnjivih patterna
"""

import base64
import hashlib
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any


# ─── TIMESTAMP KONVERZIJE ─────────────────────────────────────────────────

def ms_to_iso(ms: Optional[int]) -> Optional[str]:
    """Android millisecond epoch → ISO 8601 UTC string."""
    if ms is None or ms == 0:
        return None
    try:
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return None


def sec_to_iso(sec: Optional[int]) -> Optional[str]:
    """Unix seconds epoch → ISO 8601 UTC string."""
    if sec is None or sec == 0:
        return None
    try:
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return None


def chrome_time_to_iso(chrome_ts: Optional[int]) -> Optional[str]:
    """
    Chrome timestamp: microseconds since 1601-01-01.
    Konvertuj u Unix timestamp pa u ISO.
    """
    if chrome_ts is None or chrome_ts == 0:
        return None
    try:
        # Chrome epoch počinje 1601-01-01, Unix epoch 1970-01-01
        # Razlika je 11644473600 sekundi
        unix_us = chrome_ts - 11644473600_000_000
        unix_s = unix_us / 1_000_000
        dt = datetime.fromtimestamp(unix_s, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, OverflowError, ValueError):
        return None


# ─── STRUKTURA ARTEFAKTA ──────────────────────────────────────────────────

def artifact(
    type_: str,
    value: str,
    source: str,
    ts: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    """
    Standardizovana struktura artefakta koji koristi frontend i correlator.

    type_  : comm | call | location | web | crypto | app | media | account | contact
    value  : human-readable opis
    source : putanja do fajla ili naziv baze
    ts     : ISO 8601 timestamp ili None
    extra  : dodatni podaci za correlator (koordinate, adrese, brojevi...)
    """
    result = {
        "type": type_,
        "value": value,
        "source": source,
        "ts": ts,
    }
    if extra:
        result["extra"] = extra
    return result


def finding(key: str, value: str) -> dict:
    """Standardizovana struktura nalaza za prikaz u UI tabeli."""
    return {"key": key, "value": str(value)}


def module_result(
    status: str,
    findings: list,
    artifacts: list,
    alerts: list,
    error: Optional[str] = None,
) -> dict:
    """Standardizovana struktura koju vraća svaki modul."""
    result = {
        "status": status,
        "findings": findings,
        "artifacts": artifacts,
        "alerts": alerts,
    }
    if error:
        result["error"] = error
    return result


def not_found_result(module_name: str, path: str) -> dict:
    """Vraća se kada fajl/baza nije pronađena u dump-u."""
    return module_result(
        status="not_found",
        findings=[finding("Status", f"Fajl nije pronađen: {path}")],
        artifacts=[],
        alerts=[f"{module_name}: artifact not found in dump"],
    )


# ─── DETEKCIJA PATTERNA ───────────────────────────────────────────────────

HHY_PREFIX = "HHY"
BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')


def is_hhy_encrypted(text: str) -> bool:
    """Detektuje HHY+Base64 AES pattern iz OmniNotes modifikacije."""
    if not text or not text.startswith(HHY_PREFIX):
        return False
    rest = text[len(HHY_PREFIX):]
    return bool(BASE64_RE.match(rest.strip()))


def try_decode_hhy(text: str) -> Optional[bytes]:
    """Pokuša dekodiranje HHY poruke, vraća raw bytes (i dalje AES)."""
    if not is_hhy_encrypted(text):
        return None
    try:
        return base64.b64decode(text[len(HHY_PREFIX):].strip())
    except Exception:
        return None


def is_base64(text: str) -> bool:
    """Gruba provera da li je string Base64 enkodiran."""
    if not text or len(text) < 16:
        return False
    return bool(BASE64_RE.match(text.strip()))


def try_decode_jwt(token: str) -> Optional[dict]:
    """
    Dekodira JWT payload (bez verifikacije potpisa).
    Vraća dict sa poljima iz payload-a ili None.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        # JWT koristi URL-safe Base64 bez paddinga
        padding = 4 - len(payload) % 4
        payload += "=" * (padding % 4)
        decoded = base64.urlsafe_b64decode(payload)
        import json
        return json.loads(decoded)
    except Exception:
        return None


def shannon_entropy(data: bytes) -> float:
    """
    Izračunava Shannon entropiju bajtova.
    Visoka entropija (>7.0) ukazuje na enkripciju ili kompresiju.
    """
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    import math
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def sha256_file(path: Path) -> str:
    """SHA-256 hash fajla za verifikaciju integriteta."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ─── GEOLOKACIONI HELPERS ─────────────────────────────────────────────────

def dms_to_decimal(degrees: float, minutes: float, seconds: float, ref: str) -> float:
    """Konverzija GPS DMS → decimalni stepeni."""
    decimal = degrees + minutes / 60 + seconds / 3600
    if ref in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def coords_to_str(lat: float, lon: float) -> str:
    """Formatiraj GPS koordinate za prikaz."""
    lat_dir = "N" if lat >= 0 else "S"
    lon_dir = "E" if lon >= 0 else "W"
    return f"{abs(lat):.4f}°{lat_dir} {abs(lon):.4f}°{lon_dir}"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Rastojanje između dve GPS tačke u kilometrima."""
    import math
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


# ─── TELEFONSKI BROJ HELPERS ──────────────────────────────────────────────

def normalize_phone(number: str) -> str:
    """Ukloni razmake, crtice, zagrade iz broja telefona."""
    if not number:
        return ""
    return re.sub(r"[^\d+]", "", number)


def phone_country(number: str) -> Optional[str]:
    """Gruba detekcija države po prefiksu."""
    prefixes = {
        "+1": "SAD/Kanada",
        "+41": "Švajcarska",
        "+44": "Velika Britanija",
        "+49": "Nemačka",
        "+33": "Francuska",
        "+381": "Srbija",
        "+7": "Rusija",
        "+86": "Kina",
        "+852": "Hong Kong",
    }
    n = normalize_phone(number)
    for prefix, country in sorted(prefixes.items(), key=lambda x: -len(x[0])):
        if n.startswith(prefix):
            return country
    return None
