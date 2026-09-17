"""
capabilities.py — Detekcija uređaja i sposobnosti akvizicije (spec §6–10)
──────────────────────────────────────────────────────────────────────────
Pre nego što se ponudi metoda akvizicije, utvrđuje se ŠTA uređaj zaista
podržava. Detekcija je NEDESTRUKTIVNA i READ-ONLY — nije akvizicija:
  • identifikacija uređaja (getprop),
  • ADB autorizacija,
  • POSTOJEĆI root (samo detekcija — bez eksploita, bez zaobilaženja zaštite),
  • dostupnost metoda: LOGICAL / FILE_SYSTEM / PHYSICAL.

Načelo poštenja (spec §13,§16,§46): metoda se prijavljuje kao AVAILABLE samo
ako stvarno postoji podržan mehanizam. FILE_SYSTEM zahteva root; PHYSICAL nema
univerzalni ADB mehanizam pa je podrazumevano UNAVAILABLE uz jasan razlog.
"""

import re
from dataclasses import dataclass, asdict, field

from . import detect

_PROP_RE = re.compile(r"\[([^\]]+)\]:\s*\[([^\]]*)\]")


# ─── Enumi (spec §10) ───────────────────────────────────────────────────────

class AcquisitionMethod(str):
    LOGICAL = "logical"
    FILE_SYSTEM = "file_system"
    PHYSICAL = "physical"
    AUTO = "auto"


class AcquisitionStatus(str):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


VALID_METHODS = {AcquisitionMethod.LOGICAL, AcquisitionMethod.FILE_SYSTEM,
                 AcquisitionMethod.PHYSICAL, AcquisitionMethod.AUTO}


# ─── Modeli (spec §7,§8) ─────────────────────────────────────────────────────

@dataclass
class AndroidDevice:
    manufacturer: str | None = None
    model: str | None = None
    device: str | None = None
    android_version: str | None = None
    sdk_version: int | None = None
    security_patch: str | None = None
    build_id: str | None = None
    fingerprint: str | None = None
    serial: str | None = None
    adb_state: str | None = None
    adb_authorized: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class DeviceCapabilities:
    adb_available: bool = False
    adb_authorized: bool = False
    root_available: bool = False

    logical_available: bool = False
    filesystem_available: bool = False
    physical_available: bool = False

    root_reason: str | None = None
    logical_reason: str | None = None
    filesystem_reason: str | None = None
    physical_reason: str | None = None

    def to_dict(self):
        return asdict(self)


def _adb_cmd(adb, serial, *args):
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    return cmd + list(args)


# ─── Root detekcija (spec §9) — SAMO postojeći root, bez eksploita ──────────

def detect_root(adb: str, serial: str) -> tuple[bool, str]:
    """
    Detektuje SAMO već prisutan root pristup. Ne pokušava eksploate, ne menja
    boot, ne instalira ništa, ne zaobilazi zaključavanje (spec §9,§46).
    Vraća (root_available, reason).
    """
    # 1) adbd već radi kao root (userdebug/eng build, emulator) — bez prompta
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "shell", "id"), timeout=10)
    if rc == 0 and "uid=0(" in out:
        return True, "adbd radi kao root (uid=0) — file-system akvizicija je moguća."

    # 2) postojeći `su` daje root (Magisk i sl.) — može zatražiti odobrenje na uređaju
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "shell", "su", "-c", "id"), timeout=12)
    if rc == 0 and "uid=0(" in out:
        return True, "root dostupan preko 'su' (uid=0)."

    # 3) `su` binarni postoji ali ne daje root bez odobrenja → NIJE potvrđen root
    rc, out, _ = detect._run(
        _adb_cmd(adb, serial, "shell", "command -v su 2>/dev/null || which su 2>/dev/null"),
        timeout=10)
    if rc == 0 and out.strip():
        return False, ("'su' binarni postoji, ali root nije potvrđen (nije odobren "
                       "uid=0). File-system akvizicija zahteva odobren root.")

    return False, "Root nije detektovan (nije eksploatisan — samo postojeći root se koristi)."


def _getprop(adb: str, serial: str) -> dict:
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "shell", "getprop"), timeout=20)
    props = {}
    if rc == 0:
        for line in out.splitlines():
            m = _PROP_RE.match(line.strip())
            if m:
                props[m.group(1)] = m.group(2)
    return props


def _adb_state(adb: str, serial: str) -> str:
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "get-state"), timeout=10)
    return out.strip() if rc == 0 else "unknown"


def detect_capabilities(serial: str = "") -> dict:
    """
    Puna detekcija: uređaj + sposobnosti. Vraća {device, capabilities} kao dict-ove.
    Bezbedno i read-only. Ako adb/uređaj nije dostupan → sve metode UNAVAILABLE.
    """
    adb = detect.adb_path()
    caps = DeviceCapabilities()
    dev = AndroidDevice(serial=serial or None)

    if not adb:
        caps.logical_reason = caps.filesystem_reason = caps.physical_reason = (
            "adb (Android platform-tools) nije pronađen.")
        caps.root_reason = "adb nije dostupan."
        return {"device": dev.to_dict(), "capabilities": caps.to_dict(),
                "reason": "adb nije pronađen. Instaliraj platform-tools i uključi USB debugging."}

    caps.adb_available = True
    state = _adb_state(adb, serial)
    dev.adb_state = state
    authorized = (state == "device")
    caps.adb_authorized = authorized
    dev.adb_authorized = authorized

    if not authorized:
        reason = {
            "unauthorized": "Uređaj nije autorizovan — potvrdi 'Allow USB debugging' na telefonu.",
            "offline": "Uređaj je offline — ponovo poveži USB.",
            "unknown": "Nijedan autorizovan Android uređaj nije detektovan.",
        }.get(state, f"ADB stanje: {state}.")
        caps.logical_reason = caps.filesystem_reason = caps.physical_reason = reason
        caps.root_reason = reason
        return {"device": dev.to_dict(), "capabilities": caps.to_dict(), "reason": reason}

    # Uređaj autorizovan → identifikacija (getprop)
    props = _getprop(adb, serial)
    try:
        sdk = int(props.get("ro.build.version.sdk")) if props.get("ro.build.version.sdk") else None
    except Exception:
        sdk = None
    dev = AndroidDevice(
        manufacturer=props.get("ro.product.manufacturer"),
        model=props.get("ro.product.model"),
        device=props.get("ro.product.device"),
        android_version=props.get("ro.build.version.release"),
        sdk_version=sdk,
        security_patch=props.get("ro.build.version.security_patch"),
        build_id=props.get("ro.build.display.id") or props.get("ro.build.id"),
        fingerprint=props.get("ro.build.fingerprint"),
        serial=props.get("ro.serialno") or serial or None,
        adb_state=state,
        adb_authorized=True,
    )

    # LOGICAL: uvek dostupno kad je uređaj autorizovan
    caps.logical_available = True
    caps.logical_reason = "Dostupno (ADB autorizovan)."

    # ROOT + FILE_SYSTEM
    root_ok, root_reason = detect_root(adb, serial)
    caps.root_available = root_ok
    caps.root_reason = root_reason
    caps.filesystem_available = root_ok
    caps.filesystem_reason = (
        "Dostupno (root potvrđen) — pristup /data preko 'su'." if root_ok else
        "Nedostupno: file-system akvizicija zahteva odobren root. " + root_reason)

    # PHYSICAL: preko kabla je moguća SAMO uz root (dd particija). Bez root-a
    # zahteva EDL/bootloader/hardver (device-specific) ili eksploit — što se ne
    # radi (spec §16,§46). Root read-only 'dd' je legitiman kad root već postoji.
    caps.physical_available = root_ok
    caps.physical_reason = (
        "Dostupno (root potvrđen) — imidž particije preko 'dd' (npr. userdata), read-only." if root_ok else
        "Nedostupno bez root-a: fizička akvizicija preko kabla zahteva root ('dd' particija) "
        "ili EDL/bootloader/hardverske metode (device-specific). Bez eksploita/zaobilaženja zaštite. "
        "Napomena: rutovanje nerutovanog dokaznog uređaja MENJA dokaz (narušava integritet).")

    return {"device": dev.to_dict(), "capabilities": caps.to_dict(), "reason": ""}


def choose_best_method(caps: dict) -> str:
    """AUTO (spec §40): najbolja DOSTUPNA metoda. Nikad ne bira nedostupnu."""
    if caps.get("physical_available"):
        return AcquisitionMethod.PHYSICAL
    if caps.get("filesystem_available"):
        return AcquisitionMethod.FILE_SYSTEM
    if caps.get("logical_available"):
        return AcquisitionMethod.LOGICAL
    raise RuntimeError("Nema podržane metode Android akvizicije za ovaj uređaj "
                       "(proveri ADB autorizaciju).")


def resolve_method(requested: str, caps: dict) -> tuple[str, str]:
    """
    Razreši i VALIDIRAJ traženu metodu prema sposobnostima (spec §40,§46):
      • AUTO → najbolja dostupna,
      • ručno izabrana metoda koja je NEDOSTUPNA → greška (NIKAD tihi downgrade).
    Vraća (effective_method, note).
    """
    requested = (requested or AcquisitionMethod.LOGICAL)
    if requested not in VALID_METHODS:
        raise RuntimeError(f"Nepoznata metoda akvizicije: {requested}")

    if requested == AcquisitionMethod.AUTO:
        best = choose_best_method(caps)
        return best, f"AUTO → izabrana najbolja dostupna metoda: {best}."

    avail_key = {
        AcquisitionMethod.LOGICAL: "logical_available",
        AcquisitionMethod.FILE_SYSTEM: "filesystem_available",
        AcquisitionMethod.PHYSICAL: "physical_available",
    }[requested]
    if not caps.get(avail_key):
        reason_key = {
            AcquisitionMethod.LOGICAL: "logical_reason",
            AcquisitionMethod.FILE_SYSTEM: "filesystem_reason",
            AcquisitionMethod.PHYSICAL: "physical_reason",
        }[requested]
        raise RuntimeError(
            f"Izabrana metoda '{requested}' je NEDOSTUPNA. "
            f"{caps.get(reason_key) or ''} "
            f"(Ručno izabrana metoda se ne menja automatski — spec §40.)")
    return requested, f"Metoda '{requested}' je dostupna."
