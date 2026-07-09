"""
detect.py — Detekcija izvora dokaza (uređaji / čitači / diskovi)
─────────────────────────────────────────────────────────────────
Realna detekcija hardvera, bez izmišljanja:
  • Telefon  → `adb` (Android platform-tools). Bez adb-a → jasna uputstva.
  • SD/USB   → uklonjivi diskovi (Windows: PowerShell/CIM; POSIX: lsblk).
  • SIM      → PC/SC čitači preko `pyscard` (opciono). Bez biblioteke → jasan razlog.

Sve funkcije vraćaju {"available": bool, ...}. Kada hardver/alat nije prisutan,
`available=False` + `reason` (nikad lažni uređaj).
"""

import json
import os
import re
import shutil
import subprocess
import sys

WINDOWS = sys.platform.startswith("win")
_CREATE_NO_WINDOW = 0x08000000 if WINDOWS else 0


def _run(cmd, timeout=20) -> tuple[int, str, str]:
    """Pokreni komandu bez otvaranja konzolnog prozora; nikad ne baca izuzetak."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=_CREATE_NO_WINDOW)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


# ═══════════════════════════════════════════════════════════════════════════
# TELEFON — adb
# ═══════════════════════════════════════════════════════════════════════════

def adb_path() -> str | None:
    # Prvo adb koji je aplikacija sama obezbedila (spakovan uz app ili preuzet),
    # pa PATH, pa ANDROID_HOME/platform-tools raspored.
    try:
        from provisioning import provision
        p = provision.find_adb()
        if p:
            return p
    except Exception:
        pass
    p = shutil.which("adb")
    if p:
        return p
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(env)
        if base:
            cand = os.path.join(base, "platform-tools", "adb.exe" if WINDOWS else "adb")
            if os.path.exists(cand):
                return cand
    return None


def _getprop(adb: str, serial: str) -> dict:
    rc, out, _ = _run([adb, "-s", serial, "shell", "getprop"], timeout=15)
    props = {}
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"\[([^\]]+)\]:\s*\[([^\]]*)\]", line)
            if m:
                props[m.group(1)] = m.group(2)
    return props


def _adb_storage(adb: str, serial: str) -> dict:
    rc, out, _ = _run([adb, "-s", serial, "shell", "df", "/data"], timeout=10)
    if rc != 0:
        return {}
    # poslednja linija: Filesystem 1K-blocks Used Available Use% Mounted
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 4:
            try:
                total_kb = int(cols[1]); used_kb = int(cols[2]); avail_kb = int(cols[3])
                return {"total_mb": total_kb // 1024, "used_mb": used_kb // 1024,
                        "available_mb": avail_kb // 1024}
            except Exception:
                pass
    return {}


def detect_phones() -> dict:
    adb = adb_path()
    if not adb:
        return {"available": False, "source": "mobile", "devices": [],
                "reason": "adb (Android platform-tools) nije pronađen. Instaliraj "
                          "platform-tools i dodaj u PATH, pa uključi USB debugging na telefonu."}
    rc, out, err = _run([adb, "devices", "-l"], timeout=15)
    if rc != 0:
        return {"available": False, "source": "mobile", "devices": [],
                "reason": f"adb greška: {err or out or rc}"}

    devices = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line and " " not in line:
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        entry = {"serial": serial, "state": state, "connection": "USB"}
        if state == "unauthorized":
            entry["note"] = "Uređaj nije autorizovan — potvrdi 'Allow USB debugging' na telefonu."
        elif state == "device":
            props = _getprop(adb, serial)
            entry.update({
                "manufacturer": props.get("ro.product.manufacturer", ""),
                "model": props.get("ro.product.model", ""),
                "device": props.get("ro.product.device", ""),
                "android": props.get("ro.build.version.release", ""),
                "sdk": props.get("ro.build.version.sdk", ""),
                "os": f"Android {props.get('ro.build.version.release','?')} "
                      f"(SDK {props.get('ro.build.version.sdk','?')})",
                "device_serial": props.get("ro.serialno", serial),
                "security_patch": props.get("ro.build.version.security_patch", ""),
                "storage": _adb_storage(adb, serial),
            })
        devices.append(entry)

    ready = [d for d in devices if d.get("state") == "device"]
    return {"available": True, "source": "mobile", "adb_path": adb,
            "devices": devices, "ready_count": len(ready),
            "reason": "" if devices else "Nijedan telefon nije povezan. Poveži telefon USB-om i uključi USB debugging."}


# ═══════════════════════════════════════════════════════════════════════════
# SD / USB — uklonjivi diskovi
# ═══════════════════════════════════════════════════════════════════════════

_PS_REMOVABLE = r"""
$vols = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue
$disks = @{}
try { Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object { $disks[$_.DeviceID] = $_ } } catch {}
$out = @()
foreach ($v in $vols) {
  $bus = "unknown"
  try {
    $partitions = Get-CimAssociatedInstance -InputObject $v -ResultClassName Win32_DiskPartition -ErrorAction SilentlyContinue
    foreach ($p in $partitions) {
      $drv = Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_DiskDrive -ErrorAction SilentlyContinue
      foreach ($d in $drv) { if ($d.InterfaceType) { $bus = $d.InterfaceType } }
    }
  } catch {}
  $out += [PSCustomObject]@{
    device_id  = $v.DeviceID
    name       = $v.VolumeName
    filesystem = $v.FileSystem
    size       = [int64]$v.Size
    free       = [int64]$v.FreeSpace
    bus        = $bus
  }
}
$out | ConvertTo-Json -Compress
"""


def _human(n) -> str:
    try:
        f = float(n)
    except Exception:
        return "?"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or u == "TB":
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{f:.1f} TB"


def detect_removable_windows() -> list:
    rc, out, _ = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_REMOVABLE], timeout=25)
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    disks = []
    for d in data:
        did = d.get("device_id")
        if not did:
            continue
        bus = (d.get("bus") or "unknown")
        # Heuristika oznake: USB busType → USB; ostalo (SD čitači su često "SCSI"/"unknown") → SD/nepoznato
        kind = "usb" if "usb" in bus.lower() else "removable"
        disks.append({
            "device_id": did,
            "mount": did + "\\",
            "name": d.get("name") or "(bez oznake)",
            "filesystem": d.get("filesystem") or "?",
            "size": d.get("size") or 0,
            "free": d.get("free") or 0,
            "size_human": _human(d.get("size") or 0),
            "free_human": _human(d.get("free") or 0),
            "bus": bus,
            "kind": kind,
        })
    return disks


def detect_removable_posix() -> list:
    rc, out, _ = _run(["lsblk", "-J", "-b", "-o", "NAME,MOUNTPOINT,FSTYPE,SIZE,RM,TRAN,LABEL"], timeout=15)
    if rc != 0 or not out.strip():
        return []
    try:
        tree = json.loads(out)
    except Exception:
        return []
    disks = []

    def walk(nodes):
        for n in nodes:
            rm = str(n.get("rm")) in ("1", "True", "true")
            mnt = n.get("mountpoint")
            if rm and mnt:
                tran = (n.get("tran") or "").lower()
                disks.append({
                    "device_id": "/dev/" + n.get("name", ""),
                    "mount": mnt,
                    "name": n.get("label") or n.get("name") or "(bez oznake)",
                    "filesystem": n.get("fstype") or "?",
                    "size": int(n.get("size") or 0),
                    "free": 0,
                    "size_human": _human(n.get("size") or 0),
                    "free_human": "?",
                    "bus": tran,
                    "kind": "usb" if tran == "usb" else "removable",
                })
            if n.get("children"):
                walk(n["children"])

    walk(tree.get("blockdevices", []))
    return disks


def detect_storage(kind: str = "sdcard") -> dict:
    """
    kind: 'sdcard' ili 'usb' — služi samo kao oznaka koju je korisnik izabrao.
    Vraća SVE uklonjive diskove (SD i USB fleš se u OS-u vide kao 'removable';
    ne izmišljamo razliku koju ne možemo pouzdano utvrditi — korisnik bira disk).
    """
    disks = detect_removable_windows() if WINDOWS else detect_removable_posix()
    if not disks:
        return {"available": False, "source": kind, "disks": [],
                "reason": "Nije pronađen nijedan uklonjivi disk. Ubaci "
                          + ("SD karticu u čitač" if kind == "sdcard" else "USB fleš")
                          + " i osveži."}
    return {"available": True, "source": kind, "disks": disks,
            "reason": ""}


# ═══════════════════════════════════════════════════════════════════════════
# SIM — PC/SC čitači (pyscard, opciono)
# ═══════════════════════════════════════════════════════════════════════════

def pyscard_available() -> bool:
    try:
        import smartcard  # noqa: F401
        return True
    except Exception:
        return False


def detect_sim_readers() -> dict:
    if not pyscard_available():
        return {"available": False, "source": "sim", "readers": [],
                "reason": "PC/SC podrška (pyscard) nije instalirana. "
                          "Instaliraj: pip install pyscard  (i drajver za USB SIM čitač)."}
    try:
        from smartcard.System import readers as _readers
        rlist = _readers()
    except Exception as e:
        return {"available": False, "source": "sim", "readers": [],
                "reason": f"PC/SC greška: {e}. Proveri da je servis 'Smart Card' pokrenut."}

    out = []
    for r in rlist:
        entry = {"name": str(r), "card_present": False}
        try:
            conn = r.createConnection()
            conn.connect()          # uspešno = kartica prisutna
            entry["card_present"] = True
            try:
                entry["atr"] = " ".join(f"{b:02X}" for b in conn.getATR())
            except Exception:
                pass
            conn.disconnect()
        except Exception:
            entry["card_present"] = False
        out.append(entry)

    if not out:
        return {"available": False, "source": "sim", "readers": [],
                "reason": "PC/SC podrška postoji, ali nijedan čitač nije pronađen. Poveži USB SIM čitač."}
    return {"available": True, "source": "sim", "readers": out,
            "reason": "" if any(r["card_present"] for r in out)
                      else "Čitač je povezan, ali SIM kartica nije detektovana. Ubaci SIM u čitač."}


# ═══════════════════════════════════════════════════════════════════════════
# Zbirni pregled dostupnosti svih izvora (za wizard)
# ═══════════════════════════════════════════════════════════════════════════

def sources_overview() -> dict:
    return {
        "platform": sys.platform,
        "sources": {
            "mobile": {"tool": "adb", "ready": adb_path() is not None,
                       "hint": "" if adb_path() else "Instaliraj Android platform-tools (adb)."},
            "sim": {"tool": "pyscard/PCSC", "ready": pyscard_available(),
                    "hint": "" if pyscard_available() else "pip install pyscard + USB SIM čitač."},
            "sdcard": {"tool": "OS removable disks", "ready": True, "hint": ""},
            "usb": {"tool": "OS removable disks", "ready": True, "hint": ""},
            "dump": {"tool": "filesystem", "ready": True, "hint": ""},
        },
    }
