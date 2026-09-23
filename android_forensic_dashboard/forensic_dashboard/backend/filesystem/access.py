"""
access.py — IFileSystemAccess apstrakcija (spec §6) i implementacije
─────────────────────────────────────────────────────────────────────
Sav pristup filesystem-u ide kroz interfejs, pa je akvizicija ista bez obzira
da li čita preko adb-a (bez root-a), preko su (root), ili iz mock uređaja (test).

Metode interfejsa (minimalne, dovoljne za forenzičku akviziciju):
  available()               → (bool, reason)         : da li se uopšte može čitati
  crypto_state()            → str                     : ro.crypto.state ('encrypted'/'unencrypted'/'')
  location_status(path)     → (LocationStatus, reason): stanje jedne lokacije/mounta
  enumerate(root)           → Iterator[FileStat]      : metapodaci SVIH entry-ja pod root
  pull_tree(root, dest, …)  → (ok, note)              : prenese dostupan sadržaj u dest (stream)

Reutilizuje postojeći ADB transport iz acquisition.detect (run/run_streaming/run_to_file).
"""

import io
import os
import re
import shlex
import tarfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from acquisition import detect
from .status import FileStat, LocationStatus

_FIELD_SEP = "\x1f"   # unit separator — retko u imenima fajlova, pouzdan delimiter


def _epoch_to_iso(v) -> str | None:
    try:
        e = int(v)
        if e <= 0:
            return None
        return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


class IFileSystemAccess(ABC):
    name: str = "abstract"
    privileged: bool = False

    @abstractmethod
    def available(self) -> tuple[bool, str]: ...

    def crypto_state(self) -> str:
        return ""

    @abstractmethod
    def location_status(self, path: str) -> tuple[str, str]: ...

    @abstractmethod
    def enumerate(self, root: str): ...

    @abstractmethod
    def pull_tree(self, root: str, dest_dir, progress=None) -> tuple[bool, str]: ...


# ═══════════════════════════════════════════════════════════════════════════
# ADB (bez root-a) — čita ono što adb legitimno daje (npr. /sdcard)
# ═══════════════════════════════════════════════════════════════════════════

class AdbFileSystemAccess(IFileSystemAccess):
    name = "adb"
    privileged = False

    def __init__(self, adb: str, serial: str = ""):
        self.adb = adb
        self.serial = serial

    # ── izgradnja adb komandi ────────────────────────────────────────────
    def _base(self, mode):
        cmd = [self.adb]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd + [mode]

    def _wrap_su(self, shell_cmd: str) -> str:
        if self.privileged:
            return "su -c " + shlex.quote(shell_cmd)
        return shell_cmd

    def _shell(self, shell_cmd: str, timeout=60):
        return detect._run(self._base("shell") + [self._wrap_su(shell_cmd)], timeout=timeout)

    # ── interfejs ────────────────────────────────────────────────────────
    def available(self) -> tuple[bool, str]:
        rc, out, _ = detect._run(self._base("get-state"), timeout=10)
        if rc == 0 and out.strip() == "device":
            return True, ""
        return False, f"Uređaj nije autorizovan (ADB stanje: {out.strip() or 'nepoznato'})."

    def crypto_state(self) -> str:
        rc, out, _ = self._shell("getprop ro.crypto.state", timeout=10)
        return out.strip() if rc == 0 else ""

    def location_status(self, path: str) -> tuple[str, str]:
        # Postojanje/čitljivost: `ls -ld <path>` (kroz su ako privileged).
        rc, out, err = self._shell(f"ls -ld {shlex.quote(path)}", timeout=15)
        blob = (out + err).lower()
        if "no such file" in blob or "not found" in blob:
            return LocationStatus.NOT_PRESENT, f"{path} ne postoji na uređaju."
        if "permission denied" in blob:
            # Ako je uređaj enkriptovan i /data nedostupan — ENCRYPTED je precizniji nalaz
            if path.startswith("/data") and self.crypto_state() == "encrypted":
                return LocationStatus.ENCRYPTED, (f"{path} je nedostupan (uređaj enkriptovan, "
                                                  f"korisnički podaci nisu dešifrovani/dostupni).")
            return LocationStatus.PERMISSION_DENIED, (
                f"{path}: nedostupno bez privilegovanog pristupa (potreban root).")
        if rc == 0:
            return LocationStatus.AVAILABLE, ""
        return LocationStatus.UNAVAILABLE, f"{path}: {err.strip() or out.strip() or 'nedostupno'}"

    def enumerate(self, root: str):
        """
        Metapodaci svih entry-ja pod root: `find <root> -exec stat -c FORMAT`.
        Redovi koje find prijavi kao 'Permission denied' se emituju kao FileStat
        (readable=False), da se u manifestu vidi da entry postoji ali je nedostupan.
        """
        fmt = _FIELD_SEP.join(["%n", "%F", "%s", "%a", "%u", "%g", "%i", "%X", "%Y", "%Z", "%N"])
        cmd = (f"find {shlex.quote(root)} -exec stat -c {shlex.quote(fmt)} {{}} \\; 2>&1")
        rc, out, err = self._shell(cmd, timeout=1800)
        for line in (out or "").splitlines():
            line = line.rstrip("\r\n")
            if not line:
                continue
            if "Permission denied" in line and _FIELD_SEP not in line:
                m = re.search(r"find:\s*[\"']?(/[^\"':]+)[\"']?:\s*Permission denied", line)
                if m:
                    yield FileStat(path=m.group(1), entry_type="dir", readable=False)
                continue
            parts = line.split(_FIELD_SEP)
            if len(parts) < 11:
                continue
            name, ftype, size, mode, uid, gid, inode, atime, mtime, ctime, nfield = parts[:11]
            etype = ("dir" if "directory" in ftype else
                     "link" if "symbolic link" in ftype else
                     "file" if "regular" in ftype else "other")
            link_target = None
            if etype == "link":
                mm = re.search(r"->\s*[\"'](.+?)[\"']\s*$", nfield)
                if mm:
                    link_target = mm.group(1)
            yield FileStat(
                path=name, entry_type=etype,
                size=(int(size) if size.isdigit() else None),
                mode=mode or None, uid=uid or None, gid=gid or None,
                inode=inode or None,
                atime=_epoch_to_iso(atime), mtime=_epoch_to_iso(mtime), ctime=_epoch_to_iso(ctime),
                link_target=link_target, readable=True)

    def pull_tree(self, root: str, dest_dir, progress=None) -> tuple[bool, str]:
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        if self.privileged:
            return self._pull_via_tar(root, dest_dir, progress)
        # bez root-a: adb pull (radi za /sdcard i sl.)
        rc, tail = detect.run_streaming(
            self._base("pull") + ["-a", root.rstrip("/") + "/.", str(dest_dir)],
            progress=progress, timeout=1800, stall_timeout=120,
            on_line=(lambda l: progress.log(l[:160]) if progress and (l.startswith("/") or "pulled" in l) else None))
        if rc == 0:
            return True, "OK (adb pull)"
        reason = {130: "otkazano", 124: "vremenski limit", 125: "zastoj"}.get(rc, f"rc={rc}")
        return False, reason

    def _pull_via_tar(self, root: str, dest_dir: Path, progress) -> tuple[bool, str]:
        """Root: `adb exec-out su -c 'tar -c -C <root> .'` → raspakuj u dest (read-only)."""
        tar_path = dest_dir.parent / (dest_dir.name + "_.tar")
        cmd = self._base("exec-out") + ["su", "-c", f"tar -c -C {shlex.quote(root)} . 2>/dev/null"]

        def _ob(n):
            if progress:
                progress.log(f"  … {n // 1048576} MB ({root})") if (n // 1048576) % 64 == 0 else None

        rc, nbytes = detect.run_to_file(cmd, str(tar_path), progress=progress,
                                        timeout=7200, stall_timeout=180, on_bytes=_ob)
        if rc != 0 or nbytes < 512:
            try:
                tar_path.unlink()
            except Exception:
                pass
            reason = {130: "otkazano", 124: "vremenski limit", 125: "zastoj"}.get(rc, f"rc={rc}, {nbytes}B")
            return False, reason
        try:
            with tarfile.open(str(tar_path)) as tf:
                for m in tf.getmembers():
                    try:
                        tf.extract(m, path=str(dest_dir), filter="data")
                    except Exception:
                        continue
        except Exception as e:
            return False, f"raspakivanje: {e}"
        finally:
            try:
                tar_path.unlink()
            except Exception:
                pass
        return True, "OK (su tar)"


class PrivilegedFileSystemAccess(AdbFileSystemAccess):
    """Root pristup: iste komande, ali obavijene u `su -c` (spec §6)."""
    name = "privileged"
    privileged = True


# ═══════════════════════════════════════════════════════════════════════════
# MOCK — simulira uređaj za testove (spec §19): denied/link/encrypted/large…
# ═══════════════════════════════════════════════════════════════════════════

class MockFileSystemAccess(IFileSystemAccess):
    """
    Virtuelni uređaj za testiranje FileSystemAcquisition bez hardvera.
    `nodes`: dict apsolutna_putanja → opis:
      {"type":"file","content":b"…","mode":"660","uid":"1000","gid":"1000","readable":True,"mtime":169...}
      {"type":"dir","readable":True}
      {"type":"link","target":"/…"}
    `locations`: dict putanja → LocationStatus (za lokacije koje nisu AVAILABLE).
    """
    name = "mock"
    privileged = True

    def __init__(self, nodes: dict, locations: dict = None, crypto="unencrypted"):
        self.nodes = nodes
        self.locations = locations or {}
        self._crypto = crypto

    def available(self) -> tuple[bool, str]:
        return True, ""

    def crypto_state(self) -> str:
        return self._crypto

    def location_status(self, path: str) -> tuple[str, str]:
        if path in self.locations:
            return self.locations[path], f"(mock) {self.locations[path]}"
        if path in self.nodes or any(p.startswith(path.rstrip("/") + "/") for p in self.nodes):
            return LocationStatus.AVAILABLE, ""
        return LocationStatus.NOT_PRESENT, "(mock) ne postoji"

    def enumerate(self, root: str):
        r = root.rstrip("/")
        for path in sorted(self.nodes):
            if path == r or path.startswith(r + "/"):
                n = self.nodes[path]
                t = n.get("type", "file")
                yield FileStat(
                    path=path, entry_type=t,
                    size=(len(n["content"]) if t == "file" and "content" in n else None),
                    mode=n.get("mode"), uid=n.get("uid"), gid=n.get("gid"),
                    inode=n.get("inode"),
                    mtime=_epoch_to_iso(n["mtime"]) if n.get("mtime") else None,
                    atime=_epoch_to_iso(n["atime"]) if n.get("atime") else None,
                    ctime=_epoch_to_iso(n["ctime"]) if n.get("ctime") else None,
                    link_target=n.get("target"),
                    readable=n.get("readable", True))

    def pull_tree(self, root: str, dest_dir, progress=None) -> tuple[bool, str]:
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        r = root.rstrip("/")
        for path in sorted(self.nodes):
            if not (path == r or path.startswith(r + "/")):
                continue
            n = self.nodes[path]
            if n.get("type") != "file" or not n.get("readable", True):
                continue   # denied/nefajl se ne prenose (ostaju denied u statusu)
            rel = path[len(r):].lstrip("/")
            out = dest_dir / rel
            try:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(n.get("content", b""))
            except Exception:
                continue
        return True, "OK (mock)"
