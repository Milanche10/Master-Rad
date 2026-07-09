"""
base.py — Zajednička osnova acquisition sloja
──────────────────────────────────────────────
Hešovanje (MD5/SHA-1/SHA-256), manifest dokaza (per-file hash + timestamp),
i kopiranje stabla fajlova uz očuvanje vremena i sračunavanje heševa.

Sve operacije su READ-ONLY nad izvorom (samo se čita; original se nikad ne menja).
Nijedna funkcija ne baca izuzetak na pojedinačnom fajlu — greška se loguje i
preskače, tako da akvizicija nikad ne pukne na jednom problematičnom fajlu.
"""

import csv
import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

HASH_CHUNK = 1024 * 1024           # 1 MB streaming (velike datoteke bez OOM)
DEFAULT_ALGOS = ("md5", "sha1", "sha256")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


def compute_hashes(path, algos=DEFAULT_ALGOS) -> dict:
    """
    Streaming MD5/SHA-1/SHA-256 nad fajlom. Vraća {algo: hexdigest}.
    Na grešci vraća {} (fajl se preskače u pozivaocu, uz log).
    """
    hs = {a: hashlib.new(a) for a in algos}
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(HASH_CHUNK)
                if not chunk:
                    break
                for h in hs.values():
                    h.update(chunk)
        return {a: h.hexdigest() for a, h in hs.items()}
    except Exception:
        return {}


def hash_bytes(data: bytes, algos=DEFAULT_ALGOS) -> dict:
    return {a: hashlib.new(a, data).hexdigest() for a in algos}


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


class EvidenceManifest:
    """
    Skuplja zapis o svakom prikupljenom fajlu (relativna putanja, veličina,
    original mtime/ctime, MD5/SHA1/SHA256). Piše se kao JSON (mašinski) i CSV
    (za izveštaj / ručnu proveru). Ovim se dokazuje integritet svakog dokaza.
    """

    def __init__(self, case_id: str = "", source: str = ""):
        self.case_id = case_id
        self.source = source
        self.created_at = now_iso()
        self.entries: list[dict] = []
        self.errors: list[dict] = []
        self.total_bytes = 0

    def add(self, rel_path: str, abs_path, hashes: dict, src_stat=None):
        try:
            st = src_stat or os.stat(abs_path)
            size = st.st_size
            self.entries.append({
                "path": rel_path.replace("\\", "/"),
                "size": size,
                "modified": _iso(st.st_mtime),
                "created": _iso(getattr(st, "st_ctime", st.st_mtime)),
                "md5": hashes.get("md5"),
                "sha1": hashes.get("sha1"),
                "sha256": hashes.get("sha256"),
            })
            self.total_bytes += size
        except Exception as e:
            self.errors.append({"path": rel_path, "error": str(e)})

    def add_error(self, rel_path: str, error: str):
        self.errors.append({"path": rel_path, "error": str(error)})

    def summary(self) -> dict:
        return {
            "case_id": self.case_id,
            "source": self.source,
            "created_at": self.created_at,
            "file_count": len(self.entries),
            "error_count": len(self.errors),
            "total_bytes": self.total_bytes,
            "total_size_human": human_size(self.total_bytes),
        }

    def write(self, out_dir) -> dict:
        """Zapiši manifest.json + manifest.csv u dati folder (npr. Logs/ ili Metadata/)."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        doc = {"summary": self.summary(), "files": self.entries, "errors": self.errors}
        try:
            (out_dir / "manifest.json").write_text(
                json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        try:
            with open(out_dir / "manifest.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["path", "size", "modified", "md5", "sha1", "sha256"])
                for e in self.entries:
                    w.writerow([e["path"], e["size"], e["modified"],
                                e["md5"], e["sha1"], e["sha256"]])
        except Exception:
            pass
        return doc


def _safe_copy2(src: Path, dst: Path):
    """copy2 čuva mtime/atime; pravi roditeljske foldere; read-only nad src."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)   # metapodaci (vreme) se čuvaju


def iter_files(root: Path):
    """Rekurzivno svi fajlovi ispod root-a (bez dizanja izuzetka na loš folder)."""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            yield Path(dirpath) / name


def copy_tree_preserving(src_root, dst_root, manifest: EvidenceManifest,
                         progress=None, kind: str = "file",
                         media_exts=None) -> dict:
    """
    Kopira celo stablo `src_root` → `dst_root` uz:
      • očuvanje strukture foldera i vremenskih pečata (copy2),
      • MD5/SHA-1/SHA-256 svakog fajla → manifest,
      • progress callback (progress.update / progress.log / progress.cancelled),
      • otpornost: greška na jednom fajlu se loguje i preskače (nikad ne pukne).

    `progress` je opcioni objekat sa .update(pct,msg), .log(msg), .cancelled()->bool
    (vidi acquisition.jobs.Progress). Vraća statistiku.
    """
    src_root = Path(src_root)
    dst_root = Path(dst_root)
    dst_root.mkdir(parents=True, exist_ok=True)

    # Prvi prolaz: popis (za progres proceniti ukupno). Na ogromnim diskovima
    # ovo je jeftino u odnosu na kopiranje + hešovanje.
    files = list(iter_files(src_root))
    total = len(files) or 1
    copied = 0
    skipped = 0
    bytes_done = 0

    for i, f in enumerate(files):
        if progress and progress.cancelled():
            if progress:
                progress.log("Akvizicija otkazana od strane korisnika.")
            break
        try:
            rel = f.relative_to(src_root)
        except Exception:
            rel = Path(f.name)
        dst = dst_root / rel
        try:
            _safe_copy2(f, dst)
            hashes = compute_hashes(dst)
            manifest.add(str(rel), dst, hashes)
            copied += 1
            try:
                bytes_done += dst.stat().st_size
            except Exception:
                pass
        except Exception as e:
            skipped += 1
            manifest.add_error(str(rel), str(e))
            if progress:
                progress.log(f"Preskočen (greška): {rel} — {e}")

        if progress and (i % 25 == 0 or i == total - 1):
            pct = int((i + 1) / total * 100)
            progress.update(pct, f"Kopirano {copied}/{total} fajlova ({human_size(bytes_done)})")

    return {
        "copied": copied,
        "skipped": skipped,
        "total_seen": len(files),
        "bytes": bytes_done,
        "bytes_human": human_size(bytes_done),
    }
