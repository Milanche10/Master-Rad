"""
image_parser.py — parsiranje sirovog imidža preko pytsk3 (The Sleuth Kit)
──────────────────────────────────────────────────────────────────────────
Otvara raw (dd/.img) ili EWF (.E01, ako je pyewf dostupan) imidž, pronalazi
filesystem(e) i rekurzivno vadi fajlove (uključujući OBRISANE) u ciljni folder
u Android-FS rasporedu. Streaming čitanje (bez učitavanja celog fajla u RAM),
symlink-safe (bez rekurzije kroz link), zaštita od petlji (posećeni inode-ovi).
Za svaki fajl: metapodaci (inode/mode/uid/gid/timestamps) + SHA-256 + status
(ACQUIRED / RECOVERED / ERROR).

Ako pytsk3 nije instaliran → parse_image vraća {ok:False, reason:...} bez rušenja.
"""

import hashlib
import os
from pathlib import Path

MAX_PATH_DEPTH = 40          # zaštita od patoloških stabala
CHUNK = 1024 * 1024          # streaming (spec §15)


def pytsk3_available() -> bool:
    try:
        import pytsk3  # noqa: F401
        return True
    except Exception:
        return False


def _iso(epoch) -> str | None:
    try:
        from datetime import datetime, timezone
        if not epoch:
            return None
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _open_image(image_path: str):
    """Vrati pytsk3.Img_Info za raw ili EWF (.E01) imidž."""
    import pytsk3
    lower = image_path.lower()
    if lower.endswith((".e01", ".ex01", ".s01")):
        try:
            import pyewf
            names = pyewf.glob(image_path)
            ewf = pyewf.handle()
            ewf.open(names)

            class _EWFImg(pytsk3.Img_Info):
                def __init__(self, handle):
                    self._h = handle
                    super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

                def close(self):
                    self._h.close()

                def read(self, offset, size):
                    self._h.seek(offset)
                    return self._h.read(size)

                def get_size(self):
                    return self._h.get_media_size()

            return _EWFImg(ewf)
        except Exception:
            # pyewf nedostupan → probaj kao raw (radiće za split tek uz pyewf)
            return pytsk3.Img_Info(image_path)
    return pytsk3.Img_Info(image_path)


def _filesystems(img):
    """Vrati listu (offset_bytes, FS_Info). Podržava particionisan imidž i single-FS."""
    import pytsk3
    out = []
    try:
        vol = pytsk3.Volume_Info(img)
        for part in vol:
            # preskoči nealocirane/meta particije bez fajl sistema
            if part.len <= 0 or (part.flags & pytsk3.TSK_VS_PART_FLAG_UNALLOC):
                continue
            off = part.start * vol.info.block_size
            try:
                fs = pytsk3.FS_Info(img, offset=off)
                out.append((off, fs))
            except Exception:
                continue
    except Exception:
        pass
    if not out:
        # single-FS imidž (npr. userdata.img — nema tabele particija)
        try:
            out.append((0, pytsk3.FS_Info(img, offset=0)))
        except Exception:
            pass
    return out


def _extract_file(fs_file, dest: Path) -> tuple[int, str | None]:
    """Streaming izvlačenje + SHA-256. Vraća (bytes, sha256)."""
    size = int(getattr(fs_file.info.meta, "size", 0) or 0)
    h = hashlib.sha256()
    written = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        off = 0
        while off < size:
            try:
                chunk = fs_file.read_random(off, min(CHUNK, size - off))
            except Exception:
                break
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            off += len(chunk)
            written += len(chunk)
    return written, (h.hexdigest() if written else None)


def _walk(fs, directory, dev_dir: str, dest_root: Path, ctx, depth=0):
    import pytsk3
    if depth > MAX_PATH_DEPTH:
        return
    if ctx["progress"] and ctx["progress"].cancelled():
        return
    for entry in directory:
        if ctx["max_files"] and ctx["count"] >= ctx["max_files"]:
            return
        try:
            name = entry.info.name.name.decode("utf-8", "replace")
        except Exception:
            continue
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        if meta is None:
            continue
        dev_path = (dev_dir.rstrip("/") + "/" + name)
        rel = dev_path.lstrip("/")
        dest = dest_root / rel
        deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
        mtype = meta.type

        rec = {
            "path": dev_path, "evidencePath": rel, "filename": name,
            "type": ("dir" if mtype == pytsk3.TSK_FS_META_TYPE_DIR else
                     "link" if mtype == pytsk3.TSK_FS_META_TYPE_LNK else
                     "file" if mtype == pytsk3.TSK_FS_META_TYPE_REG else "other"),
            "size": int(getattr(meta, "size", 0) or 0),
            "mode": oct(getattr(meta, "mode", 0) or 0)[-4:],
            "uid": getattr(meta, "uid", None), "gid": getattr(meta, "gid", None),
            "inode": getattr(meta, "addr", None),
            "mtime": _iso(getattr(meta, "mtime", None)),
            "atime": _iso(getattr(meta, "atime", None)),
            "ctime": _iso(getattr(meta, "ctime", None)),
            "crtime": _iso(getattr(meta, "crtime", None)),
            "sha256": None,
            "deleted": deleted,
            "acquisitionStatus": None,
        }

        if mtype == pytsk3.TSK_FS_META_TYPE_DIR:
            addr = getattr(meta, "addr", None)
            if addr in ctx["visited"]:
                continue
            ctx["visited"].add(addr)
            rec["acquisitionStatus"] = "ACQUIRED"
            ctx["dirs"] += 1
            try:
                dest.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            try:
                sub = entry.as_directory()
                _walk(fs, sub, dev_path, dest_root, ctx, depth + 1)
            except Exception:
                pass
        elif mtype == pytsk3.TSK_FS_META_TYPE_REG:
            try:
                nbytes, sha = _extract_file(entry, dest)
                rec["size"] = nbytes
                rec["sha256"] = sha
                rec["acquisitionStatus"] = "RECOVERED" if deleted else "ACQUIRED"
                ctx["recovered" if deleted else "acquired"] += 1
                ctx["bytes"] += nbytes
                ctx["count"] += 1
            except Exception:
                rec["acquisitionStatus"] = "ERROR"
                ctx["errors"] += 1
        elif mtype == pytsk3.TSK_FS_META_TYPE_LNK:
            rec["acquisitionStatus"] = "ACQUIRED"
            ctx["links"] += 1
        else:
            rec["acquisitionStatus"] = "SKIPPED"

        ctx["entries"].append(rec)
        if ctx["progress"] and ctx["count"] % 200 == 0:
            ctx["progress"].update(min(92, 40 + ctx["count"] // 1000),
                                   f"Parsiranje imidža: {ctx['acquired']} fajlova, "
                                   f"{ctx['recovered']} obrisanih…")


def parse_image(image_path: str, dest_dir, progress=None, max_files: int | None = None) -> dict:
    """
    Parsiraj imidž i izvadi fajlove u dest_dir (Android-FS raspored).
    Vraća {ok, reason, totals, entries, filesystems}. NE ruši se ako pytsk3/imidž fale.
    """
    if not pytsk3_available():
        return {"ok": False, "reason": "pytsk3 nije instaliran (pip install pytsk3). "
                                       "Analiza sirovog imidža nije moguća.", "totals": {}}
    if not os.path.exists(image_path):
        return {"ok": False, "reason": f"Imidž ne postoji: {image_path}", "totals": {}}

    dest_root = Path(dest_dir)
    dest_root.mkdir(parents=True, exist_ok=True)
    if progress:
        progress.update(35, "Otvaranje imidža (pytsk3)…")
    try:
        img = _open_image(image_path)
    except Exception as e:
        return {"ok": False, "reason": f"Ne mogu da otvorim imidž: {e}", "totals": {}}

    fss = _filesystems(img)
    if not fss:
        return {"ok": False, "reason": "Nijedan podržan filesystem nije pronađen u imidžu "
                                       "(nepodržan/enkriptovan/oštećen).", "totals": {}}

    ctx = {"entries": [], "visited": set(), "count": 0, "acquired": 0, "recovered": 0,
           "dirs": 0, "links": 0, "errors": 0, "bytes": 0, "progress": progress,
           "max_files": max_files}
    fs_infos = []
    for i, (off, fs) in enumerate(fss):
        try:
            ftype = str(fs.info.ftype)
        except Exception:
            ftype = "?"
        fs_infos.append({"offset": off, "ftype": ftype})
        if progress:
            progress.log(f"Filesystem #{i} @ offset {off} ({ftype}) — vadim fajlove…")
        try:
            root = fs.open_dir(path="/")
            _walk(fs, root, "", dest_root, ctx, 0)
        except Exception as e:
            if progress:
                progress.log(f"Greška pri obilasku FS #{i}: {e}")

    totals = {"acquired": ctx["acquired"], "recovered": ctx["recovered"],
              "dirs": ctx["dirs"], "links": ctx["links"], "errors": ctx["errors"],
              "bytes": ctx["bytes"], "files_total": ctx["acquired"] + ctx["recovered"]}
    return {"ok": ctx["acquired"] + ctx["recovered"] > 0, "reason": "",
            "totals": totals, "entries": ctx["entries"], "filesystems": fs_infos}
