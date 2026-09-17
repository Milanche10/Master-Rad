"""
image_parser.py — Parsiranje sirovih forenzičkih slika (Faza 4, spec §17–18)
──────────────────────────────────────────────────────────────────────────────
Otvara raw/dd/.img forenzičku sliku preko The Sleuth Kit-a (pytsk3), prepoznaje
particionu tabelu i fajl sisteme (ext4/FAT/NTFS/HFS…), i EKSTRAHUJE fajlove u
folder stablo koje POSTOJEĆI analitički engine čita (DumpResolver). Ovim se
fizička/file-system slika (npr. userdata.img, dd particija, izlaz eksternog alata)
pretvara u analizabilne artefakte.

Poštenje (spec §46): pytsk3 NIJE alat za akviziciju uređaja — samo parsira već
akvizirane slike. Ako fajl sistem NIJE prepoznat (Android FBE enkripcija, f2fs
koji TSK ne podržava), to se JASNO prijavljuje — ne izmišlja se sadržaj i ne
tumači se šifrovan blob kao podaci.

Napomena o enkripciji (bitno forenzički): moderni Android (npr. Galaxy S10 /
Android 10) koristi File-Based Encryption. Sirov `dd` userdata sa zaključanog/
šifrovanog uređaja je ŠIFROVAN — TSK tada ne prepoznaje FS. Čitljive podatke daje
FILE-SYSTEM akvizicija (root `tar` nad pokrenutim, otključanim uređajem), gde OS
dešifruje fajlove pri čitanju. To se ovde eksplicitno navodi.
"""

from pathlib import Path

# Bezbednosne granice (da ekstrakcija ne ode van kontrole)
MAX_FILES = 300000
MAX_TOTAL_BYTES = 96 * 1024 ** 3       # 96 GB
MAX_DEPTH = 48
CHUNK = 1024 * 1024

# Ako se u korenu FS-a vide ovi dir-ovi, radi se o /data particiji (userdata) →
# ekstrahujemo pod 'data/' da DumpResolver nađe sidra (data/data, data/media/0…).
_DATA_DIR_HINTS = {"media", "app", "system", "misc", "user", "user_de", "data", "app-private"}


def pytsk3_available() -> bool:
    try:
        import pytsk3  # noqa: F401
        return True
    except Exception:
        return False


def _safe_name(entry) -> str:
    try:
        return entry.info.name.name.decode("utf-8", "replace")
    except Exception:
        return ""


def _fs_root_looks_like_userdata(fs) -> bool:
    try:
        root = fs.open_dir(path="/")
        names = set()
        for e in root:
            n = _safe_name(e)
            if n and n not in (".", ".."):
                names.add(n)
        return len(_DATA_DIR_HINTS & names) >= 2
    except Exception:
        return False


def _extract_fs(pytsk3, fs, out_root: Path, prefix: str, progress, cancel, stats):
    """Rekurzivno ekstrahuj sve regularne fajlove iz FS-a u out_root/prefix/…"""
    base_prefix = prefix.strip("/")

    def walk(tsk_dir, rel, depth):
        if depth > MAX_DEPTH:
            return
        for entry in tsk_dir:
            if cancel and cancel():
                return
            if stats["files"] >= MAX_FILES or stats["bytes"] >= MAX_TOTAL_BYTES:
                stats["capped"] = True
                return
            name = _safe_name(entry)
            if not name or name in (".", ".."):
                continue
            meta = getattr(entry.info, "meta", None)
            if meta is None:
                continue
            child_rel = f"{rel}/{name}" if rel else name
            try:
                mtype = meta.type
            except Exception:
                continue
            if mtype == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub = entry.as_directory()
                except Exception:
                    continue
                try:
                    (out_root / child_rel).mkdir(parents=True, exist_ok=True)
                except Exception:
                    pass
                walk(sub, child_rel, depth + 1)
            elif mtype == pytsk3.TSK_FS_META_TYPE_REG:
                size = getattr(meta, "size", 0) or 0
                dst = out_root / child_rel
                try:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    with open(dst, "wb") as fh:
                        off = 0
                        while off < size:
                            n = min(CHUNK, size - off)
                            try:
                                buf = entry.read_random(off, n)
                            except Exception:
                                break
                            if not buf:
                                break
                            fh.write(buf)
                            off += len(buf)
                    stats["files"] += 1
                    stats["bytes"] += size
                    if progress and stats["files"] % 300 == 0:
                        progress.update(min(90, 40 + int(stats["files"] / MAX_FILES * 50)),
                                        f"Ekstrahovano {stats['files']} fajlova iz slike…")
                except Exception:
                    stats["errors"] += 1

    try:
        root = fs.open_dir(path="/")
    except Exception:
        return
    out = out_root / base_prefix if base_prefix else out_root
    walk(root, base_prefix, 0)


def analyze_image(image_path, out_dir, progress=None, cancel=None) -> dict:
    """
    Otvori sliku, obiđi particije/fajl sisteme i ekstrahuj fajlove u out_dir.
    Vraća statistiku (fajlovi, bajtovi, particije, neprepoznati/šifrovani FS).
    """
    import pytsk3
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = {"files": 0, "bytes": 0, "errors": 0, "partitions": 0,
             "unrecognized": 0, "filesystems": [], "capped": False}

    try:
        img = pytsk3.Img_Info(str(image_path))
    except Exception as e:
        raise RuntimeError(f"Ne mogu da otvorim sliku ({image_path}): {e}")

    # Particiona tabela? (mmls)
    partitions = []
    try:
        vol = pytsk3.Volume_Info(img)
        sector = getattr(vol.info, "block_size", 512) or 512
        for part in vol:
            try:
                if part.len < 2:
                    continue
                partitions.append((int(part.start) * sector,
                                   part.desc.decode("utf-8", "replace")))
            except Exception:
                continue
    except Exception:
        partitions = []

    def _try_fs(offset_bytes, label):
        try:
            fs = pytsk3.FS_Info(img, offset=offset_bytes)
        except Exception as e:
            stats["unrecognized"] += 1
            stats["filesystems"].append({"label": label, "recognized": False, "note": str(e)[:80]})
            if progress:
                progress.log(f"{label}: fajl sistem NIJE prepoznat (moguće FBE enkripcija / "
                             f"f2fs koji TSK ne podržava): {str(e)[:80]}")
            return
        is_userdata = _fs_root_looks_like_userdata(fs)
        prefix = "data" if is_userdata else label
        stats["partitions"] += 1
        stats["filesystems"].append({"label": label, "recognized": True, "userdata": is_userdata})
        if progress:
            progress.log(f"{label}: fajl sistem prepoznat"
                         + (" (izgleda kao /data → pod 'data/')" if is_userdata else ""))
        _extract_fs(pytsk3, fs, out_dir, prefix, progress, cancel, stats)

    if partitions:
        for off, desc in partitions:
            if cancel and cancel():
                break
            _try_fs(off, f"vol_{off // 512}")
    else:
        # Jedna slika = jedan FS (npr. userdata.img)
        _try_fs(0, "img")

    return stats
