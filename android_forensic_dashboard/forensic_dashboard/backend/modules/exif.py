"""
modules/exif.py
────────────────
Analiza slika u korisničkom storage-u (DCIM, Pictures, Download, WhatsApp...):
  - EXIF GPS koordinate → fizička lokacija snimanja
  - DateTimeOriginal → vreme snimanja
  - Make/Model → uređaj kojim je fotografija snimljena (može se razlikovati
    od analiziranog uređaja → fotografija je primljena/transferovana)
  - Detekcija fotografija bez EXIF-a (mogući indikator "screenshot" ili
    edit/strip alata)

Korišćena biblioteka: Pillow (PIL.Image / PIL.ExifTags). Ako Pillow nije
instaliran, modul vraća status "error" sa jasnom porukom.
"""

from pathlib import Path
from datetime import datetime, timezone

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result, dms_to_decimal, coords_to_str

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".3gp", ".m4v", ".mkv"}

# Direktorijumi koje pretražujemo (relativno na root dump-a)
SEARCH_DIRS = [
    "data/media/0/DCIM",
    "data/media/0/Pictures",
    "data/media/0/Download",
    "data/media/0/WhatsApp/Media/WhatsApp Images",
    "data/media/0/WhatsApp/Media/WhatsApp Video",
    "data/media/0/Movies",
    "data/media/0/Pictures/Screenshots",
]

MAX_IMAGES = 500  # bezbednosni limit za velike dump-ove
MAX_VIDEOS = 200

# Potpisi ugrađenih arhiva/fajlova (steganografija / skriveni sadržaj)
_EMBEDDED_SIGS = [(b"PK\x03\x04", "ZIP"), (b"Rar!\x1a\x07", "RAR"),
                  (b"7z\xbc\xaf\x27\x1c", "7z"), (b"%PDF", "PDF"),
                  (b"\x89PNG", "PNG-u-slici")]
_STEGO_TRAILING_MIN = 256   # bajtova posle EOI/IEND da bi bilo sumnjivo


def _check_image_stego(path: Path, data: bytes) -> list:
    """
    Detekcija skrivenog sadržaja u slici (bez izmišljanja):
      - podaci POSLE JPEG EOI (FFD9) ili PNG IEND markera (append stego)
      - ugrađeni potpisi arhiva/fajlova (ZIP/RAR/7z/PDF) unutar slike
    Vraća listu opisa nalaza (prazno ako čisto).
    """
    flags = []
    ext = path.suffix.lower()
    try:
        if ext in (".jpg", ".jpeg"):
            eoi = data.rfind(b"\xff\xd9")
            if eoi != -1:
                trailing = len(data) - (eoi + 2)
                if trailing >= _STEGO_TRAILING_MIN:
                    flags.append(f"{trailing}B podataka POSLE JPEG EOI markera (append stego)")
        elif ext == ".png":
            iend = data.rfind(b"IEND")
            if iend != -1:
                trailing = len(data) - (iend + 8)
                if trailing >= _STEGO_TRAILING_MIN:
                    flags.append(f"{trailing}B podataka POSLE PNG IEND (append stego)")
        # ugrađeni fajl-potpisi (preskoči prvih 64B = zaglavlje same slike)
        for sig, name in _EMBEDDED_SIGS:
            idx = data.find(sig, 64)
            if idx != -1:
                flags.append(f"ugrađen {name} potpis na offsetu {idx}")
                break
    except Exception:
        pass
    return flags


def _video_metadata(path: Path) -> dict:
    """
    Metapodaci video snimka (MP4/MOV...) preko mutagen: vreme snimanja,
    GPS (©xyz ISO-6709), trajanje. Radi bez ffmpeg-a.
    """
    out = {"ts": None, "lat": None, "lon": None, "duration": None, "make": None}
    try:
        from mutagen.mp4 import MP4
        m = MP4(str(path))
        if m.info is not None:
            out["duration"] = round(getattr(m.info, "length", 0) or 0, 1)
        tags = m.tags or {}
        # vreme snimanja
        day = tags.get("\xa9day")
        if day:
            raw = str(day[0])[:19].replace("T", " ").replace("-", ":", 2)
            out["ts"] = _exif_to_iso(raw) or (str(day[0])[:19] + "Z" if len(str(day[0])) >= 10 else None)
            if out["ts"] is None and len(str(day[0])) >= 10:
                out["ts"] = str(day[0])[:19]
                if "T" not in out["ts"]:
                    out["ts"] = out["ts"].replace(" ", "T") + "Z"
        # GPS ISO-6709 npr. "+46.5220+006.5752/"
        xyz = tags.get("\xa9xyz") or tags.get("com.apple.quicktime.location.ISO6709")
        if xyz:
            s = str(xyz[0])
            import re as _re
            mt = _re.findall(r"([+-]\d+\.\d+)", s)
            if len(mt) >= 2:
                out["lat"], out["lon"] = float(mt[0]), float(mt[1])
        mk = tags.get("\xa9mak") or tags.get("com.apple.quicktime.make")
        if mk:
            out["make"] = str(mk[0])
    except Exception:
        pass
    return out


def _exif_to_iso(value) -> str | None:
    """EXIF DateTimeOriginal je 'YYYY:MM:DD HH:MM:SS' bez timezone-a."""
    if not value:
        return None
    try:
        dt = datetime.strptime(str(value), "%Y:%m:%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _gps_to_decimal(gps_info: dict) -> tuple[float, float] | None:
    """Konvertuje EXIF GPSInfo dict u (lat, lon) decimalne koordinate."""
    try:
        lat_dms = gps_info.get(2)
        lat_ref = gps_info.get(1)
        lon_dms = gps_info.get(4)
        lon_ref = gps_info.get(3)
        if not (lat_dms and lon_dms and lat_ref and lon_ref):
            return None

        def _to_float(x):
            return float(x)

        lat = dms_to_decimal(_to_float(lat_dms[0]), _to_float(lat_dms[1]), _to_float(lat_dms[2]), lat_ref)
        lon = dms_to_decimal(_to_float(lon_dms[0]), _to_float(lon_dms[1]), _to_float(lon_dms[2]), lon_ref)
        return lat, lon
    except Exception:
        return None


def analyze(dump_path: str) -> dict:
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return module_result(
            status="error",
            findings=[finding("Greška", "Pillow (PIL) nije instaliran — 'pip install pillow'")],
            artifacts=[],
            alerts=[],
            error="Pillow not installed",
        )

    resolver = DumpResolver(dump_path)

    # Build reverse tag-name lookup
    TAGS = {v: k for k, v in ExifTags.TAGS.items()}
    GPS_TAGS = {v: k for k, v in ExifTags.GPSTAGS.items()}

    findings = []
    artifacts_list = []
    alerts = []

    image_files: list[Path] = []
    for rel_dir in SEARCH_DIRS:
        full_dir = resolver.root / rel_dir
        if full_dir.exists():
            for f in full_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
                    image_files.append(f)

    if not image_files:
        return module_result(
            status="not_found",
            findings=[finding("Status", "Nisu pronađene slike u DCIM/Pictures/Download")],
            artifacts=[],
            alerts=[],
        )

    truncated = len(image_files) > MAX_IMAGES
    image_files = image_files[:MAX_IMAGES]

    total = len(image_files)
    with_gps = 0
    without_exif = 0
    stego_count = 0
    devices_seen = set()
    locations = []  # (lat, lon, ts, path)

    for img_path in image_files:
        rel_path = str(img_path.relative_to(resolver.root)) if resolver.root in img_path.parents else str(img_path)

        # ── Steganografija / skriveni sadržaj — proveri SIROVE bajtove PRE EXIF-a
        # (radi i za slike bez EXIF-a, gde se stego najčešće krije). Cap 25MB.
        try:
            if img_path.stat().st_size <= 25 * 1024 * 1024:
                raw = img_path.read_bytes()
                sflags = _check_image_stego(img_path, raw)
                if sflags:
                    stego_count += 1
                    artifacts_list.append(artifact(
                        "media",
                        f"⚠ Skriveni sadržaj u slici {img_path.name}: {'; '.join(sflags)}",
                        rel_path,
                        extra={"filename": img_path.name, "stego": True, "suspicious": True,
                               "indicators": sflags},
                    ))
        except Exception:
            pass

        try:
            with Image.open(img_path) as img:
                exif_raw = img._getexif()
        except Exception:
            without_exif += 1
            continue

        if not exif_raw:
            without_exif += 1
            continue

        exif = {ExifTags.TAGS.get(k, k): v for k, v in exif_raw.items()}

        make = str(exif.get("Make", "")).strip()
        model = str(exif.get("Model", "")).strip()
        date_taken = _exif_to_iso(exif.get("DateTimeOriginal") or exif.get("DateTime"))

        if make or model:
            devices_seen.add(f"{make} {model}".strip())

        gps_info = exif.get("GPSInfo")
        coords = None
        if gps_info:
            # GPSInfo dict ima numeričke ključeve po GPS IFD spec-u
            gps_named = {GPS_TAGS.get(k, k): v for k, v in gps_info.items()} if isinstance(gps_info, dict) else None
            # dms_to_decimal očekuje gps_info sa numeričkim ključevima 1-4
            coords = _gps_to_decimal(gps_info if isinstance(gps_info, dict) else {})

        rel_path = str(img_path.relative_to(resolver.root)) if resolver.root in img_path.parents else str(img_path)

        if coords:
            with_gps += 1
            lat, lon = coords
            locations.append((lat, lon, date_taken, rel_path))

            value = f"📷 {coords_to_str(lat, lon)}"
            if make or model:
                value += f" — snimljeno: {make} {model}".strip()
            value += f" ({img_path.name})"

            artifacts_list.append(artifact(
                "location",
                value,
                rel_path,
                ts=date_taken,
                extra={
                    "lat": lat,
                    "lon": lon,
                    "device": f"{make} {model}".strip(),
                    "filename": img_path.name,
                },
            ))
        elif date_taken or make or model:
            value = f"📷 {img_path.name}"
            if date_taken:
                value += f" — snimljeno {date_taken}"
            if make or model:
                value += f" na {make} {model}".strip()
            artifacts_list.append(artifact(
                "media",
                value,
                rel_path,
                ts=date_taken,
                extra={"device": f"{make} {model}".strip(), "filename": img_path.name, "has_gps": False},
            ))

    # ── VIDEO snimci (MP4/MOV...) — metapodaci: vreme, GPS, trajanje ──────
    video_files = []
    for rel_dir in SEARCH_DIRS:
        full_dir = resolver.root / rel_dir
        if full_dir.exists():
            for f in full_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in VIDEO_EXTENSIONS:
                    video_files.append(f)
    video_files = sorted(set(video_files))[:MAX_VIDEOS]
    video_gps = 0
    for vid in video_files:
        vrel = str(vid.relative_to(resolver.root)) if resolver.root in vid.parents else str(vid)
        meta = _video_metadata(vid)
        dur = f"{meta['duration']}s" if meta.get("duration") else "?"
        if meta.get("lat") is not None and meta.get("lon") is not None:
            video_gps += 1
            locations.append((meta["lat"], meta["lon"], meta.get("ts"), vrel))
            artifacts_list.append(artifact(
                "location",
                f"🎬 {coords_to_str(meta['lat'], meta['lon'])} — video {vid.name} ({dur})",
                vrel, ts=meta.get("ts"),
                extra={"lat": meta["lat"], "lon": meta["lon"], "filename": vid.name,
                       "media_kind": "video", "duration": meta.get("duration")},
            ))
        else:
            artifacts_list.append(artifact(
                "media",
                f"🎬 Video {vid.name} — {dur}" + (f", snimljeno {meta['ts']}" if meta.get("ts") else ""),
                vrel, ts=meta.get("ts"),
                extra={"filename": vid.name, "media_kind": "video", "duration": meta.get("duration"),
                       "make": meta.get("make")},
            ))

    findings += [
        finding("Ukupno analizirano slika", str(total) + (" (ograničeno)" if truncated else "")),
        finding("Slike sa GPS koordinatama", str(with_gps)),
        finding("Slike bez EXIF metapodataka", str(without_exif)),
        finding("Slike sa skrivenim sadržajem (stego)", str(stego_count)),
        finding("Analizirano video snimaka", str(len(video_files))),
        finding("Video snimci sa GPS", str(video_gps)),
        finding("Uređaji koji su snimili slike", ", ".join(sorted(d for d in devices_seen if d)) or "Nepoznato"),
    ]

    # ── Upozorenja ─────────────────────────────────────────────────────────
    if with_gps > 0 or video_gps > 0:
        alerts.append(
            f"Pronađeno {with_gps} fotografija i {video_gps} video snimaka sa GPS metapodacima — "
            f"omogućava rekonstrukciju kretanja korisnika u vremenu."
        )

    if stego_count > 0:
        alerts.append(
            f"Detektovan skriveni sadržaj u {stego_count} slika (podaci posle EOI/IEND markera "
            f"ili ugrađene arhive) — mogući indikator steganografije / prikrivanja podataka."
        )

    if without_exif > total * 0.5 and total > 5:
        alerts.append(
            f"Većina slika ({without_exif}/{total}) nema EXIF metapodatke — "
            f"mogući indikator skrinšotova, preuzetih/komprimovanih fajlova ili EXIF-stripping alata."
        )

    if truncated:
        alerts.append(f"Analiza ograničena na prvih {MAX_IMAGES} slika zbog veličine dump-a.")

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
