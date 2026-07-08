"""
modules/anti_forensics.py — Anti-Forensics Detection (Upgrade #5)
────────────────────────────────────────────────────────────────
Detekcija tragova prikrivanja/manipulacije, isključivo iz podataka koji
STVARNO postoje u logičkom dump-u. Isti interfejs kao ostali moduli:
analyze(dump_path) -> module_result(status, findings, artifacts, alerts).

Detektori:
  1. Obrisani artefakti   — SQLite freelist + rowid-gap + WAL frame residue
                            (max_rowid > row_count → obrisani redovi)
  2. Root/tampering       — build.prop (ro.debuggable, ro.secure, test-keys)
                            + su/magisk/busybox putanje i paketi
  3. Timestamp manipulacija — EXIF DateTimeOriginal vs file mtime vs ms-epoch ime
  4. Fake GPS             — mock-location u settings + nemoguća brzina (haversine)
  5. Log wiping           — prazni/skraćeni sistemski logovi
  6. Encryption toggling  — SQLCipher enkriptovane baze (nedostupan sadržaj)

Sve lokalno, bez izmišljanja. Svaki nalaz nosi konkretan izvor.
"""

import re
from pathlib import Path
from datetime import datetime, timezone

from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import artifact, finding, module_result, haversine_km

SQLITE_MAGIC = b"SQLite format 3\x00"
ROOT_PATH_HINTS = ["su", "magisk", "busybox", "supersu", "xposed"]
ROOT_PKG_HINTS = ["eu.chainfire.supersu", "com.topjohnwu.magisk", "com.koushikdutta.superuser",
                  "de.robv.android.xposed.installer"]
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".heic"}
IMPOSSIBLE_SPEED_KMH = 1000   # brže od putničkog aviona → sumnjivo/fake GPS


def _is_sqlite(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except Exception:
        return False


def _detect_deleted_rows(resolver, findings, artifacts_list, alerts):
    """SQLite freelist + rowid-gap analiza nad ključnim bazama."""
    idx = resolver._build_sqlite_index()
    # ciljamo baze sa forenzički vrednim tabelama
    targets = {"calls", "sms", "pdu", "raw_contacts", "urls", "visits", "message", "messages"}
    checked = 0
    total_deleted_est = 0
    for path, tables in idx.items():
        if checked >= 40:
            break
        hit = targets & set(tables)
        if not hit:
            continue
        checked += 1
        try:
            with SafeDBReader(path) as db:
                freelist = db.freelist_count()
                wal = db.wal_frame_count()
                for t in sorted(hit):
                    maxid = db.max_rowid(t)
                    cnt = db.row_count(t)
                    # rowid-gap je validan indikator brisanja SAMO ako su rowid-ovi
                    # približno sekvencijalni (maxid ~ cnt). Aplikacije koje koriste
                    # timestamp/nasumične id-eve daju ogroman maxid uz malo redova —
                    # to NIJE brisanje, pa se ignoriše (izbegavamo lažni ~2^63).
                    sequential = (maxid > 0 and cnt >= 0 and maxid <= max(1000, cnt * 10))
                    gap = (maxid - cnt) if sequential else 0
                    gap = gap if gap > 0 else 0
                    if gap > 0 or freelist > 0 or wal > 0:
                        if gap > 0:
                            total_deleted_est += gap
                        note = "" if sequential else " (rowid nesekvencijalni — gap nije pouzdan)"
                        artifacts_list.append(artifact(
                            "anti_forensic",
                            f"Tragovi brisanja u {path.name}/{t}: rowid_max={maxid}, redova={cnt}, "
                            f"gap={gap}, freelist={freelist}, wal_frames={wal}{note}",
                            str(path.name),
                            extra={"table": t, "rowid_gap": gap, "freelist": freelist,
                                   "wal_frames": wal, "indicator": "deleted_rows",
                                   "suspicious": gap > 0 or freelist > 0},
                        ))
        except Exception:
            continue
    if total_deleted_est > 0:
        alerts.append(f"Detektovani tragovi brisanja: procenjeno ~{total_deleted_est} obrisanih redova "
                      f"(rowid gap) u komunikacionim bazama — indikator uklanjanja dokaza.")
    findings.append(finding("Baze provereno na brisanje", str(checked)))
    findings.append(finding("Procenjeno obrisanih redova (rowid gap)", str(total_deleted_est)))


def _detect_root(resolver, findings, artifacts_list, alerts):
    """build.prop bezbednosni flagovi + su/magisk/busybox putanje i paketi."""
    props = {}
    for bp in resolver.find_files_by_regex(r"^build\.prop$"):
        try:
            for line in bp.read_text(errors="replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
        except Exception:
            continue

    flags = []
    if props.get("ro.debuggable") == "1":
        flags.append("ro.debuggable=1")
    if props.get("ro.secure") == "0":
        flags.append("ro.secure=0")
    tags = props.get("ro.build.tags", "")
    if "test-keys" in tags:
        flags.append(f"ro.build.tags={tags}")
    if flags:
        alerts.append(f"Bezbednosni build flagovi ukazuju na modifikovan/rootovan sistem: {', '.join(flags)}.")
        artifacts_list.append(artifact("anti_forensic", f"Rootovan/dev build: {', '.join(flags)}",
                                       "build.prop", extra={"indicator": "root_build_flags", "suspicious": True}))

    # su/magisk binarni tragovi bilo gde
    found_bins = []
    for name in ROOT_PATH_HINTS:
        try:
            m = resolver.find_files_by_regex(rf"^{re.escape(name)}$")
        except Exception:
            m = []
        for p in m[:3]:
            found_bins.append(p.name)
    installed = set(resolver.list_installed_packages())
    root_pkgs = [p for p in ROOT_PKG_HINTS if p in installed]
    if found_bins or root_pkgs:
        alerts.append(f"Root indikatori: binarni tragovi {sorted(set(found_bins)) or '—'}, "
                      f"paketi {root_pkgs or '—'}.")
        artifacts_list.append(artifact("anti_forensic",
                                       f"Root alati: {', '.join(sorted(set(found_bins)) + root_pkgs)}",
                                       "filesystem/packages",
                                       extra={"indicator": "root_tools", "suspicious": True}))
    findings.append(finding("Root indikatori (flagovi/alati)", str(len(flags) + len(found_bins) + len(root_pkgs))))


def _exif_dt(path):
    try:
        from PIL import Image
        with Image.open(path) as im:
            ex = im._getexif() or {}
        # 36867 DateTimeOriginal, 306 DateTime
        raw = ex.get(36867) or ex.get(306)
        if raw:
            return datetime.strptime(str(raw), "%Y:%m:%d %H:%M:%S")
    except Exception:
        return None
    return None


def _detect_timestamp_manipulation(resolver, findings, artifacts_list, alerts):
    """EXIF vreme vs mtime vs ms-epoch iz imena fajla — nesklad = manipulacija."""
    mism = 0
    checked = 0
    for rel in ("data/media/0/DCIM", "data/media/0/DCIM/Camera", "data/media/0/Download"):
        d = resolver.root / rel
        if not d.exists():
            continue
        imgs = sorted([f for f in d.rglob("*") if f.is_file() and f.suffix.lower() in IMAGE_EXT])
        for img in imgs[:150]:
            checked += 1
            exif_dt = _exif_dt(img)
            try:
                mtime = datetime.utcfromtimestamp(img.stat().st_mtime)
            except Exception:
                mtime = None
            # ms-epoch u imenu (npr. 1618756982374.jpg)
            m = re.match(r"^(\d{13})\.", img.name)
            name_dt = None
            if m:
                try:
                    name_dt = datetime.utcfromtimestamp(int(m.group(1)) / 1000)
                except Exception:
                    name_dt = None

            anomalies = []
            if exif_dt and mtime and abs((exif_dt - mtime).total_seconds()) > 86400:
                anomalies.append(f"EXIF({exif_dt:%Y-%m-%d}) vs mtime({mtime:%Y-%m-%d}) razlika >1 dan")
            if exif_dt and name_dt and abs((exif_dt - name_dt).total_seconds()) > 86400:
                anomalies.append(f"EXIF vs ime-epoha razlika >1 dan")
            if anomalies:
                mism += 1
                artifacts_list.append(artifact(
                    "anti_forensic", f"Nesklad vremena za {img.name}: {'; '.join(anomalies)}",
                    str(img.relative_to(resolver.root)),
                    extra={"indicator": "timestamp_manipulation", "suspicious": True}))
    if mism:
        alerts.append(f"Detektovan nesklad vremenskih oznaka na {mism} fotografija (EXIF/mtime/ime) "
                      f"— mogući indikator manipulacije vremenom.")
    findings.append(finding("Slike provereno na manipulaciju vremena", str(checked)))
    findings.append(finding("Slike sa neskladom vremena", str(mism)))


def _detect_fake_gps(resolver, findings, artifacts_list, alerts):
    """Mock-location provider + nemoguća brzina između uzastopnih GPS tačaka."""
    # 1) mock location u settings (secure) baze/xml
    mock = False
    for m in resolver.find_files_by_regex(r"^settings_secure\.xml$") + resolver.find_files_by_regex(r"^settings\.db$"):
        try:
            txt = m.read_text(errors="replace") if m.suffix == ".xml" else ""
            if "mock_location" in txt and (">1<" in txt or "value=\"1\"" in txt):
                mock = True
        except Exception:
            continue
    if mock:
        alerts.append("Uključena 'mock_location' opcija u sistemskim podešavanjima — indikator lažne GPS lokacije.")
        artifacts_list.append(artifact("anti_forensic", "Mock location omogućen (settings)",
                                       "settings", extra={"indicator": "fake_gps_setting", "suspicious": True}))

    # 2) nemoguća brzina iz EXIF GPS niza
    from PIL import Image, ExifTags
    pts = []
    dcim = resolver.root / "data/media/0/DCIM"
    if dcim.exists():
        for img in sorted([f for f in dcim.rglob("*") if f.suffix.lower() in IMAGE_EXT])[:200]:
            try:
                with Image.open(img) as im:
                    ex = im._getexif() or {}
                gps = ex.get(34853)  # GPSInfo
                dt = ex.get(36867) or ex.get(306)
                if gps and dt:
                    def _dec(dms, ref):
                        d, mm, s = [float(x) for x in dms]
                        val = d + mm / 60 + s / 3600
                        return -val if ref in ("S", "W") else val
                    lat = _dec(gps[2], gps[1]); lon = _dec(gps[4], gps[3])
                    t = datetime.strptime(str(dt), "%Y:%m:%d %H:%M:%S")
                    pts.append((t, lat, lon, img.name))
            except Exception:
                continue
    pts.sort()
    impossible = 0
    for (t1, la1, lo1, n1), (t2, la2, lo2, n2) in zip(pts, pts[1:]):
        dt_h = abs((t2 - t1).total_seconds()) / 3600
        if dt_h <= 0:
            continue
        km = haversine_km(la1, lo1, la2, lo2)
        speed = km / dt_h
        if speed > IMPOSSIBLE_SPEED_KMH:
            impossible += 1
            artifacts_list.append(artifact(
                "anti_forensic",
                f"Nemoguća brzina {speed:.0f} km/h između {n1} i {n2} ({km:.0f}km za {dt_h:.2f}h) — mogući lažni GPS",
                n2, extra={"indicator": "impossible_speed", "speed_kmh": round(speed), "suspicious": True}))
    if impossible:
        alerts.append(f"Detektovano {impossible} segmenata sa nemogućom brzinom kretanja (GPS) — mogući lažni GPS.")
    findings.append(finding("GPS tačaka analizirano (brzina)", str(len(pts))))
    findings.append(finding("Segmenata sa nemogućom brzinom", str(impossible)))


def _detect_encryption_toggling(resolver, findings, artifacts_list, alerts):
    """SQLCipher enkriptovane baze (npr. Signal) — sadržaj nedostupan bez ključa."""
    enc = 0
    for pkg in ("org.thoughtcrime.securesms",):
        root = resolver.pkg_root(pkg) if hasattr(resolver, "pkg_root") else None
        if not root:
            continue
        dbdir = root / "databases"
        if dbdir.exists():
            for db in dbdir.glob("*.db"):
                if not _is_sqlite(db):   # nema plaintext SQLite header → verovatno SQLCipher
                    enc += 1
                    artifacts_list.append(artifact(
                        "anti_forensic", f"Enkriptovana baza (SQLCipher): {db.name} — sadržaj nedostupan bez ključa",
                        db.name, extra={"indicator": "encrypted_db", "package": pkg, "suspicious": True}))
    if enc:
        alerts.append(f"{enc} enkriptovanih baza (SQLCipher) — enkripcija kao anti-forenzička mera.")
    findings.append(finding("Enkriptovanih baza (SQLCipher)", str(enc)))


def _detect_log_wiping(resolver, findings, artifacts_list, alerts):
    """
    Log wiping: sistemski logovi/dnevnici prisutni ali PRAZNI/skraćeni dok
    uređaj očigledno ima aktivnost (postoje SMS/pozivi/notifikacije baze).
    Prazan log uz aktivan uređaj = mogući indikator brisanja tragova.
    """
    # da li uređaj uopšte ima aktivnosti (postoji bar jedna komunikaciona baza sa redovima)
    idx = resolver._build_sqlite_index()
    device_active = any({"sms", "calls"} & set(t) for t in idx.values())

    empty_logs = []
    LOG_DIRS = ["data/system/dropbox", "data/misc/logd", "data/log", "data/tombstones",
                "data/system/usagestats"]
    for rel in LOG_DIRS:
        d = resolver.root / rel
        if d.exists() and d.is_dir():
            files = [f for f in d.rglob("*") if f.is_file()]
            nonempty = [f for f in files if _safe_size(f) > 0]
            if not nonempty:
                empty_logs.append(rel)

    # prazna notification/usage baza uz aktivan uređaj
    empty_dbs = []
    for path, tables in idx.items():
        if path.name in ("notification_log.db",) and device_active:
            try:
                with SafeDBReader(path) as db:
                    for t in tables:
                        if "notification" in t.lower() or "log" in t.lower():
                            if db.row_count(t) == 0:
                                empty_dbs.append(f"{path.name}/{t}")
            except Exception:
                continue

    if empty_logs or empty_dbs:
        alerts.append(
            f"Mogući log wiping: prazni dnevnici {empty_logs or '—'} / prazne log tabele "
            f"{empty_dbs[:3] or '—'} uz aktivan uređaj — indikator brisanja tragova.")
        artifacts_list.append(artifact("anti_forensic",
                                       f"Prazni logovi/dnevnici: {', '.join(empty_logs + empty_dbs) or '—'}",
                                       "system logs",
                                       extra={"indicator": "log_wiping", "suspicious": True}))
    findings.append(finding("Praznih log lokacija", str(len(empty_logs) + len(empty_dbs))))


def _safe_size(f):
    try:
        return f.stat().st_size
    except Exception:
        return 0


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    findings, artifacts_list, alerts = [], [], []

    for detector in (_detect_deleted_rows, _detect_root, _detect_timestamp_manipulation,
                     _detect_fake_gps, _detect_encryption_toggling, _detect_log_wiping):
        try:
            detector(resolver, findings, artifacts_list, alerts)
        except Exception as e:
            findings.append(finding(f"Greška u {detector.__name__}", str(e)))

    status = "completed" if (findings or artifacts_list) else "not_found"
    return module_result(status=status, findings=findings, artifacts=artifacts_list, alerts=alerts)
