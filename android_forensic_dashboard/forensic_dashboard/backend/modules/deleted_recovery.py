"""
modules/deleted_recovery.py
───────────────────────────
Pokušaj oporavka OBRISANIH podataka vidljivih u LOGIČKOM dump-u.

VAŽNO — OGRANIČENJE LOGIČKOG DUMP-A:
  Logički dump sadrži samo alocirane fajlove fajl-sistema. Pravo "carving"
  neraspoređenog (unallocated) prostora particije zahteva FIZIČKU sliku
  (bit-po-bit), koja ovde NIJE dostupna. Zato se ne rekonstruišu potpuno
  obrisani fajlovi iz slobodnog prostora diska — umesto toga primenjuju se
  pragmatične, pouzdane tehnike nad fajlovima koji JESU u dump-u:

    1) SQLite freelist / unallocated cell recovery — čitljivi tekstualni
       fragmenti (poruke, brojevi, adrese) u sirovim bajtovima baze kojih
       NEMA u živim (live) redovima tabela → "moguć obrisan sadržaj".
    2) WAL rezidua — prisustvo/veličina <db>-wal fajla; nepreuzeti
       (uncheckpointed) ili obrisani redovi mogu biti tamo (flag, ne parsira
       se WAL binarni format).
    3) Trashed / pending / .Trash media — Android '.trashed-*', '.pending-*',
       fajlovi u '.Trash'/'.trash' folderima → media koja se oporavlja "u mestu".
    4) Siročad thumbnail-ovi — thumbnail-ovi u DCIM/.thumbnails i
       Pictures/.thumbnails čiji originalni fajl više ne postoji u galeriji →
       dokaz o obrisanim fotografijama.

Nikad se ne izmišlja: šifrovane baze se ne "čitaju", samo se prijavljuju
fragmenti koje sirovi bajtovi zaista sadrže.
"""

import re
from pathlib import Path

from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    sec_to_iso, normalize_phone,
)


# ── Ograničenja skeniranja (velike baze / dump-ovi) ──────────────────────────
MAX_DB_BYTES = 64 * 1024 * 1024        # ne učitavaj baze veće od 64 MB u RAM
MAX_FRAGMENTS_PER_DB = 80              # najviše fragmenata po bazi (UI-friendly)
MAX_TOTAL_FRAGMENTS = 600             # globalni cap na fragmente
MAX_LIVE_TEXT_BYTES = 8 * 1024 * 1024  # cap na prikupljanje živog teksta
MAX_ARTIFACTS = 800                   # globalni cap na artefakte
MIN_FRAG_LEN = 8                      # minimalna dužina čitljivog stringa

# Baze koje ciljano skeniramo za obrisanim sadržajem (ključ resolver-a).
KEY_DBS = ["mmssms", "calllog", "contacts2"]

# Ekstenzije slika koje smatramo "galerijskim" originalima.
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif",
              ".dng", ".mp4", ".3gp", ".mov"}

# Čitljiv ASCII/UTF-8 tekst: štampljivi znakovi (uklj. razmak) dužine >= MIN.
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_FRAG_LEN)

# Fragmenti koji "liče" na forenzički zanimljiv sadržaj (telefon / URL / reč).
_PHONE_RE = re.compile(r"\+?\d[\d\s().-]{6,}\d")
_WORD_RE = re.compile(r"[A-Za-zČčĆćĐđŠšŽž]{4,}")

# Šum koji NE prijavljujemo kao "obrisan sadržaj" (SQLite/interni tokeni).
_NOISE_TOKENS = (
    "CREATE TABLE", "CREATE INDEX", "CREATE TRIGGER", "CREATE VIEW",
    "sqlite_", "android_metadata", "PRIMARY KEY", "INTEGER", "AUTOINCREMENT",
    "REFERENCES", "DEFAULT", "NOT NULL", "BEGIN", "COMMIT", "SELECT ", "UPDATE ",
    "WITHOUT ROWID", "SQLITE FORMAT", "canonical_addresses", "recipient_ids",
    "CONSTRAINT", "UNIQUE", "FOREIGN KEY",
)

# Cele reči koje su nazivi tabela/kolona (kada je fragment TAČNO taj token —
# to je struktura baze, ne obrisan sadržaj).
_STRUCT_EXACT = {
    "canonical_addresses", "recipient_ids", "thread_id", "message_count",
    "android_metadata", "raw_contacts", "view_contacts", "sqlite_sequence",
}


def _clean_fragment(frag: str) -> str:
    """
    Očisti fragment izvučen iz sirovih bajtova: SQLite često čuva jedan
    kontrolni/serijalni bajt neposredno pre stringa ćelije (npr. '!0766...',
    '%+4178...'). Skini vodeći ne-alfanumerički/ne-plus šum, sačuvaj '+'.
    """
    return re.sub(r"^[^\w+]+", "", frag).strip()


def _looks_interesting(frag: str) -> bool:
    """Da li fragment liči na poruku / broj / adresu (a ne na SQL šum)."""
    if len(frag) < MIN_FRAG_LEN:
        return False
    up = frag.upper()
    for noise in _NOISE_TOKENS:
        if noise.upper() in up:
            return False
    # Tačan naziv tabele/kolone → struktura baze, ne obrisan sadržaj.
    if _norm(frag) in _STRUCT_EXACT:
        return False
    # SQLite sqlite_master zapisi šeme: '<index|table><ime><ime>...' bez razmaka.
    # Ako fragment nema NIJEDAN razmak a počinje sa index/table/trigger/view —
    # to je serijalizovan red šeme, ne korisnički tekst.
    low = frag.lower()
    if " " not in frag:
        # Direktno, ili sa jednim vodećim serijalnim bajtom (npr. 'qindexspam_addr').
        core = low[1:] if len(low) > 1 else low
        if low.startswith(("index", "table", "trigger", "view")) or \
           core.startswith(("index", "table", "trigger", "view")):
            return False
    # Mora imati broj telefona ILI bar dve prave reči (sprečava heksadecimalni/ID šum).
    if _PHONE_RE.search(frag):
        return True
    if len(_WORD_RE.findall(frag)) >= 2:
        return True
    return False


def _norm(s: str) -> str:
    """Normalizacija za poređenje sa živim sadržajem (case + razmaci)."""
    return re.sub(r"\s+", " ", s.strip().lower())


def _collect_live_text(db_path: Path) -> set:
    """
    Prikupi sav tekstualni sadržaj iz ŽIVIH (live) redova baze — da bismo
    fragmente iz sirovih bajtova mogli uporediti i zadržati samo one kojih
    NEMA u živim redovima (kandidati za obrisan sadržaj).
    Tolerantno: greške/nepostojeće kolone se preskaču, nikad ne krešira.
    """
    live = set()
    collected = 0
    try:
        with SafeDBReader(db_path) as db:
            for table in db.tables():
                if table.startswith("sqlite_") or table == "android_metadata":
                    continue
                try:
                    cols = db.columns(table)
                except Exception:
                    continue
                if not cols:
                    continue
                # Selektuj samo tekstualno-relevantne kolone; ograniči broj redova.
                col_list = ", ".join(f'"{c}"' for c in cols)
                rows = db.query(f'SELECT {col_list} FROM "{table}" LIMIT 20000')
                for row in rows:
                    for v in row.values():
                        if isinstance(v, str) and v:
                            n = _norm(v)
                            if n:
                                live.add(n)
                                collected += len(n)
                    if collected > MAX_LIVE_TEXT_BYTES:
                        return live
    except Exception:
        pass
    return live


def _scan_db_freespace(db_path: Path, live_text: set, source_name: str):
    """
    Tehnika 1: skeniraj SIROVE bajtove baze za čitljive fragmente kojih nema
    u živim redovima. Ovo pokriva freelist stranice i neraspoređeni prostor
    ćelija (obrisani redovi ostaju kao rezidua dok se stranica ne prepiše).
    Vraća listu artefakata.
    """
    out = []
    try:
        size = db_path.stat().st_size
    except Exception:
        return out
    if size == 0 or size > MAX_DB_BYTES:
        return out

    try:
        raw = db_path.read_bytes()
    except Exception:
        return out

    seen_frag = set()
    count = 0
    for m in _PRINTABLE_RE.finditer(raw):
        if count >= MAX_FRAGMENTS_PER_DB:
            break
        try:
            frag = m.group().decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        frag = _clean_fragment(frag)
        if not _looks_interesting(frag):
            continue
        norm = _norm(frag)
        # Već prijavljeno u ovoj bazi?
        if norm in seen_frag:
            continue
        # Postoji u živim redovima → NIJE obrisano, preskoči.
        if norm in live_text:
            continue
        # Delimično sadržan u nekom živom redu (npr. skraćeni snippet)?
        if any(norm in lt for lt in live_text if len(lt) >= len(norm)):
            continue

        seen_frag.add(norm)
        count += 1

        preview = frag if len(frag) <= 120 else frag[:117] + "..."
        phone_hit = _PHONE_RE.search(frag)
        kind = "phone/number" if phone_hit else "text"
        out.append(artifact(
            "note",
            f"Moguć OBRISAN sadržaj [{source_name}]: {preview}",
            source_name,
            ts=None,
            extra={
                "technique": "sqlite_freespace",
                "source": str(db_path),
                "detail": f"fragment ({kind}, {len(frag)}B) nije u živim redovima baze",
                "fragment": frag if len(frag) <= 512 else frag[:512],
            },
        ))
    return out


def _wal_residue(db_path: Path):
    """
    Tehnika 2: prijavi prisustvo i veličinu <db>-wal fajla. Redovi u WAL-u
    mogu biti nepreuzeti (uncheckpointed) ili obrisani. NE parsiramo binarni
    WAL format — samo flag + metapodaci.
    """
    wal = Path(str(db_path) + "-wal")
    try:
        if not wal.exists():
            return None
        wsize = wal.stat().st_size
    except Exception:
        return None
    if wsize <= 0:
        return None
    # Gruba procena broja frame-ova: header 32B, frame = 24B + page (~4096B).
    approx_frames = max(0, (wsize - 32) // (24 + 4096))
    return artifact(
        "note",
        f"WAL rezidua: {wal.name} ({wsize}B, ~{approx_frames} frame-ova) – "
        f"mogući nepreuzeti/obrisani redovi",
        wal.name,
        ts=None,
        extra={
            "technique": "wal_residue",
            "source": str(wal),
            "detail": f"veličina={wsize}B, procenjeno frame-ova≈{approx_frames}; "
                      f"WAL binarni format nije parsiran",
        },
    )


def _scan_trashed_media(resolver: DumpResolver):
    """
    Tehnika 3: nađi '.trashed-*', '.pending-*' fajlove i sve fajlove unutar
    '.Trash'/'.trash' foldera pod data/media. To je media koja je obrisana
    ("u kanti") ali se i dalje fizički nalazi u dump-u → oporaviva u mestu.
    """
    out = []
    media_root = resolver.root / "data" / "media"
    if not media_root.exists():
        return out

    seen = set()
    try:
        for dirpath, dirnames, filenames in __import__("os").walk(media_root):
            dp_lower = dirpath.lower()
            in_trash_dir = (f"{__import__('os').sep}.trash" in dp_lower
                            or dp_lower.endswith(f"{__import__('os').sep}.trash"))
            for name in filenames:
                lower = name.lower()
                is_trashed = lower.startswith(".trashed-")
                is_pending = lower.startswith(".pending-")
                if not (is_trashed or is_pending or in_trash_dir):
                    continue
                full = Path(dirpath) / name
                key = str(full)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    st = full.stat()
                    fsize = st.st_size
                    ts = sec_to_iso(int(st.st_mtime))
                except Exception:
                    fsize = 0
                    ts = None
                if is_trashed:
                    tech = "trashed_media"
                    label = "TRASHED"
                elif is_pending:
                    tech = "pending_media"
                    label = "PENDING"
                else:
                    tech = "trash_dir_media"
                    label = ".Trash folder"
                out.append(artifact(
                    "media",
                    f"Oporaviva OBRISANA media [{label}]: {name} ({fsize}B)",
                    name,
                    ts=ts,
                    extra={
                        "technique": tech,
                        "source": str(full),
                        "detail": f"{label}; fizički prisutna u dump-u, oporaviva u mestu",
                        "size": fsize,
                    },
                ))
                if len(out) >= MAX_ARTIFACTS:
                    return out
    except Exception:
        pass
    return out


def _gallery_original_stems(resolver: DumpResolver) -> set:
    """
    Skupi "stem"-ove (imena fajlova bez ekstenzije, lowercase) svih živih
    slika/video u galerijskim folderima (DCIM, Pictures). Koristi se da se
    utvrdi koji thumbnail-ovi više nemaju odgovarajući original.
    """
    stems = set()
    os = __import__("os")
    for key in ("dcim", "pictures"):
        base = resolver.resolve(key)
        if not base or not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            # ne ulazi u same thumbnail foldere
            dirnames[:] = [d for d in dirnames if d.lower() != ".thumbnails"]
            for name in filenames:
                p = Path(name)
                if p.suffix.lower() in IMAGE_EXTS:
                    stems.add(p.stem.lower())
    return stems


def _scan_orphan_thumbnails(resolver: DumpResolver):
    """
    Tehnika 4: nabroji thumbnail-ove u DCIM/.thumbnails i Pictures/.thumbnails.
    Best-effort orphan detekcija: thumbnail čiji "stem" (ime bez ekstenzije)
    NE odgovara nijednom živom originalu u galeriji → dokaz obrisane fotografije.

    Napomena o pouzdanosti: Samsung/Android često imenuje thumbnail-ove
    sekvencijalnim ID-om (npr. '47.jpg') ili heš imenom, a ne po originalu.
    Takve NE proglašavamo sirotim (nema pouzdanog mapiranja na original) —
    prijavljujemo ih neutralno kao "thumbnail bez dokaziv​e veze sa originalom".
    """
    out = []
    os = __import__("os")
    orphan_count = 0
    thumb_total = 0
    live_stems = _gallery_original_stems(resolver)

    thumb_dirs = []
    for key in ("dcim", "pictures"):
        base = resolver.resolve(key)
        if not base or not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            if Path(dirpath).name.lower() == ".thumbnails":
                thumb_dirs.append(Path(dirpath))

    for tdir in thumb_dirs:
        try:
            entries = list(tdir.iterdir())
        except Exception:
            continue
        for f in entries:
            if not f.is_file():
                continue
            if f.suffix.lower() not in IMAGE_EXTS:
                continue
            thumb_total += 1
            stem = f.stem.lower()
            # Sekvencijalni/heš ID (npr. '47', 'thumbdata') → nemamo mapiranje.
            is_numeric_id = stem.isdigit()
            has_original = stem in live_stems
            try:
                st = f.stat()
                fsize = st.st_size
                ts = sec_to_iso(int(st.st_mtime))
            except Exception:
                fsize = 0
                ts = None

            if not is_numeric_id and not has_original:
                # Pravi siroče: ime po originalu, a originala nema u galeriji.
                orphan_count += 1
                out.append(artifact(
                    "media",
                    f"DOKAZ OBRISANE FOTOGRAFIJE: thumbnail {f.name} bez originala u galeriji",
                    f.name,
                    ts=ts,
                    extra={
                        "technique": "orphan_thumbnail",
                        "source": str(f),
                        "detail": "thumbnail postoji, odgovarajući original ne postoji u DCIM/Pictures",
                        "size": fsize,
                    },
                ))
            else:
                # Neutralan zapis: thumbnail sa sekvencijalnim ID-om (nema pouzdanog mapiranja).
                out.append(artifact(
                    "media",
                    f"Thumbnail {f.name} ({fsize}B) – "
                    + ("original prisutan" if has_original else "ID-imenovan, veza sa originalom nedokaziva"),
                    f.name,
                    ts=ts,
                    extra={
                        "technique": "thumbnail_inventory",
                        "source": str(f),
                        "detail": ("odgovarajući original prisutan u galeriji" if has_original
                                   else "sekvencijalni/heš ID; mapiranje na original nije moguće iz logičkog dump-a"),
                        "size": fsize,
                    },
                ))
            if len(out) >= MAX_ARTIFACTS:
                return out, orphan_count, thumb_total
    return out, orphan_count, thumb_total


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    # Root mora postojati da bi bilo šta imalo smisla.
    if not resolver.root or not Path(resolver.root).exists():
        return not_found_result("DeletedRecovery", dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    # ── Trajno ograničenje logičkog dump-a (uvek prijavi) ────────────────────
    findings.append(finding(
        "Ograničenje logičkog dump-a",
        "Logički dump — carving neraspoređenog prostora particije nije moguć "
        "(zahteva fizičku sliku). Oporavak ograničen na rezidue u postojećim fajlovima.",
    ))

    # ═══ TEHNIKA 1 + 2: SQLite freespace + WAL rezidua ═══════════════════════
    scanned_dbs = []
    frag_total = 0
    wal_count = 0

    # (a) ciljane ključne baze
    target_db_paths = []
    for key in KEY_DBS:
        p = resolver.resolve_db(key)
        if p and p not in target_db_paths:
            target_db_paths.append(p)

    # (b) sve ostale SQLite baze iz deljenog indeksa (generički, bilo koji uređaj)
    try:
        sqlite_index = resolver._build_sqlite_index()
    except Exception:
        sqlite_index = {}
    for p in sqlite_index.keys():
        if p not in target_db_paths:
            target_db_paths.append(p)

    for db_path in target_db_paths:
        if frag_total >= MAX_TOTAL_FRAGMENTS:
            break
        try:
            source_name = db_path.name
        except Exception:
            continue

        # Tehnika 2: WAL rezidua (jeftino, uvek proveri)
        wal_art = _wal_residue(db_path)
        if wal_art:
            wal_count += 1
            if len(artifacts_list) < MAX_ARTIFACTS:
                artifacts_list.append(wal_art)

        # Tehnika 1: freespace fragmenti (skupo — ograniči na razumnu veličinu)
        live_text = _collect_live_text(db_path)
        frags = _scan_db_freespace(db_path, live_text, source_name)
        if frags:
            scanned_dbs.append((source_name, len(frags)))
            for a in frags:
                if frag_total >= MAX_TOTAL_FRAGMENTS or len(artifacts_list) >= MAX_ARTIFACTS:
                    break
                artifacts_list.append(a)
                frag_total += 1

    findings.append(finding("SQLite freespace fragmenti (moguć obrisan sadržaj)", str(frag_total)))
    findings.append(finding("Baze sa WAL rezidualom", str(wal_count)))
    for name, cnt in sorted(scanned_dbs, key=lambda x: -x[1])[:8]:
        findings.append(finding(f"  {name}", f"{cnt} fragmenata"))

    if frag_total >= MAX_TOTAL_FRAGMENTS:
        alerts.append(
            f"Skeniranje fragmenata dostiglo limit ({MAX_TOTAL_FRAGMENTS}); "
            f"rezultat je odsečen (moguće još obrisanog sadržaja)."
        )

    # ═══ TEHNIKA 3: Trashed / pending / .Trash media ═════════════════════════
    trashed = _scan_trashed_media(resolver)
    trashed_count = len(trashed)
    for a in trashed:
        if len(artifacts_list) >= MAX_ARTIFACTS:
            break
        artifacts_list.append(a)
    findings.append(finding("Trashed/pending media (oporaviva u mestu)", str(trashed_count)))

    # ═══ TEHNIKA 4: Siročad thumbnail-ovi ════════════════════════════════════
    thumb_arts, orphan_count, thumb_total = _scan_orphan_thumbnails(resolver)
    for a in thumb_arts:
        if len(artifacts_list) >= MAX_ARTIFACTS:
            break
        artifacts_list.append(a)
    findings.append(finding("Thumbnail-ovi pregledani", str(thumb_total)))
    findings.append(finding("Siročad thumbnail (dokaz obrisanih fotografija)", str(orphan_count)))

    # ── Sumarni alert ────────────────────────────────────────────────────────
    recovered_parts = []
    if frag_total:
        recovered_parts.append(f"{frag_total} SQLite fragmenata")
    if wal_count:
        recovered_parts.append(f"{wal_count} WAL rezidua")
    if trashed_count:
        recovered_parts.append(f"{trashed_count} trashed/pending media")
    if orphan_count:
        recovered_parts.append(f"{orphan_count} siročad thumbnail")

    if recovered_parts:
        alerts.append(
            "Oporavak obrisanih tragova (logički dump): " + ", ".join(recovered_parts) + "."
        )
    else:
        alerts.append(
            "Nisu pronađeni tragovi obrisanih podataka dostupnim tehnikama "
            "(logički dump; za neraspoređeni prostor potrebna fizička slika)."
        )

    if orphan_count:
        alerts.append(
            f"Detektovano {orphan_count} thumbnail-ova bez originala u galeriji – "
            f"indikacija da su fotografije obrisane iz glavne galerije."
        )
    if trashed_count:
        alerts.append(
            f"Detektovano {trashed_count} media fajlova u kanti/pending stanju – "
            f"korisnik ih je obrisao ali su fizički prisutni i oporavivi."
        )

    status = "completed"
    return module_result(
        status=status,
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
