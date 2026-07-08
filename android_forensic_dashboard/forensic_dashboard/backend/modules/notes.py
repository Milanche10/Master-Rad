"""
modules/notes.py
────────────────
Ekstrakcija BELEŠKI iz aplikacija za beleške (note-taking apps):
  - Samsung Notes / Samsung Memo (memomodel.db, notes.db)
  - Google Keep (keep.db → tree_entity)
  - ColorNote (colornote.db → notes)
  - OmniNotes (db / omni-notes → notes)
  - EasyNotes i drugi OmniNotes-derivati (my-notes → notes)
  - Ogden Memo i slični (data.db → memos)

Pristup je generički: za svaki prisutan paket otvaramo svaku SQLite bazu,
pronalazimo tabelu čije kolone liče na tekst beleške (content/note/text/body/
strippedContent) + naslov + vremenske oznake, i emitujemo po jedan artefakt
type_="note" po belešci.

NIKAD se ne izmišlja: šifrovane baze (SQLCipher / Evernote / zaključane beleške)
se DETEKTUJU i FLAGUJU sa metapodacima (veličina, putanja), ne pretvaramo se da
ih čitamo. Nedostajuće tabele/kolone/fajlovi ne smeju da sruše modul.
"""

import re
from pathlib import Path
from collections import defaultdict
from typing import Optional

from utils.dump_resolver import DumpResolver, SQLITE_MAGIC
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    ms_to_iso, sec_to_iso, is_hhy_encrypted, normalize_phone,
)


# ─── CILJANI PAKETI ───────────────────────────────────────────────────────
# Ljudski-čitljivo ime aplikacije po package name-u (za findings/artefakte).
NOTE_PACKAGES = {
    "com.samsung.android.app.notes":              "Samsung Notes",
    "com.samsung.android.memo":                   "Samsung Memo",
    "com.sec.android.widgetapp.diotek.smemo":     "Samsung S Memo",
    "com.google.android.keep":                    "Google Keep",
    "com.socialnmobile.dictapp":                  "ColorNote",
    "com.socialnmobile.colornote":                "ColorNote",
    "it.feio.android.omninotes":                  "OmniNotes",
    "com.ogden.memo":                             "Ogden Memo",
    "com.evernote":                               "Evernote",
    "easynotes.notes.notepad.notebook.privatenotes.note": "EasyNotes",
}

# Ostali paketi se otkrivaju heuristikom po imenu (bilo koji instaliran paket
# čiji naziv sadrži note/memo/keep/diary/journal se takođe skenira).
NAME_HINTS = ("note", "memo", "keep", "diary", "journal", "notepad", "notebook")

# Baze koje NISU beleške iako se nalaze u note-aplikacijama (analytics/telemetry
# /job scheduler bibliotečke baze) — preskačemo ih da ne bismo lažno prijavljivali.
IGNORE_DB_NAMES = {
    "google_analytics_v4.db", "google_app_measurement_local.db",
    "google_tagmanager.db", "evernote_jobs.db", "androidx.work.workdb",
    "ads.db", "easy_file_downloader.db",
    "com.google.android.datatransport.events",
}

# Kolone koje nose TEKST beleške (bilo koja od njih => tabela je kandidat).
# 'description' je namerno izostavljen: to je i kolona 'categories' tabele
# (Home/Work) pa bi lažno prepoznao tabelu kategorija kao tabelu beleški.
CONTENT_COLS = [
    "content", "note", "text", "body", "strippedcontent", "stripped_content",
    "note_text", "snippet", "memo",
]
# Kolone sa NASLOVOM beleške.
TITLE_COLS = ["title", "subject", "name", "note_title", "heading"]
# Nazivi tabela koji su jak signal da je reč o tabeli beleški.
NOTE_TABLE_HINTS = ("note", "memo", "tree_entity", "list_item", "diary", "journal")
# Kolone sa vremenom izmene (prioritet) / kreiranja. Vrednosti u ms ili sec.
MODIFIED_COLS = [
    "last_modification", "modified_date", "modified", "time_last_updated",
    "last_modified", "updated", "date_modified", "datetime", "date", "timestamp",
]
CREATED_COLS = [
    "creation", "created_date", "created", "time_created", "date_created",
    "createdate",
]
# Kolone koje označavaju "obrisano/otpad" — beležimo ih ali ne izostavljamo.
TRASHED_COLS = ["trashed", "deleted", "is_deleted", "is_trashed"]
# Kolone koje označavaju zaključanu (lozinkom zaštićenu) belešku.
LOCKED_COLS = ["locked", "is_locked", "encrypted", "is_encrypted"]

MAX_NOTES = 5000  # kapiranje velikih skenova

# Regexi za detekciju osetljivih indikatora u tekstu beleške.
BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+|00)\d{7,15}\b")


def _pick(cols_lower: dict, candidates) -> Optional[str]:
    """Vrati stvarno ime kolone (case-preserved) za prvi kandidat koji postoji."""
    for cand in candidates:
        if cand in cols_lower:
            return cols_lower[cand]
    return None


def _is_encrypted_sqlite(path: Path) -> bool:
    """
    True ako fajl liči na bazu ali NEMA plaintext SQLite header
    (SQLCipher / šifrovan store). Prazan/nepostojeći fajl → False.
    """
    try:
        if path.stat().st_size < 16:
            return False
        with open(path, "rb") as fh:
            head = fh.read(16)
        return head != SQLITE_MAGIC
    except Exception:
        return False


def _to_iso(value) -> Optional[str]:
    """
    Heuristička konverzija numeričke vremenske oznake u ISO.
    >1e12 → milisekunde; inače sekunde. Ne-numeričke vrednosti → None.
    """
    if value is None:
        return None
    try:
        v = int(value)
    except (ValueError, TypeError):
        return None
    if v <= 0:
        return None
    if v > 1_000_000_000_000:  # ~2001+ u ms
        return ms_to_iso(v)
    return sec_to_iso(v)


def _scan_sensitive(text: str):
    """Vrati (btc, eth, phones) liste indikatora pronađenih u tekstu."""
    if not text:
        return [], [], []
    btc = BTC_RE.findall(text)
    eth = ETH_RE.findall(text)
    phones = [normalize_phone(p) for p in PHONE_RE.findall(text)]
    return btc, eth, phones


def _find_note_table(db: SafeDBReader):
    """
    Pronađi tabelu koja liči na tabelu beleški: ima bar jednu content-kolonu
    (ili naslov u tabeli čije ime liči na beleške). Vrati (table_name, colmap)
    gde colmap sadrži stvarna imena kolona za content/title/modified/created/
    trashed/locked, ili None.

    Bira NAJBOLJI kandidat po skoru (a ne prosto po broju redova) da bi
    izbegao zamku 'categories' tabele (Home/Work) koja bi inače pobedila pravu
    'notes' tabelu sa manje redova. Jak signal je note-ime tabele i prava
    content-kolona; na kraju se remizira brojem redova.
    """
    best = None
    best_score = None  # (score, rows)
    for t in db.tables():
        if t in ("android_metadata", "sqlite_sequence") or t.startswith("sqlite_"):
            continue
        cols = db.columns(t)
        if not cols:
            continue
        cols_lower = {c.lower(): c for c in cols}

        content_col = _pick(cols_lower, CONTENT_COLS)
        title_col = _pick(cols_lower, TITLE_COLS)
        table_named_note = any(h in t.lower() for h in NOTE_TABLE_HINTS)

        # Kandidat mora imati content-kolonu, ILI naslov ako mu ime liči na beleške.
        if not content_col and not (title_col and table_named_note):
            continue

        try:
            n = db.count(t)
        except Exception:
            n = 0

        # ── Skorovanje ───────────────────────────────────────────────────
        score = 0
        if table_named_note:
            score += 100          # ime tabele je najjači signal
        if content_col:
            score += 40           # prava tekst-kolona
        if title_col:
            score += 5
        if _pick(cols_lower, MODIFIED_COLS) or _pick(cols_lower, CREATED_COLS):
            score += 10           # ima vremensku oznaku → liči na belešku

        cand = (score, n)
        if best_score is None or cand > best_score:
            colmap = {
                "content": content_col,
                "title": title_col,
                "modified": _pick(cols_lower, MODIFIED_COLS),
                "created": _pick(cols_lower, CREATED_COLS),
                "trashed": _pick(cols_lower, TRASHED_COLS),
                "locked": _pick(cols_lower, LOCKED_COLS),
            }
            best = (t, colmap)
            best_score = cand
    return best


def _gather_dbs(resolver: DumpResolver, pkg: str):
    """Vrati sve fajl-baze u databases/ folderu paketa (i .db i bez ekstenzije)."""
    root = resolver.pkg_root(pkg)
    if not root:
        return []
    db_dir = root / "databases"
    if not db_dir.exists():
        return []
    out = []
    for f in sorted(db_dir.iterdir()):
        if not f.is_file():
            continue
        name = f.name
        # preskoči journal/wal/shm i telemetry baze
        if name.endswith(("-journal", "-wal", "-shm")):
            continue
        if name in IGNORE_DB_NAMES:
            continue
        out.append(f)
    return out


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    # ── Otkrij prisutne note-pakete ──────────────────────────────────────
    installed = resolver.list_installed_packages()
    installed_set = set(installed)

    target_pkgs = []
    for pkg in NOTE_PACKAGES:
        if pkg in installed_set:
            target_pkgs.append(pkg)
    # heuristika po imenu za sve ostale
    for pkg in installed:
        if pkg in NOTE_PACKAGES:
            continue
        low = pkg.lower()
        if any(h in low for h in NAME_HINTS):
            target_pkgs.append(pkg)

    if not target_pkgs:
        return not_found_result(
            "Notes",
            "nijedna aplikacija za beleške (Samsung Notes / Keep / ColorNote / OmniNotes / ...) nije pronađena u dump-u",
        )

    findings = []
    artifacts_list = []
    alerts = []

    per_app_counts = defaultdict(int)
    per_app_encrypted = defaultdict(int)
    total_notes = 0
    total_trashed = 0
    total_locked = 0
    capped = False

    crypto_hits = []   # (app, addr)
    phone_hits = []    # (app, phone)
    hhy_hits = 0

    for pkg in target_pkgs:
        app_name = NOTE_PACKAGES.get(pkg, pkg)
        dbs = _gather_dbs(resolver, pkg)
        if not dbs:
            continue

        for db_path in dbs:
            # ── Šifrovana baza (SQLCipher / Evernote) — flaguj, ne čitaj ──
            if _is_encrypted_sqlite(db_path):
                try:
                    size = db_path.stat().st_size
                except Exception:
                    size = 0
                per_app_encrypted[app_name] += 1
                artifacts_list.append(artifact(
                    "note",
                    f"ŠIFROVANA baza beleški ({app_name}): {db_path.name} [{size} B, nečitljiva bez ključa]",
                    str(db_path),
                    ts=None,
                    extra={
                        "app": app_name,
                        "package": pkg,
                        "encrypted": True,
                        "db": db_path.name,
                        "size": size,
                    },
                ))
                alerts.append(
                    f"Šifrovana baza beleški ({app_name}): {db_path.name} — "
                    f"{size} B, verovatno SQLCipher/šifrovan store; nije dešifrovana."
                )
                continue

            # ── Čitljiva SQLite baza ─────────────────────────────────────
            try:
                with SafeDBReader(db_path) as db:
                    found = _find_note_table(db)
                    if not found:
                        continue
                    table, colmap = found
                    content_col = colmap["content"]
                    title_col = colmap["title"]
                    mod_col = colmap["modified"]
                    cre_col = colmap["created"]
                    trashed_col = colmap["trashed"]
                    locked_col = colmap["locked"]

                    # Sastavi SELECT samo od kolona koje postoje
                    sel = []
                    for c in (content_col, title_col, mod_col, cre_col, trashed_col, locked_col):
                        if c and c not in sel:
                            sel.append(c)
                    if not sel:
                        continue

                    order = f' ORDER BY "{mod_col}" DESC' if mod_col else ""
                    quoted = ", ".join(f'"{c}"' for c in sel)
                    rows = db.query(
                        f'SELECT {quoted} FROM "{table}"{order} LIMIT {MAX_NOTES + 1}'
                    )
                    if len(rows) > MAX_NOTES:
                        rows = rows[:MAX_NOTES]
                        capped = True

                    for row in rows:
                        title = (row.get(title_col) if title_col else "") or ""
                        content = (row.get(content_col) if content_col else "") or ""
                        title = str(title).strip()
                        content = str(content)

                        # Preskoči potpuno prazne redove
                        if not title and not content.strip():
                            continue

                        mod_raw = row.get(mod_col) if mod_col else None
                        cre_raw = row.get(cre_col) if cre_col else None
                        mod_iso = _to_iso(mod_raw)
                        cre_iso = _to_iso(cre_raw)
                        ts = mod_iso or cre_iso

                        is_trashed = bool(row.get(trashed_col)) if trashed_col else False
                        is_locked = bool(row.get(locked_col)) if locked_col else False

                        per_app_counts[app_name] += 1
                        total_notes += 1
                        if is_trashed:
                            total_trashed += 1
                        if is_locked:
                            total_locked += 1

                        preview = content[:200]
                        # Prikazna vrednost: naslov ili prvi red teksta
                        if title:
                            value = title
                        else:
                            first_line = content.strip().splitlines()[0] if content.strip() else ""
                            value = (first_line[:80] + "...") if len(first_line) > 80 else first_line
                        flags = []
                        if is_locked:
                            flags.append("🔒zaključana")
                        if is_trashed:
                            flags.append("🗑otpad")
                        flag_str = f" [{', '.join(flags)}]" if flags else ""

                        # ── Skeniranje osetljivog sadržaja ──────────────
                        scan_text = f"{title}\n{content}"
                        btc, eth, phones = _scan_sensitive(scan_text)
                        note_hhy = is_hhy_encrypted(content.strip())
                        if note_hhy:
                            hhy_hits += 1
                        for a in btc + eth:
                            crypto_hits.append((app_name, a))
                        for p in phones:
                            phone_hits.append((app_name, p))

                        extra = {
                            "app": app_name,
                            "package": pkg,
                            "table": table,
                            "db": db_path.name,
                            "title": title,
                            "preview": preview,
                            "created": cre_iso,
                            "modified": mod_iso,
                            "trashed": is_trashed,
                            "locked": is_locked,
                        }
                        if btc or eth:
                            extra["crypto_addresses"] = btc + eth
                        if phones:
                            extra["phones"] = phones
                        if note_hhy:
                            extra["encrypted_content"] = "HHY+AES"

                        artifacts_list.append(artifact(
                            "note",
                            f"📝 {app_name}: {value or '(bez naslova)'}{flag_str}",
                            str(db_path),
                            ts=ts,
                            extra=extra,
                        ))
            except Exception as e:  # nikad ne rušimo modul zbog jedne baze
                alerts.append(f"Greška pri čitanju baze {db_path.name} ({app_name}): {e}")
                continue

    # ── Findings ─────────────────────────────────────────────────────────
    findings.append(finding("Ukupno beleški", str(total_notes)))
    findings.append(finding(
        "Aplikacije za beleške (pronađene)",
        ", ".join(sorted(set(NOTE_PACKAGES.get(p, p) for p in target_pkgs))),
    ))
    for app_name in sorted(per_app_counts, key=lambda a: -per_app_counts[a]):
        findings.append(finding(f"Beleške: {app_name}", str(per_app_counts[app_name])))
    for app_name in sorted(per_app_encrypted):
        findings.append(finding(
            f"Šifrovane baze: {app_name}", str(per_app_encrypted[app_name])
        ))
    if total_locked:
        findings.append(finding("Zaključane beleške (lozinka)", str(total_locked)))
    if total_trashed:
        findings.append(finding("Beleške u otpadu", str(total_trashed)))
    if capped:
        findings.append(finding(
            "Napomena", f"Skeniranje ograničeno na {MAX_NOTES} beleški po tabeli"
        ))

    # ── Alerts ───────────────────────────────────────────────────────────
    if crypto_hits:
        uniq = sorted(set(a for _, a in crypto_hits))
        alerts.append(
            f"Kripto adrese u beleškama: {len(uniq)} jedinstvenih "
            f"({', '.join(uniq[:5])}{'...' if len(uniq) > 5 else ''})"
        )
    if phone_hits:
        uniq_ph = sorted(set(p for _, p in phone_hits))
        alerts.append(
            f"Telefonski brojevi u beleškama: {len(uniq_ph)} jedinstvenih "
            f"({', '.join(uniq_ph[:5])}{'...' if len(uniq_ph) > 5 else ''})"
        )
    if hhy_hits:
        alerts.append(
            f"HHY+AES šifrovan sadržaj u {hhy_hits} beleški (OmniNotes pattern) — "
            f"potencijalno prikriven sadržaj."
        )
    if total_locked:
        alerts.append(
            f"{total_locked} zaključanih (lozinkom zaštićenih) beleški — "
            f"sadržaj može biti šifrovan na nivou zapisa."
        )

    status = "completed" if (total_notes or per_app_encrypted) else "not_found"
    if status == "not_found":
        # Paketi postoje ali nijedna beleška/šifrovana baza nije nađena.
        findings.append(finding(
            "Status", "Note-aplikacije prisutne, ali bez čitljivih beleški"
        ))

    return module_result(
        status=status,
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
