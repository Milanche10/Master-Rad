"""
modules/app_messaging.py
────────────────────────
Ekstrakcija PORUKA i POZIVA iz third-party messaging aplikacija:
  - WhatsApp   (com.whatsapp)              → msgstore.db (plaintext) + wa.db kontakti;
                                             .crypt14/.crypt15 backup-i → FLAG (bez ključa nečitljivo)
  - Telegram   (org.telegram.messenger)    → cache4.db (poruke su TL binarni blob-ovi) → FLAG + metapodaci
  - Signal     (org.thoughtcrime.securesms)→ SQLCipher baza → FLAG (šifrovano)
  - Viber      (com.viber.voip)            → viber_messages 'messages' + viber_data 'phonebookcontact'
  - Instagram  (com.instagram.android)     → direct.db 'messages' (ako ima plaintext)
  - Messenger  (com.facebook.orca/katana)  → threads_db2 'messages'
  - Generički  → BILO KOJI messaging paket: DB sa tabelom koja ima text + timestamp + sender kolonu

Princip: NIKAD ne izmišljaj. Plaintext SQLite baze se čitaju; šifrovane (SQLCipher /
WhatsApp .cryptNN) se DETEKTUJU i FLAG-uju sa metapodacima (veličina, putanja),
ne pretvaramo se da ih čitamo.
"""

from pathlib import Path
from collections import defaultdict
from typing import Optional

from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    ms_to_iso, sec_to_iso,
)


# Maksimalan broj poruka po celom modulu (zaštita od ogromnih baza)
MAX_MESSAGES = 5000

SQLITE_MAGIC = b"SQLite format 3\x00"

# Poznati messaging paketi → ljudsko ime aplikacije
MESSAGING_PACKAGES = {
    "com.whatsapp":                  "WhatsApp",
    "com.whatsapp.w4b":              "WhatsApp Business",
    "org.telegram.messenger":        "Telegram",
    "org.telegram.plus":             "Telegram Plus",
    "org.thoughtcrime.securesms":    "Signal",
    "com.viber.voip":                "Viber",
    "com.instagram.android":         "Instagram",
    "com.facebook.orca":             "Facebook Messenger",
    "com.facebook.mlite":            "Messenger Lite",
    "com.facebook.katana":           "Facebook",
    "com.snapchat.android":          "Snapchat",
    "com.discord":                   "Discord",
    "jp.naver.line.android":         "LINE",
    "com.kakao.talk":                "KakaoTalk",
    "com.tencent.mm":                "WeChat",
    "com.zhiliaoapp.musically":      "TikTok",
    "org.thunderdog.challegram":     "Telegram X",
}

# Heuristika za prepoznavanje messaging paketa među instaliranim (za generički prolaz)
MESSAGING_HINTS = (
    "messenger", "messaging", "chat", "whatsapp", "telegram", "signal",
    "viber", "instagram", "snapchat", "discord", "wickr", "threema",
    "wire", "session", "kakao", "wechat", "line", "im.",
)

# Kandidati imena kolona (case-insensitive) za generičku detekciju šeme poruka
TEXT_COLS = ("text", "body", "content", "message", "text_data", "data",
             "message_text", "snippet", "caption")
TS_COLS = ("timestamp", "timestamp_ms", "date", "date_sent", "created_time",
           "time", "ts", "sent_timestamp", "server_timestamp", "msg_date")
SENDER_COLS = ("sender", "from_me", "key_from_me", "address", "sender_id",
               "from_jid", "user_id", "author", "peer", "recipient_ids",
               "remote_resource", "conversation_id", "key_remote_jid")

# Kolone za koje vrednost 1/0 znači smer (out/in); ostalo su identifikatori
DIRECTION_FLAG_COLS = ("from_me", "key_from_me")


def _is_sqlite(path: Path) -> bool:
    """Da li fajl počinje SQLite magičnim potpisom (plaintext baza)."""
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except Exception:
        return False


def _size_kb(path: Path) -> int:
    try:
        return round(path.stat().st_size / 1024)
    except Exception:
        return 0


def _rel(path: Path, root: Path) -> str:
    """Putanja relativna na root dump-a (za čitljiv 'source')."""
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def _clean(v) -> str:
    """Bezbedno u string, skraćeno bez novih redova (za value prikaz)."""
    if v is None:
        return ""
    s = str(v).replace("\r", " ").replace("\n", " ").strip()
    return s


def _qcols(cols) -> str:
    """Lista kolona → '"a", "b", "c"' (bezbedno citiranje imena)."""
    return ", ".join('"' + str(c) + '"' for c in cols)


def _guess_ts_iso(col: str, raw) -> Optional[str]:
    """Konvertuj timestamp u ISO — heuristika po imenu kolone i veličini broja."""
    if raw is None:
        return None
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    name = col.lower()
    # Eksplicitno ms
    if name.endswith("_ms") or "timestamp_ms" in name:
        return ms_to_iso(n)
    # Heuristika po broju cifara: >= 1e12 je milisekunde, inače sekunde
    if n >= 1_000_000_000_000:
        return ms_to_iso(n)
    if n >= 1_000_000_000:
        return sec_to_iso(n)
    # Mali broj — verovatno indeks, ne vreme
    return None


def _flag_encrypted(app: str, package: str, path: Path, root: Path,
                    reason: str, artifacts: list, alerts: list, findings: list):
    """Dodaj artifact + alert za šifrovanu/nečitljivu bazu (bez pretvaranja da je čitamo)."""
    size_kb = _size_kb(path)
    artifacts.append(artifact(
        "app",
        f"{app}: šifrovana/nečitljiva baza {path.name} ({size_kb} KB) — {reason}",
        _rel(path, root),
        ts=None,
        extra={
            "app": app,
            "package": package,
            "encrypted": True,
            "path": _rel(path, root),
            "size_kb": size_kb,
            "reason": reason,
        },
    ))
    alerts.append(f"{app}: {path.name} je šifrovana ({reason}) — potreban ključ za dešifrovanje ({size_kb} KB)")
    findings.append(finding(f"{app} ({path.name})", f"enkriptovano — {reason}"))


# ─────────────────────────────────────────────────────────────────────────────
# WhatsApp
# ─────────────────────────────────────────────────────────────────────────────

def _parse_whatsapp(resolver, root, artifacts, alerts, findings, budget) -> int:
    """WhatsApp: msgstore.db (plaintext) + crypt backup-i (FLAG). Vraća broj poruka."""
    pkg = "com.whatsapp"
    app = "WhatsApp"
    pkg_root = resolver.pkg_root(pkg)
    added = 0

    # crypt14 / crypt15 backup-i (bilo gde u dump-u — obično u media/Databases)
    try:
        crypt_files = resolver.find_files_by_regex([r"^msgstore.*\.crypt\d+$", r".*\.crypt1[45]$"])
    except Exception:
        crypt_files = []
    for cf in crypt_files:
        _flag_encrypted(app, pkg, cf, root, "WhatsApp crypt backup", artifacts, alerts, findings)

    if not pkg_root:
        if not crypt_files:
            findings.append(finding(app, "nije instaliran"))
        return 0

    dbs = resolver.find_databases_for_package(pkg)
    msgstore = next((d for d in dbs if d.name.lower() == "msgstore.db"), None)
    wadb = next((d for d in dbs if d.name.lower() == "wa.db"), None)

    if not msgstore:
        findings.append(finding(app, "instaliran — msgstore.db nije prisutan (verovatno samo crypt backup)"))
        return added

    if not _is_sqlite(msgstore):
        _flag_encrypted(app, pkg, msgstore, root, "msgstore.db nije plaintext SQLite", artifacts, alerts, findings)
        return added

    # wa.db kontakti (mapa jid → ime)
    contact_names = {}
    if wadb and _is_sqlite(wadb):
        try:
            with SafeDBReader(wadb) as wdb:
                if "wa_contacts" in wdb.tables():
                    cols = wdb.columns("wa_contacts")
                    jid_col = "jid" if "jid" in cols else None
                    name_col = next((c for c in ("display_name", "wa_name", "given_name") if c in cols), None)
                    if jid_col and name_col:
                        for r in wdb.query(f'SELECT "{jid_col}" j, "{name_col}" n FROM wa_contacts'):
                            if r.get("j"):
                                contact_names[r["j"]] = r.get("n") or ""
                        findings.append(finding(f"{app} kontakti (wa.db)", str(len(contact_names))))
        except Exception:
            pass

    try:
        with SafeDBReader(msgstore) as db:
            tables = db.tables()
            added += _wa_read_messages(db, tables, app, pkg, msgstore, root,
                                       contact_names, artifacts, findings, budget)
    except Exception as e:
        findings.append(finding(app, f"greška pri čitanju msgstore.db: {e}"))
    return added


def _wa_read_messages(db, tables, app, pkg, dbpath, root, contact_names,
                      artifacts, findings, budget) -> int:
    """Čitaj modernu 'message' ili legacy 'messages' tabelu WhatsApp-a."""
    added = 0
    src = _rel(dbpath, root)

    # Moderna šema: tabela 'message' (text_data, timestamp, from_me, chat_row_id)
    if "message" in tables:
        cols = db.columns("message")
        if "text_data" in cols or "timestamp" in cols:
            # Pokušaj join na chat/jid da dobijemo peer-a
            jid_map = _wa_chat_jid_map(db, tables)
            sel = [c for c in ("text_data", "timestamp", "from_me", "chat_row_id", "_id") if c in cols]
            rows = db.query(f'SELECT {", ".join(sel)} FROM message '
                            f'WHERE text_data IS NOT NULL ORDER BY timestamp ASC '
                            f'LIMIT {max(0, budget())}')
            for r in rows:
                if budget() <= 0:
                    break
                text = _clean(r.get("text_data"))
                if not text:
                    continue
                from_me = r.get("from_me")
                direction = "out" if from_me in (1, "1", True) else "in"
                peer = jid_map.get(r.get("chat_row_id"), "") if jid_map else ""
                ts = ms_to_iso(r.get("timestamp"))
                _emit_message(app, pkg, direction, peer, text, ts, src, dbpath.name,
                              artifacts)
                added += 1
            if added:
                findings.append(finding(f"{app} poruke", str(added)))
            else:
                findings.append(finding(f"{app} poruke", "0 (tabela 'message' prazna)"))
            return added

    # Legacy šema: tabela 'messages' (key_remote_jid, data, timestamp, key_from_me)
    if "messages" in tables:
        cols = db.columns("messages")
        sel = [c for c in ("key_remote_jid", "data", "timestamp", "key_from_me", "_id") if c in cols]
        if "data" in cols:
            rows = db.query(f'SELECT {", ".join(sel)} FROM messages '
                            f'WHERE data IS NOT NULL ORDER BY timestamp ASC '
                            f'LIMIT {max(0, budget())}')
            for r in rows:
                if budget() <= 0:
                    break
                text = _clean(r.get("data"))
                if not text:
                    continue
                from_me = r.get("key_from_me")
                direction = "out" if from_me in (1, "1", True) else "in"
                peer = _clean(r.get("key_remote_jid"))
                if peer in contact_names and contact_names[peer]:
                    peer = f"{contact_names[peer]} ({peer})"
                ts = ms_to_iso(r.get("timestamp"))
                _emit_message(app, pkg, direction, peer, text, ts, src, dbpath.name,
                              artifacts)
                added += 1
            findings.append(finding(f"{app} poruke (legacy)", str(added)))
            return added

    findings.append(finding(app, "msgstore.db bez poznate tabele poruka (message/messages)"))
    return added


def _wa_chat_jid_map(db, tables) -> dict:
    """Mapa chat_row_id → jid string (moderna WhatsApp šema)."""
    out = {}
    try:
        if "chat" in tables and "jid" in tables:
            cc = db.columns("chat")
            jc = db.columns("jid")
            if "_id" in cc and "jid_row_id" in cc and "_id" in jc and "user" in jc:
                rows = db.query(
                    "SELECT chat._id cid, jid.user u, jid.server s "
                    "FROM chat JOIN jid ON chat.jid_row_id = jid._id")
                for r in rows:
                    u = r.get("u") or ""
                    s = r.get("s") or ""
                    out[r.get("cid")] = f"{u}@{s}" if s else u
    except Exception:
        pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Telegram
# ─────────────────────────────────────────────────────────────────────────────

def _parse_telegram(resolver, root, artifacts, alerts, findings, budget) -> int:
    """Telegram cache4.db — poruke su TL binarni blob-ovi, ne plain text. FLAG + metapodaci."""
    pkg = "org.telegram.messenger"
    app = "Telegram"
    pkg_root = resolver.pkg_root(pkg)
    if not pkg_root:
        findings.append(finding(app, "nije instaliran"))
        return 0

    dbs = resolver.find_databases_for_package(pkg)
    cache4 = next((d for d in dbs if d.name.lower() == "cache4.db"), None)
    if not cache4:
        # nekad je pod files/ ili drugačije ime
        try:
            cand = resolver.find_files_by_regex([r"^cache4\.db$"])
        except Exception:
            cand = []
        cache4 = cand[0] if cand else None

    if not cache4:
        findings.append(finding(app, "instaliran — cache4.db nije pronađen"))
        return 0

    size_kb = _size_kb(cache4)
    src = _rel(cache4, root)

    if not _is_sqlite(cache4):
        _flag_encrypted(app, pkg, cache4, root, "cache4.db nije plaintext SQLite", artifacts, alerts, findings)
        return 0

    users_meta = 0
    dialogs_meta = 0
    try:
        with SafeDBReader(cache4) as db:
            tables = db.tables()
            # users metapodaci (name/username su ponekad u plain koloni, ponekad blob)
            if "users" in tables:
                users_meta = db.count("users")
                cols = db.columns("users")
                name_col = next((c for c in ("name", "username", "first_name") if c in cols), None)
                if name_col:
                    rows = db.query(f'SELECT "{name_col}" n FROM users WHERE "{name_col}" IS NOT NULL LIMIT 50')
                    for r in rows:
                        nm = _clean(r.get("n"))
                        if nm:
                            artifacts.append(artifact(
                                "app", f"{app} kontakt/korisnik: {nm[:60]}", src, ts=None,
                                extra={"app": app, "package": pkg, "kind": "user", "name": nm[:120]},
                            ))
            if "dialogs" in tables:
                dialogs_meta = db.count("dialogs")
    except Exception:
        pass

    findings.append(finding(f"{app} cache4.db", f"{size_kb} KB, users={users_meta}, dialogs={dialogs_meta}"))
    # Tela poruka su TL-serijalizovana → FLAG da treba specijalizovan parser
    artifacts.append(artifact(
        "app",
        f"{app}: cache4.db prisutan ({size_kb} KB) — tela poruka su TL binarni blob-ovi, potreban specijalizovan TL parser",
        src, ts=None,
        extra={
            "app": app, "package": pkg, "encrypted": False,
            "path": src, "size_kb": size_kb,
            "note": "TL-serialized message bodies; not plain text",
            "users": users_meta, "dialogs": dialogs_meta,
        },
    ))
    alerts.append(f"{app}: tela poruka u cache4.db su TL binarno serijalizovana — nije čitljivo bez specijalizovanog Telegram TL parsera ({size_kb} KB)")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Signal
# ─────────────────────────────────────────────────────────────────────────────

def _parse_signal(resolver, root, artifacts, alerts, findings, budget) -> int:
    """Signal: SQLCipher baza — FLAG kao šifrovano (nema plaintext SQLite header-a)."""
    pkg = "org.thoughtcrime.securesms"
    app = "Signal"
    pkg_root = resolver.pkg_root(pkg)
    if not pkg_root:
        findings.append(finding(app, "nije instaliran"))
        return 0

    dbs = resolver.find_databases_for_package(pkg)
    signal_db = next((d for d in dbs if d.name.lower() == "signal.db"), None)
    if not signal_db and dbs:
        signal_db = dbs[0]

    if not signal_db:
        findings.append(finding(app, "instaliran — signal.db nije pronađen"))
        return 0

    if _is_sqlite(signal_db):
        # Neočekivano plaintext — pokušaj generički (retko)
        findings.append(finding(app, "signal.db je plaintext SQLite (neuobičajeno) — pokušaj generičkog parsiranja"))
        return _parse_generic_db(app, pkg, signal_db, root, artifacts, findings, budget)

    _flag_encrypted(app, pkg, signal_db, root, "SQLCipher (Signal)", artifacts, alerts, findings)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Viber
# ─────────────────────────────────────────────────────────────────────────────

def _parse_viber(resolver, root, artifacts, alerts, findings, budget) -> int:
    """Viber: viber_messages 'messages'(body,date,...) + viber_data 'phonebookcontact'."""
    pkg = "com.viber.voip"
    app = "Viber"
    pkg_root = resolver.pkg_root(pkg)
    if not pkg_root:
        findings.append(finding(app, "nije instaliran"))
        return 0

    dbs = resolver.find_databases_for_package(pkg)
    msg_db = next((d for d in dbs if d.name.lower() == "viber_messages"), None)
    if not msg_db:
        msg_db = next((d for d in dbs if "message" in d.name.lower()), None)
    data_db = next((d for d in dbs if d.name.lower() == "viber_data"), None)

    added = 0

    # Kontakti iz viber_data
    contact_names = {}
    if data_db and _is_sqlite(data_db):
        try:
            with SafeDBReader(data_db) as db:
                if "phonebookcontact" in db.tables():
                    cols = db.columns("phonebookcontact")
                    ncol = next((c for c in ("display_name", "name") if c in cols), None)
                    ncnt = db.count("phonebookcontact")
                    findings.append(finding(f"{app} kontakti (viber_data)", str(ncnt)))
                    if "phonebookdata" in db.tables():
                        # mapiraj broj → ime ako je moguće (best-effort, ne obavezno)
                        pass
        except Exception:
            pass

    if not msg_db:
        findings.append(finding(app, "instaliran — viber_messages baza nije pronađena"))
        return added

    if not _is_sqlite(msg_db):
        _flag_encrypted(app, pkg, msg_db, root, "viber_messages nije plaintext SQLite", artifacts, alerts, findings)
        return added

    src = _rel(msg_db, root)
    try:
        with SafeDBReader(msg_db) as db:
            tables = db.tables()
            if "messages" not in tables:
                findings.append(finding(app, "viber_messages bez tabele 'messages'"))
                return added
            cols = db.columns("messages")
            body_col = next((c for c in ("body", "msg_info", "description") if c in cols), None)
            date_col = next((c for c in ("date", "msg_date", "timebomb") if c in cols), None)
            addr_col = next((c for c in ("address", "conversation_id", "participant_id", "recipient_number") if c in cols), None)
            dir_col = "send_type" if "send_type" in cols else ("type" if "type" in cols else None)
            if not body_col:
                findings.append(finding(app, "'messages' bez tekstualne kolone (body)"))
                return added
            sel = [c for c in (body_col, date_col, addr_col, dir_col) if c]
            order_by = ('"' + date_col + '"') if date_col else "1"
            rows = db.query('SELECT ' + _qcols(sel) + ' FROM messages '
                            'ORDER BY ' + order_by + ' ASC '
                            'LIMIT ' + str(max(0, budget())))
            for r in rows:
                if budget() <= 0:
                    break
                text = _clean(r.get(body_col))
                if not text:
                    continue
                dval = r.get(dir_col) if dir_col else None
                direction = "out" if dval in (1, "1") else "in"
                peer = _clean(r.get(addr_col)) if addr_col else ""
                ts = _guess_ts_iso(date_col, r.get(date_col)) if date_col else None
                _emit_message(app, pkg, direction, peer, text, ts, src, msg_db.name, artifacts)
                added += 1
            findings.append(finding(f"{app} poruke", str(added)))
    except Exception as e:
        findings.append(finding(app, f"greška pri čitanju viber_messages: {e}"))
    return added


# ─────────────────────────────────────────────────────────────────────────────
# Instagram
# ─────────────────────────────────────────────────────────────────────────────

def _parse_instagram(resolver, root, artifacts, alerts, findings, budget) -> int:
    """Instagram direct.db 'messages'(text,timestamp,thread_id) ako ima plaintext, inače FLAG."""
    pkg = "com.instagram.android"
    app = "Instagram"
    pkg_root = resolver.pkg_root(pkg)
    if not pkg_root:
        findings.append(finding(app, "nije instaliran"))
        return 0

    dbs = resolver.find_databases_for_package(pkg)
    direct = next((d for d in dbs if d.name.lower() == "direct.db"), None)
    if not direct:
        direct = next((d for d in dbs if "thread" in d.name.lower() or "direct" in d.name.lower()), None)
    if not direct:
        findings.append(finding(app, "instaliran — direct.db (DM baza) nije pronađen"))
        return 0

    if not _is_sqlite(direct):
        _flag_encrypted(app, pkg, direct, root, "direct.db nije plaintext SQLite", artifacts, alerts, findings)
        return 0

    added = 0
    src = _rel(direct, root)
    try:
        with SafeDBReader(direct) as db:
            tables = db.tables()
            if "messages" not in tables:
                findings.append(finding(app, "direct.db bez tabele 'messages' — DM tela verovatno nisu plaintext"))
                alerts.append(f"{app}: direct.db nema čitljivu 'messages' tabelu — tela poruka nisu u plaintext obliku")
                return 0
            cols = db.columns("messages")
            if "text" not in cols:
                findings.append(finding(app, "'messages' bez 'text' kolone — nije čitljivo"))
                alerts.append(f"{app}: 'messages' tabela nema plaintext 'text' kolonu")
                return 0
            date_col = "timestamp" if "timestamp" in cols else None
            addr_col = next((c for c in ("thread_id", "recipient_ids", "user_id") if c in cols), None)
            sel = [c for c in ("text", date_col, addr_col) if c]
            rows = db.query('SELECT ' + _qcols(sel) + ' FROM messages '
                            'WHERE text IS NOT NULL '
                            'LIMIT ' + str(max(0, budget())))
            for r in rows:
                if budget() <= 0:
                    break
                text = _clean(r.get("text"))
                if not text:
                    continue
                peer = _clean(r.get(addr_col)) if addr_col else ""
                ts = _guess_ts_iso(date_col, r.get(date_col)) if date_col else None
                _emit_message(app, pkg, "?", peer, text, ts, src, direct.name, artifacts)
                added += 1
            if added:
                findings.append(finding(f"{app} poruke", str(added)))
            else:
                findings.append(finding(f"{app} poruke", "0 (tabela 'messages' prazna)"))
    except Exception as e:
        findings.append(finding(app, f"greška pri čitanju direct.db: {e}"))
    return added


# ─────────────────────────────────────────────────────────────────────────────
# Facebook Messenger
# ─────────────────────────────────────────────────────────────────────────────

def _parse_messenger(resolver, root, artifacts, alerts, findings, budget) -> int:
    """Facebook Messenger threads_db2 'messages'(text,timestamp_ms,sender)."""
    added = 0
    for pkg, app in (("com.facebook.orca", "Facebook Messenger"),
                     ("com.facebook.mlite", "Messenger Lite"),
                     ("com.facebook.katana", "Facebook")):
        pkg_root = resolver.pkg_root(pkg)
        if not pkg_root:
            continue

        dbs = resolver.find_databases_for_package(pkg)
        tdb = next((d for d in dbs if "threads_db" in d.name.lower()), None)
        if not tdb:
            tdb = next((d for d in dbs if d.name.lower() in ("msys_database.db", "prefs_db")), None)
        if not tdb:
            findings.append(finding(app, "instaliran — threads_db2 nije pronađen"))
            continue

        if not _is_sqlite(tdb):
            _flag_encrypted(app, pkg, tdb, root, f"{tdb.name} nije plaintext SQLite", artifacts, alerts, findings)
            continue

        src = _rel(tdb, root)
        try:
            with SafeDBReader(tdb) as db:
                tables = db.tables()
                if "messages" not in tables:
                    findings.append(finding(app, f"{tdb.name} bez tabele 'messages'"))
                    continue
                cols = db.columns("messages")
                text_col = next((c for c in ("text", "body", "snippet") if c in cols), None)
                if not text_col:
                    findings.append(finding(app, "'messages' bez tekstualne kolone"))
                    continue
                date_col = next((c for c in ("timestamp_ms", "timestamp", "date") if c in cols), None)
                sender_col = next((c for c in ("sender", "sender_id", "user_key") if c in cols), None)
                sel = [c for c in (text_col, date_col, sender_col) if c]
                order_by = ('"' + date_col + '"') if date_col else "1"
                rows = db.query('SELECT ' + _qcols(sel) + ' FROM messages '
                                'WHERE "' + text_col + '" IS NOT NULL '
                                'ORDER BY ' + order_by + ' ASC '
                                'LIMIT ' + str(max(0, budget())))
                app_added = 0
                for r in rows:
                    if budget() <= 0:
                        break
                    text = _clean(r.get(text_col))
                    if not text:
                        continue
                    peer = _clean(r.get(sender_col)) if sender_col else ""
                    ts = _guess_ts_iso(date_col, r.get(date_col)) if date_col else None
                    _emit_message(app, pkg, "?", peer, text, ts, src, tdb.name, artifacts)
                    app_added += 1
                    added += 1
                findings.append(finding(f"{app} poruke", str(app_added) if app_added else "0 (prazno)"))
        except Exception as e:
            findings.append(finding(app, f"greška pri čitanju {tdb.name}: {e}"))
    return added


# ─────────────────────────────────────────────────────────────────────────────
# Generički prolaz za bilo koji messaging paket
# ─────────────────────────────────────────────────────────────────────────────

def _parse_generic_db(app, pkg, dbpath, root, artifacts, findings, budget) -> int:
    """Parsiraj DB: tabela sa text + timestamp + sender kolonom → izvuci nekoliko poruka."""
    if not _is_sqlite(dbpath):
        return 0
    added = 0
    src = _rel(dbpath, root)
    try:
        with SafeDBReader(dbpath) as db:
            for t in db.tables():
                if budget() <= 0:
                    break
                low = t.lower()
                if t.startswith("sqlite_") or "android_metadata" in low:
                    continue
                cols = db.columns(t)
                if not cols:
                    continue
                lc = {c.lower(): c for c in cols}
                text_col = next((lc[c] for c in TEXT_COLS if c in lc), None)
                ts_col = next((lc[c] for c in TS_COLS if c in lc), None)
                sender_col = next((lc[c] for c in SENDER_COLS if c in lc), None)
                if not (text_col and ts_col and sender_col):
                    continue
                # Izvuci ograničen broj redova
                cap = min(budget(), 200)
                if cap <= 0:
                    break
                sel = list({text_col, ts_col, sender_col})
                rows = db.query('SELECT ' + _qcols(sel) +
                                ' FROM "' + t + '" WHERE "' + text_col +
                                '" IS NOT NULL LIMIT ' + str(cap))
                t_added = 0
                for r in rows:
                    if budget() <= 0:
                        break
                    text = _clean(r.get(text_col))
                    if not text:
                        continue
                    sval = r.get(sender_col)
                    if sender_col.lower() in DIRECTION_FLAG_COLS:
                        direction = "out" if sval in (1, "1", True) else "in"
                        peer = ""
                    else:
                        direction = "?"
                        peer = _clean(sval)
                    ts = _guess_ts_iso(ts_col, r.get(ts_col))
                    _emit_message(app, pkg, direction, peer, text, ts, src, dbpath.name, artifacts)
                    t_added += 1
                    added += 1
                if t_added:
                    findings.append(finding(f"{app} [{dbpath.name}:{t}]", f"{t_added} poruka (generički)"))
    except Exception:
        pass
    return added


def _parse_generic_package(resolver, root, pkg, app, artifacts, alerts, findings, budget) -> int:
    """Generički: prođi kroz sve *.db paketa i pokušaj naći tabelu poruka."""
    added = 0
    dbs = resolver.find_databases_for_package(pkg)
    for dbp in dbs:
        if budget() <= 0:
            break
        try:
            if not _is_sqlite(dbp):
                # Šifrovana baza u messaging paketu → FLAG jednom
                if dbp.stat().st_size > 4096:
                    _flag_encrypted(app, pkg, dbp, root, "nije plaintext SQLite (moguće SQLCipher)",
                                    artifacts, alerts, findings)
                continue
        except Exception:
            continue
        added += _parse_generic_db(app, pkg, dbp, root, artifacts, findings, budget)
    return added


# ─────────────────────────────────────────────────────────────────────────────
# Emisija poruke
# ─────────────────────────────────────────────────────────────────────────────

# Deljeni brojač poruka po pozivu analyze() (resetuje se na početku).
_STATE = {"count": 0, "capped": False}


def _emit_message(app, pkg, direction, peer, text, ts, source, dbname, artifacts):
    """Standardni message artifact — poštuje MAX_MESSAGES limit i broji poruke."""
    if _STATE["count"] >= MAX_MESSAGES:
        _STATE["capped"] = True
        return
    arrow = "→" if direction == "out" else ("←" if direction == "in" else "·")
    peer_disp = peer if peer else "?"
    value = f"{app} {arrow} {peer_disp}: {text[:100]}"
    artifacts.append(artifact(
        "message",
        value,
        source,
        ts=ts,
        extra={
            "app": app,
            "package": pkg,
            "direction": {"out": "out", "in": "in"}.get(direction, "?"),
            "peer": peer,
            "text": text[:300],
            "db": dbname,
        },
    ))
    _STATE["count"] += 1


# ─────────────────────────────────────────────────────────────────────────────
# Glavni ulaz
# ─────────────────────────────────────────────────────────────────────────────

def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    root = resolver.root

    findings = []
    artifacts_list = []
    alerts = []

    # Reset deljenog brojača za ovaj poziv
    _STATE["count"] = 0
    _STATE["capped"] = False

    def budget() -> int:
        remaining = MAX_MESSAGES - _STATE["count"]
        return remaining if remaining > 0 else 0

    try:
        installed = set(resolver.list_installed_packages())
    except Exception:
        installed = set()

    # 1) Ciljano parsiranje poznatih aplikacija
    handled = set()
    parsers = [
        ("com.whatsapp", _parse_whatsapp),
        ("org.telegram.messenger", _parse_telegram),
        ("org.thoughtcrime.securesms", _parse_signal),
        ("com.viber.voip", _parse_viber),
        ("com.instagram.android", _parse_instagram),
        ("__messenger__", _parse_messenger),  # obrađuje orca/mlite/katana
    ]
    parser_keys = {k for k, _ in parsers}
    for pkg_key, fn in parsers:
        try:
            fn(resolver, root, artifacts_list, alerts, findings, budget)
        except Exception as e:
            findings.append(finding("Greška parsera", f"{pkg_key}: {e}"))
        handled.add(pkg_key)
    handled.update(["com.facebook.orca", "com.facebook.mlite", "com.facebook.katana"])

    # 2) Generički prolaz za ostale poznate/heuristički messaging pakete
    for pkg in sorted(installed):
        if pkg in handled or pkg in parser_keys:
            continue
        app = MESSAGING_PACKAGES.get(pkg)
        is_hint = any(h in pkg.lower() for h in MESSAGING_HINTS)
        if not app and not is_hint:
            continue
        app = app or pkg
        if budget() <= 0:
            break
        try:
            _parse_generic_package(resolver, root, pkg, app, artifacts_list, alerts, findings, budget)
        except Exception as e:
            findings.append(finding("Greška (generički)", f"{pkg}: {e}"))
        handled.add(pkg)

    # ── Rezime ────────────────────────────────────────────────────────────
    total_msgs = _STATE["count"]
    findings.insert(0, finding("Ukupno poruka (sve aplikacije)", str(total_msgs)))
    enc_count = sum(1 for a in artifacts_list
                    if a.get("type") == "app" and a.get("extra", {}).get("encrypted"))
    if enc_count:
        findings.append(finding("Šifrovane/nečitljive baze", str(enc_count)))
    if _STATE["capped"]:
        note = f"Dostignut limit od {MAX_MESSAGES} poruka — rezultat je skraćen."
        findings.append(finding("Napomena", note))
        alerts.append(note)

    # Status
    if not findings and not artifacts_list:
        return not_found_result("AppMessaging", "third-party messaging aplikacije")

    any_data = total_msgs > 0 or any(
        a.get("type") in ("message", "app") for a in artifacts_list
    )
    status = "completed" if any_data or findings else "not_found"

    return module_result(
        status=status,
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
