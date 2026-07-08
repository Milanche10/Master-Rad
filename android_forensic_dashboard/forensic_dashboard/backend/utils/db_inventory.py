"""
db_inventory.py
───────────────
Generički popis SVIH SQLite baza u dump-u — čita svaki fajl koji je prava
SQLite baza (po magičnom potpisu), izvlači imena tabela i broj redova, i
KLASIFIKUJE bazu na osnovu (a) tabela koje sadrži i (b) imena fajla/paketa.

Cilj: nijedna baza ne sme da "nestane". Čak i ako modul za tu vrstu podataka
ne postoji, baza se pojavljuje u popisu sa zaključkom šta je (npr. "WhatsApp
poruke", "Telegram", "Kalendar", "Nepoznata baza — tabele: …"). Radi za bilo
koji uređaj/aplikaciju, nezavisno od putanje.
"""

from pathlib import Path

# Potpisi za klasifikaciju: (kategorija, opis, obavezne_tabele, any_of)
# any_of=True → dovoljna je bilo koja tabela; inače moraju sve.
DB_CLASSIFIERS = [
    # Redosled je bitan — prvi pogodak pobeđuje; specifičniji potpisi idu prvi.
    ("Pozivi",           "Evidencija poziva (calllog)",              {"calls"}, False),
    ("SMS/MMS",          "SMS/MMS poruke (telephony)",               {"sms", "pdu"}, True),
    ("WhatsApp",         "WhatsApp poruke (msgstore)",               {"jid"}, False),
    ("WhatsApp kontakti","WhatsApp kontakti (wa.db)",                {"wa_contacts"}, False),
    ("Telegram",         "Telegram baza",                            {"messages_v2", "dialogs"}, True),
    ("Signal",           "Signal (SQLCipher — obično nedostupna)",   {"recipient", "mms"}, False),
    ("Web istorija",     "Chrome/Chromium istorija pregledača",      {"urls", "visits"}, False),
    ("Web akreditivi",   "Chrome/Chromium sačuvane lozinke",         {"logins"}, False),
    ("Web kolačići",     "Chrome/Chromium kolačići (sesije)",        {"cookies"}, False),
    ("Web autofill",     "Chrome/Chromium autofill/forme",           {"autofill"}, False),
    ("Kripto novčanik",  "Kriptovalutni novčanik (BRD/wallet)",      {"currencyTable_v2", "kvStoreTable", "wallet"}, True),
    ("Kalendar",         "Kalendar događaji",                        {"Events", "Calendars"}, True),
    ("Kontakti",         "Kontakti (contacts2)",                     {"raw_contacts", "view_contacts"}, True),
    ("Foto/Media",       "Media/galerija indeks",                    {"local_media", "thumbnails", "media_store"}, True),
    ("Nalozi",           "Sistemski nalozi (accounts)",              {"accounts", "authtokens"}, True),
    ("Bluetooth",        "Bluetooth uparivanja",                     {"bonded_devices"}, False),
    ("Notifikacije",     "Istorija notifikacija",                    {"notification_log"}, False),
]


def classify_database(path: Path, tables: set) -> dict:
    """
    Klasifikuj jednu SQLite bazu na osnovu tabela + imena fajla.
    Vraća {category, description, confidence}.
    """
    name = path.name.lower()

    # 1) po tabelama (najpouzdanije)
    for category, desc, req, any_of in DB_CLASSIFIERS:
        hit = (req & tables) if any_of else (req <= tables)
        if hit:
            return {"category": category, "description": desc, "confidence": "visoka"}

    # 2) po imenu fajla (kada šema nije prepoznata)
    name_hints = {
        "calllog": ("Pozivi", "Evidencija poziva (po imenu)"),
        "contacts": ("Kontakti", "Kontakti (po imenu)"),
        "mmssms": ("SMS/MMS", "SMS/MMS (po imenu)"),
        "msgstore": ("WhatsApp", "WhatsApp msgstore (po imenu)"),
        "signal": ("Signal", "Signal (po imenu)"),
        "history": ("Web istorija", "Browser istorija (po imenu)"),
        "cookies": ("Web kolačići", "Kolačići (po imenu)"),
        "wallet": ("Kripto novčanik", "Novčanik (po imenu)"),
        "calendar": ("Kalendar", "Kalendar (po imenu)"),
        "telegram": ("Telegram", "Telegram (po imenu)"),
    }
    for hint, (cat, desc) in name_hints.items():
        if hint in name:
            return {"category": cat, "description": desc, "confidence": "srednja"}

    # 3) nepoznato — ali i dalje se prijavljuje (sa tabelama kao tragom)
    sample = ", ".join(sorted(tables)[:6])
    return {
        "category": "Nepoznata baza",
        "description": f"Neklasifikovana SQLite baza — tabele: {sample}" if sample else "Prazna/neklasifikovana baza",
        "confidence": "niska",
    }


def scan_all_databases(resolver) -> list[dict]:
    """
    Popis SVIH pravih SQLite baza u dump-u (nešifrovanih), klasifikovanih.
    Enkriptovane (SQLCipher) baze se ovde ne vide (nemaju SQLite header) —
    njih hvata signal_brd modul posebno.

    Vraća listu: [{path, name, size_kb, tables, table_count, category,
                   description, confidence}], sortirano po kategoriji.
    """
    root = resolver.root.resolve()
    index = resolver._build_sqlite_index()  # {Path: frozenset(tabele)}
    out = []
    for path, tables in index.items():
        try:
            size_kb = path.stat().st_size // 1024
        except Exception:
            size_kb = 0
        try:
            rel = str(path.relative_to(root))
        except Exception:
            rel = str(path)
        cls = classify_database(path, set(tables))
        out.append({
            "path": rel,
            "name": path.name,
            "size_kb": size_kb,
            "table_count": len(tables),
            "tables": sorted(tables)[:20],
            "category": cls["category"],
            "description": cls["description"],
            "confidence": cls["confidence"],
        })

    # sortiraj: prvo prepoznate (visoka pouzdanost), pa po kategoriji
    conf_rank = {"visoka": 0, "srednja": 1, "niska": 2}
    out.sort(key=lambda d: (conf_rank.get(d["confidence"], 3), d["category"], -d["size_kb"]))
    return out


def inventory_summary(inventory: list[dict]) -> dict:
    """Kratak rezime popisa baza za dashboard/izveštaj."""
    by_category = {}
    for db in inventory:
        by_category.setdefault(db["category"], 0)
        by_category[db["category"]] += 1
    recognized = sum(1 for db in inventory if db["category"] != "Nepoznata baza")
    return {
        "total_databases": len(inventory),
        "recognized": recognized,
        "unknown": len(inventory) - recognized,
        "by_category": by_category,
    }
