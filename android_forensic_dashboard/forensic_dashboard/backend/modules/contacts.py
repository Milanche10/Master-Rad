"""
modules/contacts.py
───────────────────
Analiza kontakata iz contacts2.db:
  - Sve kontakt stavke (ime, telefon, email, organizacija)
  - Detekcija suspektnih kontakata (pseudonimi, kriptografske adrese u imenu)
  - Analiza labeled account-a (Signal, Telegram, WhatsApp kontakti)
  - Korelacioni podaci za cross-referencing sa calllog i SMS
"""

import re
from collections import defaultdict
from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    normalize_phone, phone_country,
)

CRYPTO_PATTERNS = [
    re.compile(r'0x[0-9a-fA-F]{40}'),          # ETH adresa
    re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'),  # BTC adresa
    re.compile(r'bitcoincash:[a-z0-9]{42,}'),    # BCH adresa
]

# Cele reči (ne podstringovi!) koje u nazivu kontakta ukazuju na potencijalno
# pseudonimizovan/poslovni kontakt vezan za kriptovalute. Kratki podstringovi
# kao "eth"/"bch"/"btc" su izbačeni jer se javljaju u uobičajenim imenima
# (Seth, Bethany, Kenneth...) i prave masu lažnih pozitiva.
SUSPICIOUS_NAME_WORDS = {
    "broker", "dealer", "swap", "exchange", "crypto", "bitcoin", "ethereum",
    "wallet", "anon", "anonymous", "ghost", "shadow",
}


def _is_suspicious_name(name: str) -> bool:
    words = re.findall(r"[a-zA-Z]+", name.lower())
    return any(w in SUSPICIOUS_NAME_WORDS for w in words)


def _has_crypto_in_name(name: str) -> bool:
    for pattern in CRYPTO_PATTERNS:
        if pattern.search(name):
            return True
    return False


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    db_path = resolver.resolve_db("contacts2")

    if not db_path:
        return not_found_result("Contacts", "data/data/com.android.providers.contacts/databases/contacts2.db")

    findings = []
    artifacts_list = []
    alerts = []

    with SafeDBReader(db_path) as db:
        tables = db.tables()

        # ── Raw contacts (osnovna lista) ──────────────────────────────────
        # Šema raw_contacts se razlikuje po Android verziji/OEM-u: na nekim
        # uređajima (npr. Samsung) NEMA account_type/account_name direktno u
        # raw_contacts (nalog je u zasebnoj 'accounts' tabeli preko account_id).
        # Zato biramo samo kolone koje stvarno postoje (kao u calllog modulu).
        raw_contacts = {}
        if "raw_contacts" in tables:
            rc_cols = set(db.columns("raw_contacts"))
            wanted = [c for c in ("_id", "display_name", "account_type",
                                  "account_name", "account_id", "starred") if c in rc_cols]
            if "_id" in wanted:
                order = " ORDER BY display_name" if "display_name" in rc_cols else ""
                rows = db.query(f"SELECT {', '.join(wanted)} FROM raw_contacts{order}")

                # Mapiranje account_id → (type, name) ako account_type nije u raw_contacts
                accounts_map = {}
                if "account_type" not in rc_cols and "accounts" in tables:
                    acc_cols = set(db.columns("accounts"))
                    if "_id" in acc_cols:
                        sel = [c for c in ("_id", "account_type", "account_name") if c in acc_cols]
                        for a in db.query(f"SELECT {', '.join(sel)} FROM accounts"):
                            accounts_map[a.get("_id")] = (a.get("account_type") or "", a.get("account_name") or "")

                for r in rows:
                    acc_type = r.get("account_type") or ""
                    acc_name = r.get("account_name") or ""
                    if not acc_type and r.get("account_id") in accounts_map:
                        acc_type, acc_name = accounts_map[r["account_id"]]
                    raw_contacts[r["_id"]] = {
                        "name": r.get("display_name") or "",
                        "account_type": acc_type,
                        "account_name": acc_name,
                        "starred": bool(r.get("starred", 0)),
                        "phones": [],
                        "emails": [],
                    }

        findings.append(finding("Ukupno kontakata", str(len(raw_contacts))))

        # ── Data tabela (telefoni, emailovi itd.) ─────────────────────────
        if "data" in tables:
            data_rows = db.query(
                "SELECT raw_contact_id, mimetype_id, data1, data2, data3, data4 "
                "FROM data ORDER BY raw_contact_id"
            )

            # Mimetype tabela
            mimetypes = {}
            if "mimetypes" in tables:
                mt_rows = db.query("SELECT _id, mimetype FROM mimetypes")
                mimetypes = {r["_id"]: r["mimetype"] for r in mt_rows}

            for row in data_rows:
                rc_id = row.get("raw_contact_id")
                if rc_id not in raw_contacts:
                    continue
                mt_id = row.get("mimetype_id")
                mt = mimetypes.get(mt_id, "")
                data1 = row.get("data1") or ""

                if "phone" in mt.lower():
                    raw_contacts[rc_id]["phones"].append(normalize_phone(data1))
                elif "email" in mt.lower():
                    raw_contacts[rc_id]["emails"].append(data1)

        # ── Analiza i generisanje artefakata ──────────────────────────────
        account_type_counts = defaultdict(int)
        international_count = 0

        suspicious_contacts = []

        for rc_id, contact in raw_contacts.items():
            name = contact["name"]
            phones = contact["phones"]
            emails = contact["emails"]
            account_type = contact["account_type"]

            account_type_counts[account_type] += 1

            # Identifikuj sumnjive kontakte
            is_suspicious = _is_suspicious_name(name) or _has_crypto_in_name(name)
            if is_suspicious:
                suspicious_contacts.append((name, phones[0] if phones else ""))

            for phone in phones:
                country = phone_country(phone)
                if country and country not in ("Srbija",):
                    international_count += 1

                country_str = f" ({country})" if country else ""
                suspicious_marker = " ⚠" if is_suspicious else ""

                artifacts_list.append(artifact(
                    "contact",
                    f"Kontakt: {name or '(bez imena)'}{suspicious_marker} → {phone}{country_str}",
                    "contacts2.db",
                    extra={
                        "name": name,
                        "phone": phone,
                        "country": country,
                        "account_type": account_type,
                        "suspicious": is_suspicious,
                    },
                ))

            if not phones and emails:
                for email in emails:
                    artifacts_list.append(artifact(
                        "contact",
                        f"Kontakt (email): {name or '(bez imena)'} → {email}",
                        "contacts2.db",
                        extra={"name": name, "email": email, "account_type": account_type},
                    ))

        # ── Findings ─────────────────────────────────────────────────────
        for acc_type, count in sorted(account_type_counts.items(), key=lambda x: -x[1]):
            type_display = acc_type if acc_type else "(lokalni)"
            findings.append(finding(f"Nalog tip: {type_display}", str(count)))

        findings.append(finding("Međunarodni kontakti", str(international_count)))
        findings.append(finding("Sumnjivi kontakti", str(len(suspicious_contacts))))

        if suspicious_contacts:
            preview = ", ".join(
                f"{n or '(bez imena)'} ({p})" if p else (n or "(bez imena)")
                for n, p in suspicious_contacts[:10]
            )
            if len(suspicious_contacts) > 10:
                preview += f", ... (+{len(suspicious_contacts) - 10})"
            alerts.append(f"{len(suspicious_contacts)} kontakt(a) sa sumnjivim nazivom: {preview}")

        if international_count > 3:
            alerts.append(
                f"{international_count} međunarodnih kontakata – "
                f"proširena internacionalna mreža"
            )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
