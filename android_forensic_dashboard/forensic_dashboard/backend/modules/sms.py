"""
modules/sms.py
──────────────
Analiza SMS i MMS komunikacije iz mmssms.db:
  - Rekonstrukcija konverzacija po thread_id
  - Detekcija HHY+Base64/AES šifrovanih poruka (OmniNotes pattern)
  - Analiza creator kolone (koja aplikacija je slala poruke)
  - Identifikacija komunikacionih partnera
  - Statistika i vremenska distribucija
"""

import re
from pathlib import Path
from collections import defaultdict
from typing import Optional

from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    ms_to_iso, is_hhy_encrypted, try_decode_hhy,
    normalize_phone, phone_country, is_base64,
)


SMS_TYPE_MAP = {1: "INBOX (primljeno)", 2: "SENT (poslato)", 3: "DRAFT", 4: "OUTBOX", 5: "FAILED", 6: "QUEUED"}
MMS_TYPE_MAP = {1: "NOTIFICATION", 128: "SEND_REQ", 132: "RETRIEVE_CONF"}

SUSPICIOUS_APPS = [
    "omninotes", "signal", "wickr", "briar", "session",
    "threema", "wire", "telegram", "element",
]


def _detect_encryption_type(body: str) -> Optional[str]:
    """Identifikuje tip enkripcije/enkodiranja u SMS body-u."""
    if not body:
        return None
    if is_hhy_encrypted(body):
        return "HHY+AES (OmniNotes pattern)"
    if body.startswith("-----BEGIN"):
        return "PGP/GPG"
    if re.match(r'^[0-9a-fA-F]{32,}$', body.strip()):
        return "HEX enkodovano"
    if is_base64(body):
        return "Base64 enkodovano"
    return None


def _analyze_threads(db: SafeDBReader) -> dict:
    """Analizira sve thread-ove i vraća mapu thread_id → adrese."""
    threads = {}

    # canonical_addresses tabela
    if "canonical_addresses" in db.tables():
        rows = db.query("SELECT _id, address FROM canonical_addresses")
        addr_map = {r["_id"]: r["address"] for r in rows}
    else:
        addr_map = {}

    # threads tabela
    if "threads" in db.tables():
        cols = db.columns("threads")
        has_recipient = "recipient_ids" in cols
        query = "SELECT _id, recipient_ids, message_count, snippet FROM threads" if has_recipient else "SELECT _id, message_count FROM threads"
        thread_rows = db.query(query)
        for t in thread_rows:
            tid = t["_id"]
            recipient_ids = t.get("recipient_ids", "")
            addresses = []
            if recipient_ids:
                for rid in str(recipient_ids).split():
                    try:
                        rid_int = int(rid)
                        if rid_int in addr_map:
                            addresses.append(addr_map[rid_int])
                    except ValueError:
                        pass
            threads[tid] = {
                "addresses": addresses,
                "message_count": t.get("message_count", 0),
                "snippet": t.get("snippet", ""),
            }

    return threads


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    db_path = resolver.resolve_db("mmssms")

    if not db_path:
        return not_found_result("SMS", "data/data/com.android.providers.telephony/databases/mmssms.db")

    findings = []
    artifacts_list = []
    alerts = []

    with SafeDBReader(db_path) as db:
        tables = db.tables()

        # ── Threads ──────────────────────────────────────────────────────
        threads = _analyze_threads(db)
        findings.append(finding("Ukupno konverzacija (threads)", str(len(threads))))

        # ── SMS analiza ───────────────────────────────────────────────────
        if "sms" not in tables:
            findings.append(finding("SMS tabela", "Ne postoji u ovoj bazi"))
        else:
            cols = db.columns("sms")

            # Sve poruke
            sms_rows = db.query(
                "SELECT address, body, date, type, creator, thread_id, read "
                "FROM sms ORDER BY date ASC"
            )

            total = len(sms_rows)
            encrypted_count = 0
            sent_count = 0
            received_count = 0
            creators = defaultdict(int)
            contact_activity = defaultdict(int)
            enc_types = defaultdict(int)

            for row in sms_rows:
                address  = normalize_phone(row.get("address") or "")
                body     = row.get("body") or ""
                date_ms  = row.get("date")
                msg_type = row.get("type", 0)
                creator  = row.get("creator") or ""
                thread_id = row.get("thread_id")

                ts = ms_to_iso(date_ms)

                if msg_type == 2:
                    sent_count += 1
                elif msg_type == 1:
                    received_count += 1

                if creator:
                    creators[creator] += 1

                if address:
                    contact_activity[address] += 1

                # Detekcija enkripcije
                enc_type = _detect_encryption_type(body)
                if enc_type:
                    encrypted_count += 1
                    enc_types[enc_type] += 1
                    raw_bytes = try_decode_hhy(body)
                    size_info = f", {len(raw_bytes)}B ciphertext" if raw_bytes else ""

                    artifacts_list.append(artifact(
                        "comm",
                        f"Šifrovana SMS {'→' if msg_type==2 else '←'} {address}: [{enc_type}{size_info}]",
                        "mmssms.db",
                        ts=ts,
                        extra={
                            "phone": address,
                            "direction": "sent" if msg_type == 2 else "received",
                            "encryption": enc_type,
                            "creator": creator,
                            "thread_id": thread_id,
                        },
                    ))
                else:
                    # Normalna poruka – prikaži skraćeno
                    preview = (body[:80] + "...") if len(body) > 80 else body
                    artifacts_list.append(artifact(
                        "comm",
                        f"SMS {'→' if msg_type==2 else '←'} {address}: {preview}",
                        "mmssms.db",
                        ts=ts,
                        extra={
                            "phone": address,
                            "direction": "sent" if msg_type == 2 else "received",
                            "thread_id": thread_id,
                        },
                    ))

            findings += [
                finding("Ukupno SMS poruka", str(total)),
                finding("Poslate", str(sent_count)),
                finding("Primljene", str(received_count)),
                finding("Šifrovane poruke", str(encrypted_count)),
            ]

            # Creator analiza
            for creator, count in sorted(creators.items(), key=lambda x: -x[1]):
                findings.append(finding(f"SMS creator: {creator}", str(count) + " poruka"))
                creator_lower = creator.lower()
                for suspicious in SUSPICIOUS_APPS:
                    if suspicious in creator_lower and "omninotes" in creator_lower:
                        alerts.append(
                            f"KRITIČNO: OmniNotes kao SMS creator ({count} poruka) – "
                            f"trojanizovana aplikacija detektovana!"
                        )
                    elif suspicious in creator_lower:
                        alerts.append(f"Sumnjiva aplikacija kao SMS creator: {creator} ({count} poruka)")

            # Enkripcija tipovi
            for enc_type, count in enc_types.items():
                alerts.append(f"Detektovana enkripcija: {enc_type} – {count} poruka")

            # Top kontakti po aktivnosti
            top_contacts = sorted(contact_activity.items(), key=lambda x: -x[1])[:5]
            for phone, count in top_contacts:
                country = phone_country(phone)
                country_str = f" ({country})" if country else ""
                findings.append(finding(f"Kontakt {phone}{country_str}", f"{count} poruka"))
                if country and country not in ("Srbija",):
                    alerts.append(f"Međunarodna komunikacija sa {phone}{country_str}: {count} poruka")

        # ── MMS analiza ───────────────────────────────────────────────────
        if "pdu" in tables:
            mms_rows = db.query("SELECT date, msg_box FROM pdu ORDER BY date ASC")
            findings.append(finding("MMS poruke", str(len(mms_rows))))
            for row in mms_rows:
                artifacts_list.append(artifact(
                    "comm",
                    f"MMS poruka ({MMS_TYPE_MAP.get(row.get('msg_box', 0), 'UNKNOWN')})",
                    "mmssms.db",
                    ts=ms_to_iso(row.get("date")),
                ))

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
