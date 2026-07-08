"""
modules/calllog.py
──────────────────
Analiza evidencije poziva iz calllog.db:
  - Rekonstrukcija svih poziva (dolazni, odlazni, propušteni)
  - Detekcija nultosekundnih poziva kao covert signaling pattern-a
  - Identifikacija kontakata i zemalja
  - Vremenska analiza obrazaca poziva
"""

from collections import defaultdict
from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    ms_to_iso, normalize_phone, phone_country,
)


CALL_TYPE_MAP = {
    1: "INCOMING",
    2: "OUTGOING",
    3: "MISSED",
    4: "VOICEMAIL",
    5: "REJECTED",
    6: "BLOCKED",
}


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    db_path = resolver.resolve_db("calllog")

    if not db_path:
        return not_found_result("Calllog", "data/data/com.android.providers.contacts/databases/calllog.db")

    findings = []
    artifacts_list = []
    alerts = []

    with SafeDBReader(db_path) as db:
        tables = db.tables()

        if "calls" not in tables:
            return not_found_result("Calllog", "calllog.db → tabela 'calls' ne postoji")

        cols = db.columns("calls")

        # Sve kolone koje nas interesuju, uz proveru postojanja
        select_cols = ["number", "date", "duration", "type", "name"]
        available = [c for c in select_cols if c in cols]
        query = f"SELECT {', '.join(available)} FROM calls ORDER BY date ASC"

        rows = db.query(query)

        total = len(rows)
        zero_sec_calls = []
        call_type_counts = defaultdict(int)
        contact_calls = defaultdict(lambda: {"count": 0, "zero_sec": 0, "total_duration": 0})
        international_calls = []

        for row in rows:
            number   = normalize_phone(row.get("number") or "")
            date_ms  = row.get("date")
            duration = row.get("duration", 0) or 0
            call_type = row.get("type", 0)
            name     = row.get("name") or ""

            ts = ms_to_iso(date_ms)
            type_str = CALL_TYPE_MAP.get(call_type, f"TYPE_{call_type}")
            country = phone_country(number)
            country_str = f" ({country})" if country else ""

            call_type_counts[type_str] += 1
            contact_calls[number]["count"] += 1
            contact_calls[number]["total_duration"] += duration

            # ── Nultosekundni pozivi ──────────────────────────────────────
            is_zero = duration == 0 and call_type == 2  # outgoing, 0 sekundi

            if is_zero:
                zero_sec_calls.append({"number": number, "ts": ts})
                contact_calls[number]["zero_sec"] += 1
                artifacts_list.append(artifact(
                    "call",
                    f"⚡ NULTOSEKUNDNI POZIV → {number}{country_str} [{name}]",
                    "calllog.db",
                    ts=ts,
                    extra={
                        "phone": number,
                        "duration": 0,
                        "call_type": "zero_second_signal",
                        "country": country,
                    },
                ))
            else:
                duration_str = f"{duration}s" if duration < 60 else f"{duration//60}m{duration%60}s"
                artifacts_list.append(artifact(
                    "call",
                    f"{'📞' if call_type==1 else '📲'} {type_str} {number}{country_str} [{name}] – {duration_str}",
                    "calllog.db",
                    ts=ts,
                    extra={
                        "phone": number,
                        "duration": duration,
                        "call_type": type_str,
                        "country": country,
                    },
                ))

            # Međunarodni pozivi
            if country and country not in ("Srbija",):
                international_calls.append({"number": number, "country": country, "ts": ts})

        # ── Findings ─────────────────────────────────────────────────────
        findings.append(finding("Ukupno poziva", str(total)))
        for type_str, count in sorted(call_type_counts.items(), key=lambda x: -x[1]):
            findings.append(finding(f"  {type_str}", str(count)))
        findings.append(finding("Nultosekundni pozivi", str(len(zero_sec_calls))))

        # Top kontakti
        top = sorted(contact_calls.items(), key=lambda x: -x[1]["count"])[:8]
        for phone, data in top:
            country = phone_country(phone)
            country_str = f" ({country})" if country else ""
            zero_info = f", {data['zero_sec']} nultosek." if data["zero_sec"] > 0 else ""
            findings.append(finding(
                f"Kontakt {phone}{country_str}",
                f"{data['count']} poziva{zero_info}"
            ))

        # ── Alerts ───────────────────────────────────────────────────────
        if len(zero_sec_calls) >= 3:
            # Grupiši po broju
            zero_by_number = defaultdict(list)
            for z in zero_sec_calls:
                zero_by_number[z["number"]].append(z["ts"])

            for number, timestamps in zero_by_number.items():
                country = phone_country(number)
                alerts.append(
                    f"COVERT SIGNALING: {len(timestamps)} nultosekundnih poziva ka {number}"
                    + (f" ({country})" if country else "")
                    + f" – potencijalni out-of-band signal kanal"
                )

        if international_calls:
            countries_found = set(c["country"] for c in international_calls if c["country"])
            alerts.append(
                f"Međunarodna komunikacija: {len(international_calls)} poziva ka {len(countries_found)} država"
                f" ({', '.join(sorted(countries_found))})"
            )

        # Provjeri da li isti broj ima i nultosekundne i normalne pozive (signaling + komunikacija)
        for phone, data in contact_calls.items():
            if data["zero_sec"] > 0 and data["count"] > data["zero_sec"]:
                alerts.append(
                    f"Mešovit pattern poziva ka {phone}: "
                    f"{data['zero_sec']} signal poziva + {data['count'] - data['zero_sec']} normalnih poziva"
                )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
