"""
correlation/rules_registry.py — Declarative Correlation Rule Registry (#4)
─────────────────────────────────────────────────────────────────────────
Eksplicitna, mašinski-čitljiva definicija SVAKOG korelacionog pravila (C1..C10).
Cilj: auditabilnost i sudska transparentnost — za svako pravilo je jasno KOJI
ulazi su potrebni, DA LI se zahteva citirani artefakt (zabrana implicitnih
korelacija bez dokaza), i kako se formira skor.

Ovo je DEKLARATIVNI OPIS koji prati izvršni engine u main.build_correlations().
Logika ostaje u engine-u (testirana), a ovde je "ugovor" svakog pravila —
izložen preko /api/correlations/rules radi revizije.
"""

RULES = [
    {
        "id": "C1", "code": "C-TEL",
        "name": "Komunikaciona korelacija (isti broj kroz izvore)",
        "inputs": ["sms.extra.phone", "calllog.extra.phone", "contacts.extra.phone"],
        "evidence_required": True,
        "base_score": 45,
        "score_factors": {"in_contacts": 10, "encrypted_sms": 20, "zero_sec_calls": 15},
        "description": "Isti telefonski broj u 2+ nezavisna izvora; skor raste sa "
                       "prisustvom u kontaktima i jakim indikatorima.",
    },
    {
        "id": "C2", "code": "C-APK-SMS",
        "name": "Trojanizovana aplikacija → šifrovane SMS poruke",
        "inputs": ["sms.alerts(omninotes)", "sms.extra.encryption", "apk.extra.trojanized"],
        "evidence_required": True,
        "base_score": 60,
        "score_factors": {"apk_confirmed_trojan": 25},
        "description": "OmniNotes kao SMS creator + šifrovane poruke. Detalji DEX "
                       "analize NAVODE SE SAMO ako ih APK modul zaista prijavi "
                       "(bez fabrikacije).",
    },
    {
        "id": "C3", "code": "C-CRYPTO-WEB",
        "name": "Kriptovalutne aktivnosti u browser istoriji",
        "inputs": ["browser.extra.categories(crypto/P2P)", "browser.extra.credential"],
        "evidence_required": True,
        "base_score": 45,
        "score_factors": {"credentials_present": 10},
        "description": "Posete kripto/P2P servisima; akreditivi se pominju SAMO ako "
                       "postoji citiran Login Data artefakt.",
    },
    {
        "id": "C4", "code": "C-INTL",
        "name": "Međunarodna komunikaciona mreža",
        "inputs": ["sms.extra.country", "calllog.extra.country"],
        "evidence_required": True,
        "base_score": 40,
        "score_factors": {"per_country": 10},
        "description": "Gradi se IZ citiranih SMS/poziv artefakata sa stranom zemljom "
                       "(NE iz alert stringa). Ne emituje se bez dokaza.",
    },
    {
        "id": "C5", "code": "C-GEO",
        "name": "Fizička lokacija: EXIF foto + WiFi mreža",
        "inputs": ["exif.type=location+ts", "wifi.ts+extra.ssid"],
        "evidence_required": True,
        "base_score": 60,
        "score_factors": {"within_1h": 25},
        "description": "GPS fotografija vremenski blizu WiFi konekcije (<6h).",
    },
    {
        "id": "C6", "code": "C-APK-DEX-SMS",
        "name": "DEX analiza potvrđuje trojanizaciju kao izvor šifrovanih SMS",
        "inputs": ["apk.extra.trojanized", "sms.extra.encryption"],
        "evidence_required": True,
        "base_score": 85,
        "score_factors": {},
        "description": "Statička DEX potvrda + šifrovane poruke.",
    },
    {
        "id": "C7", "code": "C-CRYPTO-FLOW",
        "name": "Kriptovalutni finansijski trag (ista adresa kroz module)",
        "inputs": ["crypto/blockchain/signal_brd/browser.extra.address"],
        "evidence_required": True,
        "base_score": 60,
        "score_factors": {"3plus_modules": 25},
        "description": "Ista validirana kripto adresa u 2+ modula.",
    },
    {
        "id": "C8", "code": "C-STEGO-SIGNAL",
        "name": "Audio steganografija + nultosekundni pozivi",
        "inputs": ["mp3_signal.extra.suspicious", "calllog.extra.call_type=zero_second_signal"],
        "evidence_required": True,
        "base_score": 55,
        "score_factors": {},
        "description": "Prikriveni signalni kanal (stego audio + zero-sec pozivi).",
    },
    {
        "id": "C9", "code": "C-ID",
        "name": "Zajednički identifikator kroz module (generički)",
        "inputs": ["*.extra.{email,username,account,imei,device_id,serial,uid}"],
        "evidence_required": True,
        "base_score": 55,
        "score_factors": {"3plus_modules": 25},
        "description": "Isti identifikator (email/IMEI/nalog…) u 2+ modula.",
    },
    {
        "id": "C10", "code": "C-GEOGEN",
        "name": "Generička lokaciona korelacija (dva izvora u vremenskoj blizini)",
        "inputs": ["*.type=location+ts"],
        "evidence_required": True,
        "base_score": 60,
        "score_factors": {"within_1h": 25},
        "description": "Dva lokacijska događaja iz različitih modula <6h.",
    },
]

# Invarijanta koju engine POŠTUJE (i koju ovaj registry dokumentuje):
INVARIANTS = [
    "Nijedna korelacija se ne emituje bez bar jednog citiranog artefakta (evidence[]).",
    "Skor je numerički 0-100 i deterministički (isti ulaz → isti skor).",
    "Nijedna tvrdnja u 'detail' polju ne sme tvrditi činjenicu koju citirani artefakti ne podržavaju.",
    "Izbor artefakata je deterministički (sortiran pre slice-ovanja).",
]


def registry() -> dict:
    """Vrati kompletan registry za reviziju (/api/correlations/rules)."""
    return {"rules": RULES, "invariants": INVARIANTS, "count": len(RULES)}
