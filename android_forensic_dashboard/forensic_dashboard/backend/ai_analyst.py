"""
ai_analyst.py
─────────────
AI forenzički analitičar ugrađen u backend. Uzima SVE strukturirane nalaze
(uređaj, artefakti, upozorenja, korelacije, timeline, popis baza) i preko
LOKALNOG open-source modela (Ollama) generiše koherentan forenzički zaključak
na srpskom — rekonstrukciju događaja, procenu značaja i preporuke.

Zašto lokalni model (Ollama), a ne komercijalni API:
  - BESPLATNO i open-source (Llama 3, Qwen, Mistral, Gemma...).
  - PRIVATNOST: forenzički dokazi NIKAD ne napuštaju mašinu — nema slanja
    osetljivih podataka trećoj strani, što je ključno za poverljivost i
    lanac nadležnosti (chain of custody).
  - Radi offline.

Dizajn:
  - Poziva Ollama HTTP API (http://localhost:11434/api/chat) preko requests.
  - Ulaz je SAŽET (biramo reprezentativne nalaze da ostanemo u kontekstu).
  - Graciozna degradacija: ako Ollama nije pokrenut ili model nije preuzet,
    vraća jasnu poruku umesto da obori aplikaciju.
  - Forenzička disciplina: model se instruira da NE izmišlja činjenice.

Konfiguracija (env):
  OLLAMA_HOST  — adresa Ollama servera (default http://localhost:11434)
  AI_MODEL     — naziv modela (default llama3.1). Za bolji srpski/multijezik:
                 postavi AI_MODEL=qwen2.5  ili  AI_MODEL=gemma2
"""

import os
import re

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
#AI_MODEL = os.environ.get("AI_MODEL", "llama3.1")
AI_MODEL = os.environ.get("AI_MODEL", "qwen3:32b")
MAX_ITEMS = 40      # koliko stavki po sekciji šaljemo modelu (kontrola konteksta)
NUM_CTX = 32768     # veličina konteksta za lokalni model
GEN_TIMEOUT = 1200   # lokalna generacija može trajati (CPU) — velik timeout


def _model_matches(available: list, wanted: str) -> bool:
    """Da li je traženi model među preuzetima (uz/bez :tag sufiksa)."""
    base = wanted.split(":")[0]
    return any(m == wanted or m.split(":")[0] == base for m in available)


def ai_available() -> tuple[bool, str]:
    """
    Vrati (dostupno, razlog_ako_ne). Proverava da li je Ollama server pokrenut
    i da li je konfigurisani model preuzet. Brza provera (kratak timeout).
    """
    try:
        import requests
    except Exception:
        return False, "Biblioteka 'requests' nije instalirana."

    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=2)
    except Exception:
        return False, (
            f"Ollama server nije dostupan na {OLLAMA_HOST}. "
            f"Instaliraj sa https://ollama.com, pa pokreni: 'ollama serve' i 'ollama pull {AI_MODEL}'."
        )

    if r.status_code != 200:
        return False, f"Ollama vratio status {r.status_code} sa {OLLAMA_HOST}."

    models = [m.get("name", "") for m in r.json().get("models", [])]
    if not _model_matches(models, AI_MODEL):
        avail = ", ".join(models) if models else "nijedan model nije preuzet"
        return False, (
            f"Model '{AI_MODEL}' nije preuzet. Pokreni: 'ollama pull {AI_MODEL}'. "
            f"Trenutno dostupni: {avail}."
        )
    return True, ""


SYSTEM_PROMPT = """\
Ti si iskusan sudski veštak za digitalnu (mobilnu) forenziku. Dobijaš
strukturirane, objektivne nalaze automatske analize Android dump-a i pišeš
forenzički zaključak na srpskom jeziku (latinica).

Pravila (obavezna):
- Oslanjaj se ISKLJUČIVO na dostavljene nalaze. Ne izmišljaj brojeve, imena,
  adrese, datume niti događaje kojih nema u ulazu.
- Jasno odvoji ČINJENICE (šta podaci pokazuju) od INTERPRETACIJE (šta to može
  da znači). Interpretaciju označi kao procenu, ne kao dokazanu činjenicu.
- Budi konkretan i sažet. Piši za tužioca/sud — razumljivo i nestručnoj publici,
  ali precizno.
- Ako nalazi nisu dovoljni za neki zaključak, reci to otvoreno.
- Krivičnu kvalifikaciju NE donosiš — to je u nadležnosti organa postupka.

Označavanje tvrdnji (OBAVEZNO u tekstu):
- [ČINJENICA] za ono što direktno proizlazi iz nalaza.
- [INTERPRETACIJA] za procenu/zaključak koji ide dalje od sirovog podatka.
- [NESIGURNOST] za ono što nalazi ne mogu da potvrde.

Struktura odgovora (koristi ove naslove; svaka sekcija završava redom
"Pouzdanost sekcije: X/100" gde je X tvoja procena na osnovu KOLIČINE i
KONZISTENTNOSTI dokaza):
1. Rezime slučaja (2-4 rečenice)
2. Identifikacija uređaja i korisnika
3. Rekonstrukcija ključnih događaja (hronološki)
4. Anomalije i indikatori (anti-forenzika, prikrivena komunikacija, kripto)
5. Korelacije između izvora (šta se međusobno potvrđuje)
6. Procena značaja i pouzdanosti nalaza
7. Preporuke za dalju istragu

OBAVEZNO:
- Svaka od 7 sekcija mora postojati; ne preskači nijednu.
- Ako nema podataka za sekciju, napiši "Nema dovoljno podataka" i "Pouzdanost sekcije: 0/100".
- NE navodi telefonske brojeve, email adrese, imena ni kripto adrese kojih NEMA
  u ulaznim nalazima. Svaki takav podatak mora poticati iz ulaza.
"""


def _fmt_findings(results: dict) -> str:
    lines = []
    for module, data in results.items():
        fs = data.get("findings") or []
        if not fs:
            continue
        lines.append(f"[{module}]")
        for f in fs[:12]:
            lines.append(f"  - {f.get('key')}: {f.get('value')}")
    return "\n".join(lines)


def _fmt_list(items, key_fields, limit=MAX_ITEMS):
    lines = []
    for it in items[:limit]:
        if isinstance(it, dict):
            parts = [f"{k}={it.get(k)}" for k in key_fields if it.get(k) not in (None, "")]
            lines.append("  - " + ", ".join(parts))
        else:
            lines.append(f"  - {it}")
    if len(items) > limit:
        lines.append(f"  … (+{len(items) - limit} više)")
    return "\n".join(lines)


def build_prompt(data: dict) -> str:
    """
    data = izlaz _collect_report_data() + opcioni 'db_inventory'.
    Sastavlja sažet, strukturiran ulaz za model.
    """
    results = data.get("results", {})
    all_alerts = data.get("all_alerts", [])
    correlations = data.get("correlations", [])
    headline = data.get("headline", [])
    db_inventory = data.get("db_inventory", [])

    alerts_txt = "\n".join(f"  - [{m}] {a}" for m, a in all_alerts[:MAX_ITEMS])
    if len(all_alerts) > MAX_ITEMS:
        alerts_txt += f"\n  … (+{len(all_alerts) - MAX_ITEMS} više)"

    cor_txt = "\n".join(
        f"  - [{c.get('confidence')}] {c.get('title')} — {c.get('detail','')[:200]}"
        for c in correlations[:MAX_ITEMS]
    )

    hl_txt = _fmt_list(
        [{"ts": e.get("ts"), "tip": e.get("type"), "opis": (e.get("value") or "")[:120]} for e in headline],
        ["ts", "tip", "opis"], limit=MAX_ITEMS,
    )

    db_txt = _fmt_list(
        [{"kat": d.get("category"), "fajl": d.get("name"), "opis": d.get("description")} for d in db_inventory],
        ["kat", "fajl", "opis"], limit=MAX_ITEMS,
    )

    return f"""\
Analiziraj sledeće forenzičke nalaze sa jednog Android uređaja i napiši
forenzički zaključak prema zadatoj strukturi.

=== OSNOVNI PODACI ===
Uređaj: {data.get('device_str', 'Nepoznat')}
Android: {data.get('android_str', 'N/A')}
Dump putanja: {data.get('dump_path', 'N/A')}
Ukupno artefakata: {data.get('total_artifacts', 0)}
Broj upozorenja: {len(all_alerts)}
Broj korelacija: {len(correlations)}

=== NALAZI PO MODULIMA ===
{_fmt_findings(results) or '  (nema)'}

=== UPOZORENJA ===
{alerts_txt or '  (nema)'}

=== KORELACIJE IZMEĐU IZVORA ===
{cor_txt or '  (nema)'}

=== KLJUČNI DOGAĐAJI (rekonstrukcija) ===
{hl_txt or '  (nema)'}

=== POPIS PRONAĐENIH BAZA PODATAKA ===
{db_txt or '  (nema)'}

Napiši zaključak na srpskom, prateći traženu strukturu (7 sekcija).
"""


def generate_ai_conclusion(data: dict) -> dict:
    """
    Vrati {available, conclusion|reason, model, usage}.
    Ako lokalni model nije dostupan → available=False + razlog (bez rušenja).
    """
    ok, reason = ai_available()
    if not ok:
        return {"available": False, "reason": reason}

    import requests

    prompt = build_prompt(data)

    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": AI_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "seed": 1,
                "options": {
                    "temperature": 0.1,
                    "num_ctx": NUM_CTX,
                    "num_predict": 3000,
                }
            },
            timeout=GEN_TIMEOUT,
        )
    except requests.Timeout:
        return {"available": False, "reason": f"Model nije odgovorio u {GEN_TIMEOUT}s (spora mašina ili prevelik model)."}
    except Exception as e:
        return {"available": False, "reason": f"Greška pri pozivu Ollama servera: {e}"}

    if resp.status_code != 200:
        return {"available": False, "reason": f"Ollama vratio status {resp.status_code}: {resp.text[:200]}"}

    try:
        body = resp.json()
        text = (body.get("message") or {}).get("content", "").strip()
    except Exception as e:
        return {"available": False, "reason": f"Neočekivan odgovor Ollama servera: {e}"}

    if not text:
        return {"available": False, "reason": "Model je vratio prazan odgovor."}

    validation = validate_conclusion(text, prompt)

    return {
        "available": True,
        "model": AI_MODEL,
        "engine": "ollama (lokalno)",
        "conclusion": text,
        "validation": validation,
        "usage": {
            "input_tokens": body.get("prompt_eval_count", 0),
            "output_tokens": body.get("eval_count", 0),
        },
    }


_ENTITY_RE = {
    "telefon": re.compile(r"\+\d{9,15}"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "sekcija": re.compile(r"(?m)^\s*[1-7]\."),
}


def validate_conclusion(text: str, source_prompt: str) -> dict:
    """
    Provera halucinacija: svaki entitet (telefon/email/kripto adresa) koji AI
    navede MORA postojati u ulaznim nalazima. Vraća listu potencijalno
    izmišljenih vrednosti + da li su sve sekcije prisutne.
    """
    fabricated = []
    for kind, rx in _ENTITY_RE.items():
        if kind == "sekcija":
            continue
        for tok in set(rx.findall(text)):
            if tok not in source_prompt:
                fabricated.append({"type": kind, "value": tok})
    sections = len(_ENTITY_RE["sekcija"].findall(text))
    return {
        "sections_found": sections,
        "sections_ok": sections >= 7,
        "possible_fabrications": fabricated,
        "clean": len(fabricated) == 0 and sections >= 7,
    }
