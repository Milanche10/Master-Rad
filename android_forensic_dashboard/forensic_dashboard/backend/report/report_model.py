"""
report/report_model.py — Deterministic Report Model (Upgrade #8)
────────────────────────────────────────────────────────────────
Kanonski, DETERMINISTIČKI JSON model izveštaja. Ovo je "structured report
first" sloj: iz njega se renderuju PDF/HTML/DOCX, a AI je SAMO narativni
sloj koji se dodaje odvojeno i NIKAD ne vraća brojeve u ovaj deterministički
model.

Determinizam:
  - Sve liste sortirane stabilnim ključem.
  - Nema datetime.now()/uuid u delu koji ulazi u content_hash.
  - Isti ulaz → isti model → isti content_hash → reproducibilnost (sudska).

Metapodaci koji su volatilni (generated_at) drže se ODVOJENO od hešitanog
sadržaja (`content`), pa content_hash ostaje stabilan.
"""

import hashlib

SCHEMA_VERSION = "1.0"
MAX_TIMELINE = 500


def _canon(obj) -> str:
    """Stabilna serijalizacija za heš (bez zavisnosti od redosleda dict-a)."""
    import json
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str)


def build_report_model(data: dict) -> dict:
    """
    data = izlaz _collect_report_data() (+ opciono db_inventory summary).
    Vraća kanonski model sa odvojenim 'content' (hešira se) i 'meta' (ne).
    """
    results = data.get("results", {})
    correlations = data.get("correlations", [])
    timeline = data.get("timeline", [])
    headline = data.get("headline", [])
    all_alerts = data.get("all_alerts", [])

    # ── findings po modulu (sortirano po nazivu modula) ──
    findings_by_module = {}
    for module in sorted(results.keys()):
        fs = results[module].get("findings") or []
        findings_by_module[module] = [{"key": f.get("key"), "value": f.get("value")} for f in fs]

    # ── upozorenja (deterministički sortirana) ──
    alerts = sorted(
        [{"module": m, "text": a} for m, a in all_alerts],
        key=lambda x: (x["module"], x["text"]),
    )

    # ── korelacije (već sortirane po skoru; kanonizuj polja) ──
    corr = [{
        "id": c.get("id"), "title": c.get("title"),
        "score": c.get("score"), "band": c.get("band"),
        "detail": c.get("detail"),
        "scoring_factors": c.get("scoring_factors", []),
        "evidence": c.get("evidence", []),
        "sources": c.get("sources", []),
    } for c in correlations]

    # ── timeline (sortiran, capован) ──
    def _tl_row(e):
        return {
            "ts": e.get("ts"),
            "type": e.get("type"),
            "type_canonical": e.get("type_canonical"),
            "value": e.get("value"),
            "source": e.get("source"),
            "module": e.get("module"),
            "confidence": e.get("confidence"),
            "severity": e.get("severity"),
            "hash_sha256": (e.get("hash_set") or {}).get("sha256"),
        }
    tl_sorted = sorted(timeline, key=lambda e: (e.get("ts") or "", e.get("module") or ""))
    tl_rows = [_tl_row(e) for e in tl_sorted[:MAX_TIMELINE]]

    # ── anti-forensics izdvojeno ──
    af = results.get("anti_forensics", {})
    anti_forensics = {
        "findings": [{"key": f.get("key"), "value": f.get("value")} for f in (af.get("findings") or [])],
        "indicators": sorted(
            [a.get("value") for a in (af.get("artifacts") or [])]
        ),
        "alert_count": len(af.get("alerts") or []),
    }

    content = {
        "schema_version": SCHEMA_VERSION,
        "device": {
            "device": data.get("device_str"),
            "android": data.get("android_str"),
            "dump_path": data.get("dump_path"),
        },
        "summary": {
            "modules": len(results),
            "artifacts": data.get("total_artifacts", 0),
            "alerts": len(all_alerts),
            "correlations": len(correlations),
            "timeline_events": len(timeline),
            "reconstruction_events": len(headline),
        },
        "findings_by_module": findings_by_module,
        "alerts": alerts,
        "correlations": corr,
        "anti_forensics": anti_forensics,
        "timeline": {
            "total": len(timeline),
            "shown": len(tl_rows),
            "events": tl_rows,
        },
    }

    content_hash = hashlib.sha256(_canon(content).encode("utf-8")).hexdigest()

    return {
        "content": content,
        "meta": {   # volatilno — NE ulazi u content_hash
            "generated_at": data.get("now"),
            "tool_version": data.get("tool_version", "1.0.0"),
            "content_hash": content_hash,
        },
    }
