"""
packager.py — Pakovanje slučaja i namenski izveštaji akvizicije
────────────────────────────────────────────────────────────────
  • build_case_zip / build_case_tar  → ceo slučaj (Evidence/Reports/Logs/Exports…)
    kao .zip / .tar.gz za predaju (chain of custody).
  • model_from_acquisition(report_data) → document model za SIM/SD/USB izveštaj.
  • write_report_set(case_id, model)   → Reports/Full_Report.{pdf,docx,html,txt}.
"""

import io
import tarfile
import zipfile
from pathlib import Path

from acquisition import cases_fs
from . import exporters


# ═══════════════════════════════════════════════════════════════════════════
# ZIP / TAR ceo slučaj
# ═══════════════════════════════════════════════════════════════════════════

def _iter_case_files(case_id: str):
    root = cases_fs.case_dir(case_id)
    if not root.exists():
        return None, []
    files = []
    for dirpath, _dirnames, filenames in __import__("os").walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            files.append(p)
    return root, files


def build_case_zip(case_id: str) -> tuple[bytes, str]:
    root, files = _iter_case_files(case_id)
    if root is None:
        raise FileNotFoundError(f"Slučaj {case_id} nije pronađen na disku.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            try:
                arc = Path(case_id) / p.relative_to(root)
                zf.write(p, arcname=str(arc))
            except Exception:
                continue
    return buf.getvalue(), f"{case_id}.zip"


def build_case_tar(case_id: str) -> tuple[bytes, str]:
    root, files = _iter_case_files(case_id)
    if root is None:
        raise FileNotFoundError(f"Slučaj {case_id} nije pronađen na disku.")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p in files:
            try:
                arc = Path(case_id) / p.relative_to(root)
                tf.add(p, arcname=str(arc))
            except Exception:
                continue
    return buf.getvalue(), f"{case_id}.tar.gz"


# ═══════════════════════════════════════════════════════════════════════════
# Namenski izveštaji akvizicije (SIM / SD / USB) → document model
# ═══════════════════════════════════════════════════════════════════════════

_SRC_TITLE = {
    "sdcard": "Izveštaj o akviziciji SD kartice",
    "usb": "Izveštaj o akviziciji USB fleš diska",
    "sim": "Izveštaj o akviziciji SIM kartice",
    "mobile": "Izveštaj o akviziciji telefona",
}


def _meta_from_case(case_id: str) -> list:
    m = cases_fs.read_case_meta(case_id) or {}
    out = [{"label": "Slučaj (ID)", "value": case_id},
           {"label": "Izvor", "value": m.get("source")},
           {"label": "Veštak", "value": m.get("examiner")},
           {"label": "Kreirano", "value": m.get("created_at")},
           {"label": "Status", "value": m.get("status")}]
    return [p for p in out if p.get("value")]


def _storage_report_model(rd: dict) -> dict:
    kind = rd.get("kind", "sdcard")
    dev = rd.get("device") or {}
    stats = rd.get("stats") or {}
    msum = rd.get("manifest_summary") or {}
    sections = [
        {"heading": "Informacije o uređaju/disku", "type": "keyvalue", "pairs": [
            {"label": "Naziv/oznaka", "value": dev.get("name")},
            {"label": "Identifikator", "value": dev.get("device_id")},
            {"label": "Fajl sistem", "value": dev.get("filesystem")},
            {"label": "Kapacitet", "value": dev.get("size_human")},
            {"label": "Magistrala (bus)", "value": dev.get("bus")},
            {"label": "Tačka montiranja", "value": dev.get("mount")},
        ]},
        {"heading": "Statistika akvizicije", "type": "keyvalue", "pairs": [
            {"label": "Kopirano fajlova", "value": stats.get("copied")},
            {"label": "Preskočeno (greške)", "value": stats.get("skipped")},
            {"label": "Ukupno podataka", "value": stats.get("bytes_human")},
            {"label": "Zapisa u manifestu", "value": msum.get("file_count")},
            {"label": "Ukupna veličina (manifest)", "value": msum.get("total_size_human")},
        ]},
    ]
    ov = rd.get("overview") or []
    if ov:
        sections.append({"heading": "Sadržaj korena diska", "type": "table",
                         "columns": ["Naziv", "Tip", "Veličina"],
                         "rows": [[o.get("name"), o.get("type"),
                                   (str(o.get("size")) if o.get("size") is not None else "")] for o in ov]})
    files = rd.get("manifest_files") or []
    if files:
        rows = [[f.get("path"), str(f.get("size")), f.get("modified"), (f.get("sha256") or "")[:32]]
                for f in files[:500]]
        note = "" if len(files) <= 500 else f" (prikazano prvih 500 od {len(files)})"
        sections.append({"heading": f"Manifest fajlova{note}", "type": "table",
                         "columns": ["Putanja", "Veličina", "Izmenjeno", "SHA-256 (skraćeno)"],
                         "rows": rows})
    return {"title": _SRC_TITLE.get(kind, "Izveštaj o akviziciji"),
            "subtitle": f"Slučaj {rd.get('case_id','')}",
            "meta": _meta_from_case(rd.get("case_id", "")), "sections": sections}


def _sim_report_model(rd: dict) -> dict:
    sections = [
        {"heading": "SIM identitet", "type": "keyvalue", "pairs": [
            {"label": "ICCID", "value": rd.get("iccid")},
            {"label": "IMSI", "value": rd.get("imsi")},
            {"label": "Operater", "value": rd.get("operator")},
            {"label": "MCC/MNC", "value": rd.get("mcc_mnc")},
            {"label": "Broj (MSISDN)", "value": rd.get("msisdn")},
            {"label": "ATR", "value": rd.get("atr")},
        ]},
    ]
    contacts = rd.get("contacts") or []
    if contacts:
        sections.append({"heading": f"Kontakti sa SIM ({len(contacts)})", "type": "table",
                         "columns": ["Ime", "Broj"],
                         "rows": [[c.get("name"), c.get("number")] for c in contacts]})
    sms = rd.get("sms") or []
    if sms:
        sections.append({"heading": f"SMS sa SIM ({len(sms)})", "type": "table",
                         "columns": ["Status", "Broj", "Tekst"],
                         "rows": [[m.get("status"), m.get("number"), (m.get("text") or "")[:80]] for m in sms]})
    logs = rd.get("logs") or []
    if logs:
        sections.append({"heading": "Log ekstrakcije", "type": "list", "items": logs[:40]})
    return {"title": _SRC_TITLE["sim"], "subtitle": f"Slučaj {rd.get('case_id','')}",
            "meta": _meta_from_case(rd.get("case_id", "")), "sections": sections}


def model_from_acquisition(report_data: dict) -> dict:
    """report_data['kind'] ∈ {sdcard, usb, sim, mobile} → document model."""
    kind = (report_data or {}).get("kind", "sdcard")
    if kind == "sim":
        return _sim_report_model(report_data)
    return _storage_report_model(report_data)


# ═══════════════════════════════════════════════════════════════════════════
# Upis kompleta izveštaja u Reports/ slučaja (sva 4 formata)
# ═══════════════════════════════════════════════════════════════════════════

def write_report_set(case_id: str, model: dict, basename: str = "Full_Report") -> list:
    """Napiši Reports/<basename>.{pdf,docx,html,txt}. Vraća listu putanja."""
    reports_dir = cases_fs.case_dir(case_id) / "Reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in ("pdf", "docx", "html", "txt"):
        try:
            content, _media, ext = exporters.render(model, fmt)
            out = reports_dir / f"{basename}.{ext}"
            if isinstance(content, bytes):
                out.write_bytes(content)
            else:
                out.write_text(content, encoding="utf-8")
            written.append(str(out))
        except Exception:
            continue
    return written
