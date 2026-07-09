"""
storage.py — Akvizicija SD kartice i USB fleš diska
────────────────────────────────────────────────────
Puna logička akvizicija uklonjivog diska:
  • rekurzivno kopiranje SVIH fajlova uz očuvanje strukture i vremenskih pečata,
  • MD5/SHA-1/SHA-256 svakog fajla → manifest (integritet svakog dokaza),
  • napredak + otkazivanje (radi u pozadinskoj niti preko jobs.start_job).

Original (SD/USB) se SAMO čita — nikad ne menja. Rezultat je folder slučaja
sa Evidence/SDCard (ili Evidence/USB) + manifest u Logs/ i Metadata/.
"""

import os
from pathlib import Path

from . import base, cases_fs


def _top_level_overview(root: Path, limit: int = 40) -> list:
    """Kratak pregled sadržaja korena diska (za izveštaj), bez rekurzije."""
    out = []
    try:
        for entry in sorted(root.iterdir()):
            try:
                if entry.is_dir():
                    out.append({"name": entry.name, "type": "dir"})
                else:
                    out.append({"name": entry.name, "type": "file",
                                "size": entry.stat().st_size})
            except Exception:
                continue
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


def acquire_storage(progress, mount: str = "", kind: str = "sdcard",
                    examiner: str = "", disk_info: dict = None) -> dict:
    """
    Target funkcija za jobs.start_job. Kopira ceo `mount` u folder slučaja.
    kind: 'sdcard' | 'usb'. Vraća {case_id, evidence_path, stats, report_data}.
    """
    disk_info = disk_info or {}
    src = Path(mount)
    if not src.exists() or not src.is_dir():
        raise RuntimeError(f"Izvorni disk nije dostupan: {mount}")

    subdir = "SDCard" if kind == "sdcard" else "USB"
    device_meta = {
        "name": disk_info.get("name"),
        "model": disk_info.get("name"),
        "device_id": disk_info.get("device_id") or mount,
        "filesystem": disk_info.get("filesystem"),
        "size": disk_info.get("size"),
        "size_human": disk_info.get("size_human"),
        "bus": disk_info.get("bus"),
        "mount": mount,
    }

    case = cases_fs.create_case_folder(source=kind, examiner=examiner, device_info=device_meta)
    cid = case["case_id"]
    cases_fs.append_log(cid, f"Akvizicija {kind.upper()} sa {mount} "
                             f"(FS: {device_meta.get('filesystem')}, "
                             f"veličina: {device_meta.get('size_human')}).")
    progress.log(f"Slučaj {cid} kreiran. Izvor: {mount}")
    progress.update(2, "Popisivanje fajlova…")

    dst = Path(case["evidence_path"]) / subdir
    manifest = base.EvidenceManifest(case_id=cid, source=kind)

    stats = base.copy_tree_preserving(src, dst, manifest, progress=progress, kind=kind)

    # Manifest (integritet) u Logs/ i Metadata/
    manifest.write(cases_fs.case_dir(cid) / "Logs")
    manifest.write(Path(case["evidence_path"]) / "Metadata")
    summary = manifest.summary()

    cases_fs.append_log(cid, f"Kopirano {stats['copied']} fajlova "
                             f"({stats['bytes_human']}), preskočeno {stats['skipped']}. "
                             f"Manifest: {summary['file_count']} zapisa.")

    cancelled = progress.cancelled()
    cases_fs.update_case_meta(
        cid,
        status="cancelled" if cancelled else "acquired",
        hashes={"manifest_files": summary["file_count"],
                "total_bytes": summary["total_bytes"],
                "total_size_human": summary["total_size_human"]},
    )

    report_data = {
        "kind": kind,
        "case_id": cid,
        "device": device_meta,
        "stats": stats,
        "manifest_summary": summary,
        "overview": _top_level_overview(src),
        "manifest_files": manifest.entries[:1000],  # za tabelu u izveštaju
    }

    return {
        "case_id": cid,
        "source": kind,
        "evidence_path": case["evidence_path"],       # → predaje se create_session
        "case_path": str(cases_fs.case_dir(cid)),
        "stats": stats,
        "manifest_summary": summary,
        "device": device_meta,
        "report_data": report_data,
        "cancelled": cancelled,
    }
