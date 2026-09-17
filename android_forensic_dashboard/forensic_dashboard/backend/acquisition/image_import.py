"""
image_import.py — Uvoz i parsiranje forenzičke slike (Faza 4, spec §17–18)
────────────────────────────────────────────────────────────────────────────
Uzima postojeću sirovu sliku (raw/dd/.img — npr. userdata.img iz fizičke
akvizicije, ili izlaz eksternog alata), hešira original (integritet dokaza),
ekstrahuje fajl sisteme preko pytsk3 u Evidence stablo, i pravi manifest.
Rezultujući Evidence/ folder se predaje POSTOJEĆEM analitičkom engine-u.

Original slika se NIKAD ne menja (samo se čita). Ovo je ANALIZA/uvoz, ne
akvizicija sa uređaja (spec §17).
"""

from pathlib import Path

from . import base, cases_fs

MANIFEST_FILE_CAP = 8000


def _build_manifest(ev: Path, cid: str, progress) -> tuple:
    manifest = base.EvidenceManifest(case_id=cid, source="image")
    all_files = list(base.iter_files(ev))
    seen = len(all_files)
    capped = seen > MANIFEST_FILE_CAP
    files = all_files[:MANIFEST_FILE_CAP]
    total = len(files) or 1
    progress.update(92, f"Heširanje ekstrahovanih fajlova ({total})…")
    for i, f in enumerate(files):
        if progress.cancelled():
            break
        try:
            rel = f.relative_to(ev)
        except Exception:
            rel = Path(f.name)
        try:
            h = base.compute_hashes(f)
            manifest.add(str(rel), f, h) if h else manifest.add_error(str(rel), "heš nedostupan")
        except Exception as e:
            manifest.add_error(str(rel), str(e))
    return manifest, capped, seen


def acquire_image(progress, image_path: str = "", examiner: str = "") -> dict:
    """
    Target za jobs.start_job. Parsira forenzičku sliku u Evidence stablo.
    Vraća standardni acquisition dict {case_id, source, evidence_path, ...}.
    """
    from analysis import image_parser

    p = Path(image_path)
    if not p.exists() or not p.is_file():
        raise RuntimeError(f"Forenzička slika nije pronađena: {image_path}")
    if not image_parser.pytsk3_available():
        raise RuntimeError("pytsk3 (The Sleuth Kit) nije instaliran. Instaliraj: pip install pytsk3.")

    size = p.stat().st_size
    case = cases_fs.create_case_folder(
        source="image", examiner=examiner,
        device_info={"image": p.name, "size": size, "path": str(p)})
    cid = case["case_id"]
    ev = Path(case["evidence_path"])
    progress.log(f"Slučaj {cid}. Uvoz forenzičke slike: {p.name} ({size // 1048576} MB).")

    # 1) Heš originala PRE parsiranja (integritet dokaza)
    progress.update(6, "Heširanje originalne slike (SHA-256)…")
    img_hashes = base.compute_hashes(p)
    cases_fs.append_log(cid, f"Original slika {p.name}: SHA-256 {(img_hashes or {}).get('sha256','?')}")

    # 2) Ekstrakcija (pytsk3)
    progress.update(15, "Prepoznavanje particija i fajl sistema (pytsk3)…")
    stats = image_parser.analyze_image(p, ev, progress=progress,
                                       cancel=lambda: progress.cancelled())

    recognized = stats.get("partitions", 0)
    notes = []
    if recognized == 0:
        notes.append("Nijedan fajl sistem NIJE prepoznat u slici. Najčešći razlog: Android "
                     "File-Based Encryption (sirov userdata sa šifrovanog uređaja je šifrovan) "
                     "ili f2fs koji TSK ne podržava. Čitljive podatke daje FILE-SYSTEM akvizicija "
                     "(root `tar` nad otključanim uređajem) — ne sirov `dd`.")
        progress.log(notes[-1])
    if stats.get("capped"):
        notes.append(f"Ekstrakcija je ograničena (bezbednosni limit {image_parser.MAX_FILES} fajlova).")

    # 3) Manifest ekstrahovanih fajlova
    manifest, capped, seen = _build_manifest(ev, cid, progress)
    manifest.write(cases_fs.case_dir(cid) / "Logs")
    manifest.write(ev / "Metadata")
    summary = manifest.summary()
    cases_fs.append_log(cid, f"Ekstrahovano {stats.get('files',0)} fajlova iz slike; "
                             f"manifest {summary['file_count']} zapisa "
                             f"({summary['total_size_human']}). Prepoznatih FS: {recognized}.")

    cancelled = progress.cancelled()
    cases_fs.update_case_meta(cid, status="cancelled" if cancelled else "acquired",
                              hashes={"image_sha256": (img_hashes or {}).get("sha256"),
                                      "extracted_files": stats.get("files", 0)})
    if not cancelled:
        progress.update(100, "Parsiranje slike završeno.")

    stats_out = {"copied": summary["file_count"], "skipped": summary["error_count"],
                 "total_seen": seen, "bytes": summary["total_bytes"],
                 "bytes_human": summary["total_size_human"]}

    report_data = {
        "kind": "image", "case_id": cid,
        "image": {"name": p.name, "size": size, "sha256": (img_hashes or {}).get("sha256")},
        "parse_stats": stats, "stats": stats_out, "manifest_summary": summary, "notes": notes,
    }
    return {
        "case_id": cid, "source": "image",
        "evidence_path": case["evidence_path"],
        "case_path": str(cases_fs.case_dir(cid)),
        "stats": stats_out, "manifest_summary": summary,
        "device": {"model": p.name, "image_sha256": (img_hashes or {}).get("sha256")},
        "report_data": report_data, "cancelled": cancelled,
    }
