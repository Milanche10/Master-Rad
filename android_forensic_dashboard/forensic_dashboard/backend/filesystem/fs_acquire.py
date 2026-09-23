"""
fs_acquire.py — Android File System Acquisition (spec §8–17)
─────────────────────────────────────────────────────────────
Stvarna akvizicija DOSTUPNOG filesystem sadržaja preko IFileSystemAccess:
  1) za svaku ciljanu lokaciju utvrdi STANJE (available/denied/encrypted/…),
  2) prenese dostupan sadržaj (stream, otporno na greške, sa otkazivanjem),
  3) svaki entry dobije STATUS + metapodatke (spec §10) + SHA-256 (stream, spec §15),
  4) symlink-ovi se beleže bez praćenja (bez rekurzije, spec §16),
  5) generiše bogat manifest (po fajlu status) + standardni hash manifest.

Raspored u Evidence je Android-FS (data/data, data/media/0, …) tako da POSTOJEĆI
DumpResolver/analiza čita rezultat bez izmene (spec §12,§13).
"""

import csv
import json
import os
from pathlib import Path

from acquisition import base, cases_fs
from .status import FileStatus, LocationStatus

# Ciljane lokacije: (putanja na uređaju, relativna putanja u Evidence).
# Evidence raspored je Android-FS, pa ga DumpResolver prepoznaje po sidrima.
DEFAULT_TARGETS = [
    ("/data/data", "data/data"),
    ("/data/system", "data/system"),
    ("/data/misc", "data/misc"),
    ("/data/user/0", "data/user/0"),
    ("/data/user_de/0", "data/user_de/0"),
    ("/sdcard", "data/media/0"),
]

MAX_JSON_ENTRIES = 20000   # ceo popis ide u CSV; JSON nosi rezime + prvih N


def _ext(name: str) -> str:
    i = name.rfind(".")
    return name[i:].lower() if i > 0 else ""


class FileSystemAcquisition:
    def __init__(self, access, targets=None):
        self.access = access
        self.targets = targets or DEFAULT_TARGETS

    def run(self, ev, cid: str, progress) -> dict:
        ev = Path(ev)
        entries: list[dict] = []
        locations: list[dict] = []
        manifest = base.EvidenceManifest(case_id=cid, source="mobile-filesystem")
        totals = {k: 0 for k in ("ACQUIRED", "SKIPPED", "PERMISSION_DENIED", "NOT_PRESENT",
                                 "NOT_MOUNTED", "ENCRYPTED", "UNAVAILABLE", "ERROR",
                                 "dirs", "links", "bytes")}
        crypto = self.access.crypto_state()

        n_targets = len(self.targets)
        for ti, (dev_path, ev_rel) in enumerate(self.targets):
            if progress and progress.cancelled():
                break
            base_pct = 30 + int(ti / max(1, n_targets) * 55)
            progress.update(base_pct, f"File-system: lokacija {dev_path} …") if progress else None

            loc_status, reason = self.access.location_status(dev_path)
            loc_rec = {"path": dev_path, "evidence_rel": ev_rel, "status": loc_status,
                       "reason": reason, "acquired": 0, "denied": 0, "errors": 0,
                       "files": 0, "dirs": 0, "links": 0, "bytes": 0}

            if loc_status != LocationStatus.AVAILABLE:
                # Lokacija kao celina nije dostupna — pošteno zabeleži (bez izmišljanja).
                # (totals su brojači PO FAJLU; status lokacije je u 'locations'.)
                if progress:
                    progress.log(f"{dev_path}: {loc_status} — {reason}")
                cases_fs.append_log(cid, f"File-system lokacija {dev_path}: {loc_status} ({reason})")
                locations.append(loc_rec)
                continue

            # 1) prenos dostupnog sadržaja (bulk stream)
            dest = ev / ev_rel
            if progress:
                progress.log(f"Prenos sadržaja: {dev_path} → {ev_rel}")
            ok, note = self.access.pull_tree(dev_path, dest, progress=progress)
            if not ok and note == "otkazano":
                locations.append(loc_rec)
                break
            if not ok and progress:
                progress.log(f"{dev_path}: prenos delimičan/neuspešan ({note}) — status po fajlu sledi.")

            # 2) metapodaci + status po entry-ju (reconcile sa prenetim sadržajem)
            count = 0
            for st in self.access.enumerate(dev_path):
                if progress and count % 500 == 0 and progress.cancelled():
                    break
                count += 1
                rel = st.path[len(dev_path.rstrip("/")):].lstrip("/")
                ev_path = (ev_rel + "/" + rel).replace("\\", "/").rstrip("/")
                dest_file = ev / ev_rel / rel if rel else ev / ev_rel

                rec = {
                    "path": st.path, "evidencePath": ev_path,
                    "filename": os.path.basename(st.path), "extension": _ext(st.path),
                    "type": st.entry_type, "size": st.size, "mode": st.mode,
                    "uid": st.uid, "gid": st.gid, "inode": st.inode,
                    "mtime": st.mtime, "atime": st.atime, "ctime": st.ctime,
                    "link_target": st.link_target, "sha256": None,
                    "acquisitionStatus": None,
                }

                if st.entry_type == "dir":
                    rec["acquisitionStatus"] = FileStatus.ACQUIRED
                    totals["dirs"] += 1; loc_rec["dirs"] += 1
                elif st.entry_type == "link":
                    # spec §16: zabeleži link + target, NE prati ga (bez rekurzije)
                    rec["acquisitionStatus"] = FileStatus.ACQUIRED
                    totals["links"] += 1; loc_rec["links"] += 1
                elif not st.readable:
                    rec["acquisitionStatus"] = FileStatus.PERMISSION_DENIED
                    totals["PERMISSION_DENIED"] += 1; loc_rec["denied"] += 1
                elif dest_file.is_file():
                    hashes = base.compute_hashes(dest_file)   # streaming (spec §15)
                    if hashes:
                        rec["sha256"] = hashes.get("sha256")
                        try:
                            rec["size"] = dest_file.stat().st_size
                        except Exception:
                            pass
                        rec["acquisitionStatus"] = FileStatus.ACQUIRED
                        totals["ACQUIRED"] += 1; loc_rec["acquired"] += 1; loc_rec["files"] += 1
                        totals["bytes"] += rec["size"] or 0; loc_rec["bytes"] += rec["size"] or 0
                        try:
                            manifest.add(ev_path, dest_file, hashes)
                        except Exception:
                            pass
                    else:
                        rec["acquisitionStatus"] = FileStatus.ERROR
                        totals["ERROR"] += 1; loc_rec["errors"] += 1
                else:
                    # nabrojan kao čitljiv, ali nije prenet → greška/nedostupan pri prenosu
                    rec["acquisitionStatus"] = FileStatus.ERROR
                    totals["ERROR"] += 1; loc_rec["errors"] += 1

                entries.append(rec)
                if progress and count % 200 == 0:
                    progress.update(min(88, base_pct),
                                    f"{dev_path}: {loc_rec['acquired']} fajlova, "
                                    f"{loc_rec['denied']} denied…")

            cases_fs.append_log(
                cid, f"File-system {dev_path}: acquired={loc_rec['acquired']}, "
                     f"denied={loc_rec['denied']}, errors={loc_rec['errors']}, "
                     f"dirs={loc_rec['dirs']}, links={loc_rec['links']}.")
            locations.append(loc_rec)

        # 3) zapiši manifeste (bogati po-fajlu + standardni hash manifest)
        progress.update(90, "Upisivanje filesystem manifesta…") if progress else None
        self._write_manifests(ev, cid, entries, totals, locations, crypto)
        try:
            manifest.write(cases_fs.case_dir(cid) / "Logs")
            manifest.write(ev / "Metadata")
        except Exception:
            pass
        std_summary = manifest.summary()

        totals["bytes_human"] = base.human_size(totals["bytes"])
        totals["files_total"] = totals["ACQUIRED"] + totals["PERMISSION_DENIED"] + totals["ERROR"]
        return {
            "method": "file_system",
            "access": self.access.name,
            "privileged": bool(self.access.privileged),
            "crypto_state": crypto,
            "locations": locations,
            "totals": totals,
            "manifest_summary": std_summary,
            "entry_count": len(entries),
            "ok": totals["ACQUIRED"] > 0,
        }

    def _write_manifests(self, ev: Path, cid: str, entries, totals, locations, crypto):
        doc = {
            "summary": {
                "case_id": cid, "access": self.access.name,
                "privileged": bool(self.access.privileged), "crypto_state": crypto,
                "totals": totals,
                "locations": [{k: l[k] for k in ("path", "status", "acquired", "denied",
                                                 "errors", "files", "dirs", "links", "bytes")}
                              for l in locations],
            },
            "files": entries[:MAX_JSON_ENTRIES],
            "files_truncated": len(entries) > MAX_JSON_ENTRIES,
        }
        for out_dir in (cases_fs.case_dir(cid) / "Logs", ev / "Metadata"):
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "filesystem_manifest.json").write_text(
                    json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
        # CSV sa SVIM zapisima (ceo popis, za ručnu verifikaciju)
        try:
            csv_path = cases_fs.case_dir(cid) / "Logs" / "filesystem_manifest.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["evidencePath", "path", "type", "acquisitionStatus", "size",
                            "sha256", "mode", "uid", "gid", "inode", "mtime", "link_target"])
                for e in entries:
                    w.writerow([e["evidencePath"], e["path"], e["type"], e["acquisitionStatus"],
                                e["size"], e["sha256"], e["mode"], e["uid"], e["gid"],
                                e["inode"], e["mtime"], e["link_target"]])
        except Exception:
            pass
