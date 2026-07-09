"""
phone.py — Logička akvizicija Android telefona preko USB-a (adb)
────────────────────────────────────────────────────────────────
Logička (ne fizička) akvizicija povezanog Android telefona pomoću
`adb` (Android platform-tools). Bez root-a se prikuplja ono što je
zaista dostupno preko USB debugging-a:

  • system/build.prop        ← sintetisan iz `adb shell getprop`
                                (samo stvarno vraćene vrednosti, bez izmišljanja)
  • data/media/0/…           ← korisničko skladište (/sdcard) preko `adb pull -a`
  • data/system/packages.list← lista instaliranih paketa (`pm list packages`)

Rezultujući raspored je namerno u Android-FS obliku (data/media/0/DCIM,
data/system, system/build.prop, …) tako da POSTOJEĆI DumpResolver i
analitički engine rade nad `Evidence/` bez ikakve izmene.

POŠTENA OGRANIČENJA (bez root-a se NE mogu prikupiti):
  • aplikacioni privatni podaci (/data/data/<paket>) — baze SMS/poziva/aplikacija
    su van domašaja bez root/ADB-backup pristupa;
  • fizička particija, IMEI (modem/EFS), izbrisani prostor.
Ta ograničenja se JASNO loguju i navode u izveštaju — ništa se ne izmišlja.

Izvor (telefon) se SAMO čita — `adb pull` ne menja originalne fajlove na uređaju.
Nijedna operacija ne baca izuzetak na pojedinačnom fajlu — greška se loguje i
preskače, kao i u ostatku acquisition sloja.
"""

import re
from pathlib import Path

from . import base, cases_fs, detect

# Regex za `getprop` izlaz: linije oblika  [ro.product.model]: [SM-G973F]
_PROP_RE = re.compile(r"\[([^\]]+)\]:\s*\[([^\]]*)\]")

# Ključevi koje pišemo u sintetički build.prop (samo ako su stvarno vraćeni).
# Redosled je stabilan radi čitljivosti izveštaja.
_BUILD_PROP_KEYS = [
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.name",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.display.id",
    "ro.build.fingerprint",
    "ro.serialno",
]

# Maksimalan broj fajlova koji ulazi u manifest (heš svakog fajla je skup).
# Na telefonima sa hiljadama medija fajlova, kapiramo radi performansi.
MANIFEST_FILE_CAP = 5000


def _adb_cmd(adb: str, serial: str, *args) -> list:
    """Sastavi adb komandu; dodaj -s <serial> samo ako je serijski poznat."""
    cmd = [adb]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return cmd


def _resolve_serial(adb: str, serial: str, progress) -> str:
    """
    Ako serijski nije prosleđen, pokušaj da ga jednoznačno utvrdiš iz
    `adb devices`. Vraća serijski ili "" (bare adb). Nikad ne izmišlja uređaj:
    ako ima 0 ili >1 spremnih uređaja, vraća prosleđenu (moguće praznu) vrednost
    i to loguje — korisnik/gornji sloj bira uređaj eksplicitno.
    """
    if serial:
        return serial
    rc, out, _ = detect._run([adb, "devices"], timeout=15)
    if rc != 0:
        return ""
    ready = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line:
            continue
        s, state = line.split("\t", 1)
        if state.strip() == "device":
            ready.append(s.strip())
    if len(ready) == 1:
        progress.log(f"Serijski broj automatski određen: {ready[0]}")
        return ready[0]
    if len(ready) > 1:
        progress.log(f"Povezano više uređaja ({len(ready)}) — serijski nije "
                     f"jednoznačan; koristi se podrazumevani adb cilj.")
    return ""


def _getprop(adb: str, serial: str) -> dict:
    """`adb shell getprop` → dict svojstava (samo stvarno vraćene vrednosti)."""
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "shell", "getprop"), timeout=20)
    props = {}
    if rc == 0:
        for line in out.splitlines():
            m = _PROP_RE.match(line.strip())
            if m:
                props[m.group(1)] = m.group(2)
    return props


def _write_build_prop(ev: Path, props: dict) -> dict:
    """
    Zapiši ev/system/build.prop u realnom build.prop stilu (key=value),
    samo za ključeve koje je uređaj zaista vratio (bez izmišljanja).
    Vraća dict {kljuc: vrednost} onoga što je stvarno upisano.
    """
    written = {}
    lines = [
        "# Sintetisan iz `adb shell getprop` (Android Forensic Dashboard).",
        "# Sadrži SAMO vrednosti koje je uređaj stvarno vratio (bez izmišljanja).",
        "# Format je kompatibilan sa parserom build.prop analitičkog modula.",
    ]
    for key in _BUILD_PROP_KEYS:
        val = props.get(key)
        if val:  # samo ne-prazne, stvarno vraćene vrednosti
            lines.append(f"{key}={val}")
            written[key] = val
    try:
        out = ev / "system" / "build.prop"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass
    return written


def _pull_sdcard(adb: str, serial: str, ev: Path, progress) -> dict:
    """
    Best-effort: `adb pull -a /sdcard/. <ev>/data/media/0`.
    Uz USB debugging /sdcard je čitljiv i bez root-a. Na grešci loguje i
    nastavlja (ne baca izuzetak). Vraća {ok, rc, note}.
    """
    dst = ev / "data" / "media" / "0"
    try:
        dst.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    progress.update(30, "Preuzimanje korisničkog skladišta (/sdcard)…")
    progress.log("adb pull -a /sdcard/. → data/media/0 (može potrajati)…")
    # -a: očuvaj vremenske pečate i mod fajlova (bliže originalnim metapodacima).
    rc, out, err = detect._run(
        _adb_cmd(adb, serial, "pull", "-a", "/sdcard/.", str(dst)),
        timeout=1800,  # do 30 min za veliko skladište
    )
    tail = (out.strip().splitlines()[-1] if out.strip() else "") or \
           (err.strip().splitlines()[-1] if err.strip() else "")
    if rc == 0:
        progress.log(f"Skladište preuzeto (/sdcard). {tail}".strip())
        return {"ok": True, "rc": rc, "note": tail}
    progress.log(f"Preuzimanje /sdcard nije uspelo (rc={rc}): "
                 f"{err.strip() or out.strip() or 'nepoznata greška'}")
    return {"ok": False, "rc": rc,
            "note": (err.strip() or out.strip() or f"rc={rc}")}


def _pull_packages(adb: str, serial: str, ev: Path, progress) -> int:
    """
    `adb shell pm list packages` → ev/data/system/packages.list (po jedan
    paket u redu, kao na Android-u), da postojeći device_info/apk moduli mogu
    da ga čitaju. Vraća broj paketa (0 ako neuspešno). Ne baca izuzetak.
    """
    progress.log("Očitavanje instaliranih paketa (pm list packages)…")
    rc, out, err = detect._run(
        _adb_cmd(adb, serial, "shell", "pm", "list", "packages"), timeout=60)
    if rc != 0:
        progress.log(f"pm list packages nije uspelo (rc={rc}): "
                     f"{err.strip() or 'nepoznata greška'}")
        return 0
    pkgs = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            name = line[len("package:"):].strip()
            if name:
                pkgs.append(name)
    try:
        dst = ev / "data" / "system" / "packages.list"
        dst.parent.mkdir(parents=True, exist_ok=True)
        # Android packages.list ima više kolona; postojeći moduli koriste
        # packages.xml/data-root za detalje, pa je ovde dovoljna lista imena.
        dst.write_text("\n".join(pkgs) + ("\n" if pkgs else ""), encoding="utf-8")
    except Exception:
        pass
    progress.log(f"Pronađeno instaliranih paketa: {len(pkgs)}.")
    return len(pkgs)


def _build_manifest(ev: Path, cid: str, progress) -> tuple:
    """
    Prošetaj ev/, izračunaj heševe i sagradi EvidenceManifest.
    Kapira na MANIFEST_FILE_CAP fajlova radi performansi (uz jasnu napomenu).
    Vraća (manifest, capped: bool, seen_total: int).
    """
    manifest = base.EvidenceManifest(case_id=cid, source="mobile")
    all_files = list(base.iter_files(ev))
    seen_total = len(all_files)
    capped = seen_total > MANIFEST_FILE_CAP
    files = all_files[:MANIFEST_FILE_CAP]
    total = len(files) or 1

    progress.update(80, f"Heširanje dokaza ({total} fajlova)…")
    for i, f in enumerate(files):
        if progress.cancelled():
            progress.log("Heširanje prekinuto (otkazivanje korisnika).")
            break
        try:
            rel = f.relative_to(ev)
        except Exception:
            rel = Path(f.name)
        try:
            hashes = base.compute_hashes(f)
            if hashes:
                manifest.add(str(rel), f, hashes)
            else:
                manifest.add_error(str(rel), "heš nije izračunat (nedostupan fajl)")
        except Exception as e:
            manifest.add_error(str(rel), str(e))
        if i % 50 == 0 or i == total - 1:
            pct = 80 + int((i + 1) / total * 15)  # 80→95%
            progress.update(pct, f"Heširano {i + 1}/{total} fajlova…")

    if capped:
        note = (f"Manifest je ograničen na prvih {MANIFEST_FILE_CAP} od "
                f"{seen_total} fajlova (radi performansi).")
        manifest.add_error("__manifest__", note)
        progress.log(note)
    return manifest, capped, seen_total


def acquire_phone(progress, serial: str = "", examiner: str = "",
                  device_info: dict = None) -> dict:
    """
    Target funkcija za jobs.start_job. Logička akvizicija USB Android telefona
    preko adb. Vraća dict po ugovoru drajvera:
    {case_id, source, evidence_path, case_path, stats, device,
     report_data, cancelled}.
    """
    device_info = device_info or {}

    # ── 1. adb dostupnost ────────────────────────────────────────────────
    adb = detect.adb_path()
    if adb is None:
        raise RuntimeError(
            "adb (Android platform-tools) nije pronađen. Instaliraj Android "
            "platform-tools i dodaj folder u PATH (ili postavi ANDROID_HOME), "
            "uključi USB debugging na telefonu i potvrdi 'Allow USB debugging', "
            "pa pokušaj ponovo.")

    # ── 2. Slučaj na disku ───────────────────────────────────────────────
    case = cases_fs.create_case_folder(
        source="mobile", examiner=examiner, device_info=device_info)
    cid = case["case_id"]
    ev = Path(case["evidence_path"])
    progress.log(f"Slučaj {cid} kreiran. Izvor: USB Android telefon (adb).")
    progress.update(5, "Priprema akvizicije telefona…")

    serial = _resolve_serial(adb, serial, progress)
    if serial:
        cases_fs.append_log(cid, f"Ciljani uređaj (serijski): {serial}.")

    notes = []

    # ── 3. build.prop iz getprop ─────────────────────────────────────────
    progress.update(12, "Očitavanje svojstava uređaja (getprop)…")
    props = _getprop(adb, serial)
    written = _write_build_prop(ev, props)

    device = {
        "model": props.get("ro.product.model") or device_info.get("model"),
        "manufacturer": props.get("ro.product.manufacturer")
                        or device_info.get("manufacturer"),
        "device": props.get("ro.product.device") or device_info.get("device"),
        "android": props.get("ro.build.version.release")
                   or device_info.get("android"),
        "sdk": props.get("ro.build.version.sdk") or device_info.get("sdk"),
        "serial": props.get("ro.serialno") or serial or device_info.get("serial"),
        "security_patch": props.get("ro.build.version.security_patch"),
        "connection": "USB",
        "adb_serial": serial,
    }
    if written:
        progress.log(f"build.prop sintetisan iz {len(written)} stvarnih svojstava "
                     f"(model: {device.get('model') or 'nepoznat'}).")
        cases_fs.append_log(
            cid, f"Uređaj: {device.get('manufacturer') or '?'} "
                 f"{device.get('model') or '?'}, Android "
                 f"{device.get('android') or '?'} (SDK {device.get('sdk') or '?'}).")
    else:
        note = ("getprop nije vratio svojstva — build.prop je prazan. Proveri da "
                "je uređaj autorizovan (Allow USB debugging).")
        notes.append(note)
        progress.log(note)

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, 0, notes,
                       progress, cancelled=True)

    # ── 4. Korisničko skladište (/sdcard) ────────────────────────────────
    pull = _pull_sdcard(adb, serial, ev, progress)
    if not pull["ok"]:
        notes.append("Preuzimanje korisničkog skladišta (/sdcard) nije u "
                     "potpunosti uspelo: " + str(pull.get("note")))
    cases_fs.append_log(cid, f"Preuzimanje /sdcard → data/media/0 "
                             f"(uspeh: {pull['ok']}). {pull.get('note') or ''}".strip())

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, 0, notes,
                       progress, cancelled=True)

    # ── 5. Instalirane aplikacije ────────────────────────────────────────
    packages_count = _pull_packages(adb, serial, ev, progress)
    cases_fs.append_log(cid, f"Instaliranih paketa: {packages_count} "
                             f"(→ data/system/packages.list).")

    # ── 6. Pošteno ograničenje: /data/data bez root-a ────────────────────
    limitation = ("Aplikacioni privatni podaci (/data/data/<paket>) NISU "
                  "prikupljeni — nedostupni su bez root pristupa. Baze SMS-a, "
                  "poziva i aplikacija stoga nisu obuhvaćene ovom logičkom "
                  "akvizicijom (prikupljeno: /sdcard, svojstva uređaja, lista paketa).")
    notes.append(limitation)
    notes.append("IMEI (modem/EFS particija) i izbrisani prostor nisu dostupni "
                 "u logičkoj akviziciji bez root-a.")
    progress.log(limitation)
    cases_fs.append_log(cid, limitation)

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, packages_count, notes,
                       progress, cancelled=True)

    # ── 7. Manifest (integritet) ─────────────────────────────────────────
    manifest, capped, seen_total = _build_manifest(ev, cid, progress)
    if capped:
        notes.append(f"Manifest je ograničen na prvih {MANIFEST_FILE_CAP} od "
                     f"{seen_total} fajlova (radi performansi).")

    progress.update(96, "Upisivanje manifesta dokaza…")
    manifest.write(cases_fs.case_dir(cid) / "Logs")
    manifest.write(ev / "Metadata")
    summary = manifest.summary()
    cases_fs.append_log(
        cid, f"Manifest: {summary['file_count']} zapisa "
             f"({summary['total_size_human']}), grešaka: {summary['error_count']}.")

    return _finish(cid, ev, case, device, manifest, capped, packages_count,
                   notes, progress, cancelled=progress.cancelled(),
                   summary=summary)


def _finish(cid, ev, case, device, manifest, capped, packages_count, notes,
            progress, cancelled=False, summary=None):
    """
    Zajednički završetak: upiši manifest ako još nije (rani izlaz zbog
    otkazivanja), ažuriraj case.json i sastavi povratni dict po ugovoru.
    """
    if summary is None:
        if manifest is None:
            manifest = base.EvidenceManifest(case_id=cid, source="mobile")
        # Rani izlaz (otkazivanje): svejedno upiši ono što imamo radi traga.
        try:
            manifest.write(cases_fs.case_dir(cid) / "Logs")
            manifest.write(ev / "Metadata")
        except Exception:
            pass
        summary = manifest.summary()

    stats = {
        "copied": summary["file_count"],
        "skipped": summary["error_count"],
        "total_seen": summary["file_count"] + summary["error_count"],
        "bytes": summary["total_bytes"],
        "bytes_human": summary["total_size_human"],
    }

    cases_fs.update_case_meta(
        cid,
        status="cancelled" if cancelled else "acquired",
        hashes={"manifest_files": summary["file_count"],
                "total_bytes": summary["total_bytes"],
                "total_size_human": summary["total_size_human"]},
    )

    if cancelled:
        progress.log("Akvizicija telefona otkazana — sačuvano je ono što je do "
                     "tada prikupljeno (uz manifest).")
    else:
        progress.update(100, "Akvizicija telefona završena.")

    report_data = {
        "kind": "mobile",
        "case_id": cid,
        "device": device,
        "stats": stats,
        "manifest_summary": summary,
        "packages_count": packages_count,
        "notes": notes,
        "manifest_capped": bool(capped),
    }

    return {
        "case_id": cid,
        "source": "mobile",
        "evidence_path": case["evidence_path"],   # → predaje se create_session
        "case_path": str(cases_fs.case_dir(cid)),
        "stats": stats,
        "manifest_summary": summary,
        "device": device,
        "report_data": report_data,
        "cancelled": cancelled,
    }
