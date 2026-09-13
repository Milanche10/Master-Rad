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

from . import base, cases_fs, detect, capabilities

# /data poddrveta koja se prikupljaju u FILE-SYSTEM akviziciji (samo sa root-om).
# Putanje su relativne na / (tar -C /) → ekstrakcija daje Android-FS raspored
# (data/data/<paket>, data/system, data/misc…) koji postojeći DumpResolver čita.
_FS_DATA_SUBTREES = ["data/data", "data/system", "data/misc", "data/user", "data/user_de"]

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


# adb `pull` ispisuje redove poput "[ 45%] /sdcard/DCIM/IMG.jpg" i na kraju
# "N files pulled, 0 skipped." — parsiramo ih za napredak/log.
_PULL_PCT_RE = re.compile(r"\[\s*(\d+)%\]")


def _pull_sdcard(adb: str, serial: str, ev: Path, progress) -> dict:
    """
    Preuzmi korisničko skladište (/sdcard) uz OTKAZIVANJE, napredak i zaštitu
    od zastoja. Umesto jednog blokirajućeg `adb pull /sdcard/.` (koji je znao
    da „zaglavi" bez ikakvog feedbacka), enumerišemo top-level unose /sdcard i
    pullujemo ih pojedinačno — tako je napredak vidljiv, otkazivanje radi, a
    jedan ogroman/zaključan poddirektorijum (npr. Android/) se prekine po
    zastoju bez rušenja cele akvizicije. Read-only nad uređajem. Vraća {ok, note}.
    """
    dst_root = ev / "data" / "media" / "0"
    try:
        dst_root.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    def _on_line(line: str):
        # Loguj samo relevantne redove (putanje/rezime), da log ne eksplodira.
        if line.startswith("/sdcard") or "pulled" in line or "skipped" in line \
                or "error" in line.lower():
            progress.log(line[:160])

    # 1) Enumeriši top-level unose /sdcard (kratko, sa timeout-om).
    progress.update(28, "Popisivanje korisničkog skladišta (/sdcard)…")
    rc, out, _ = detect._run(_adb_cmd(adb, serial, "shell", "ls", "-1", "/sdcard/"), timeout=25)
    entries = [e.strip() for e in out.splitlines() if e.strip() and "No such file" not in e] \
        if rc == 0 else []

    notes: list[str] = []
    ok_any = False

    if entries:
        progress.log(f"Preuzimam /sdcard po stavkama ({len(entries)}): {', '.join(entries[:8])}"
                     + (" …" if len(entries) > 8 else ""))
        total = len(entries)
        for i, name in enumerate(entries):
            if progress.cancelled():
                notes.append("Otkazano tokom preuzimanja /sdcard.")
                break
            base_pct = 30 + int(i / total * 45)   # 30 → 75%
            progress.update(base_pct, f"Preuzimanje /sdcard/{name} ({i + 1}/{total})…")
            # `adb pull -a /sdcard/<name> <dst_root>` → kreira <dst_root>/<name>
            rc2, tail = detect.run_streaming(
                _adb_cmd(adb, serial, "pull", "-a", f"/sdcard/{name}", str(dst_root)),
                progress=progress, on_line=_on_line,
                timeout=1200, stall_timeout=90)
            if rc2 == 0:
                ok_any = True
            elif rc2 == 130:
                notes.append("Otkazano tokom preuzimanja /sdcard.")
                progress.log(f"Otkazano tokom /sdcard/{name}.")
                break
            elif rc2 in (124, 125):
                reason = "vremenski limit" if rc2 == 124 else "zastoj (nema napretka)"
                notes.append(f"/sdcard/{name}: prekinuto ({reason}) — moguće delimično preuzeto.")
                progress.log(f"/sdcard/{name}: prekinuto ({reason}); nastavljam sa ostatkom.")
                ok_any = ok_any or True  # deo je verovatno preuzet
            else:
                notes.append(f"/sdcard/{name}: neuspešno (rc={rc2}).")
                progress.log(f"/sdcard/{name}: rc={rc2} {(tail or '')[-120:]}")
        return {"ok": ok_any, "rc": 0 if ok_any else 1,
                "note": ("; ".join(notes) if notes else "OK"), "per_item": True}

    # 2) Fallback: jedan streaming pull celog /sdcard (uz zaštitu od zastoja).
    progress.update(30, "Preuzimanje /sdcard (jedinstveno)…")
    progress.log("Enumeracija /sdcard nije uspela — pokušavam pun `adb pull -a /sdcard/.`")
    rc3, tail = detect.run_streaming(
        _adb_cmd(adb, serial, "pull", "-a", "/sdcard/.", str(dst_root)),
        progress=progress, on_line=_on_line, timeout=1800, stall_timeout=120)
    if rc3 == 0:
        progress.log("Skladište preuzeto (/sdcard).")
        return {"ok": True, "rc": 0, "note": "OK (pun pull)"}
    if rc3 == 130:
        return {"ok": False, "rc": 130, "note": "otkazano"}
    reason = {124: "vremenski limit", 125: "zastoj (hang) — prekinuto"}.get(rc3, f"rc={rc3}")
    progress.log(f"Preuzimanje /sdcard prekinuto: {reason}. {(tail or '')[-120:]}")
    return {"ok": False, "rc": rc3, "note": reason}


def _pull_data_via_root(adb: str, serial: str, ev: Path, progress, cid: str) -> dict:
    """
    FILE-SYSTEM akvizicija (spec §14–15): sa POTVRĐENIM root-om prikupi /data
    poddrveta preko `adb exec-out su -c 'tar -c -C / …'` (sirov binarni stream),
    pa raspakuj u Evidence u Android-FS rasporedu. Read-only na uređaju
    (tar samo čita; ništa se ne piše na telefon). Vraća {ok, bytes, extracted, tar_sha256, note}.
    """
    progress.update(58, "File-system akvizicija: /data preko root-a (tar)…")
    progress.log("adb exec-out su -c 'tar -c -C / " + " ".join(_FS_DATA_SUBTREES) +
                 "' (root, read-only na uređaju)")
    tar_path = ev / "Metadata" / "_filesystem_data.tar"
    try:
        tar_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    subtrees = " ".join(_FS_DATA_SUBTREES)
    cmd = _adb_cmd(adb, serial, "exec-out", "su", "-c",
                   f"tar -c -C / {subtrees} 2>/dev/null")

    def _on_bytes(n):
        mb = n // 1048576
        progress.update(min(74, 58 + int(mb / 400 * 16)),
                        f"File-system: preuzeto {mb} MB /data…")

    rc, nbytes = detect.run_to_file(cmd, str(tar_path), progress=progress,
                                    timeout=3600, stall_timeout=180, on_bytes=_on_bytes)
    if rc == 130:
        try:
            tar_path.unlink()
        except Exception:
            pass
        return {"ok": False, "rc": 130, "note": "otkazano", "bytes": nbytes}
    if rc != 0 or nbytes < 512:
        note = {124: "vremenski limit", 125: "zastoj (nema napretka)"}.get(rc, f"rc={rc}")
        progress.log(f"File-system tar nije uspeo ({note}, {nbytes} B) — moguće da su "
                     f"prava/root nedovoljni. Prelaz na logical nije automatski (spec §14).")
        try:
            tar_path.unlink()
        except Exception:
            pass
        return {"ok": False, "rc": rc, "note": note, "bytes": nbytes}

    tar_hashes = base.compute_hashes(tar_path)   # provenance heš sirovog tar-a
    progress.update(75, "Raspakivanje /data (tar) u Evidence…")
    extracted = 0
    try:
        import tarfile
        with tarfile.open(str(tar_path)) as tf:
            for m in tf.getmembers():
                try:
                    tf.extract(m, path=str(ev), filter="data")  # bezbedno (bez path traversal)
                    if m.isfile():
                        extracted += 1
                except Exception:
                    continue
    except Exception as e:
        progress.log(f"Raspakivanje tar-a delimično/neuspešno: {e}")

    try:
        tar_path.unlink()   # sirovi tar može biti GB; heš je zabeležen (provenance)
    except Exception:
        pass

    cases_fs.append_log(cid, f"File-system (root): /data → {extracted} fajlova raspakovano "
                             f"({nbytes // 1048576} MB tar, SHA-256 {(tar_hashes or {}).get('sha256','?')[:16]}…).")
    progress.log(f"File-system akvizicija: raspakovano {extracted} fajlova iz /data.")
    return {"ok": True, "rc": 0, "bytes": nbytes, "extracted": extracted,
            "tar_sha256": (tar_hashes or {}).get("sha256"), "note": "OK"}


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
                  device_info: dict = None, method: str = "logical") -> dict:
    """
    Target funkcija za jobs.start_job. Akvizicija USB Android telefona preko adb.
    `method`: logical | file_system | physical | auto (spec §10,§40).
      • Uvek se rade logički koraci (build.prop, /sdcard, lista paketa).
      • FILE_SYSTEM dodatno prikuplja /data preko root-a (ako je root potvrđen).
      • PHYSICAL / nedostupna ručno izabrana metoda → PREKID sa razlogom
        (NIKAD tihi downgrade — spec §40,§46).
    Vraća dict po ugovoru drajvera:
    {case_id, source, evidence_path, case_path, stats, device, report_data, cancelled}.
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
    fs_result = None

    # ── 2b. Sposobnosti + izbor metode (spec §6–10, §40, §46) ────────────
    progress.update(8, "Detekcija sposobnosti uređaja (capabilities)…")
    caps_info = capabilities.detect_capabilities(serial)
    caps = caps_info.get("capabilities", {})
    try:
        effective_method, method_note = capabilities.resolve_method(method, caps)
    except RuntimeError as e:
        # Ručno izabrana metoda je nedostupna → jasno prekini (bez tihog downgrade-a).
        cases_fs.append_log(cid, f"Akvizicija prekinuta: {e}")
        cases_fs.update_case_meta(cid, status="failed")
        raise
    progress.log(f"Metoda akvizicije: {effective_method.upper()} — {method_note}")
    cases_fs.append_log(
        cid, f"Sposobnosti: logical={caps.get('logical_available')}, "
             f"filesystem={caps.get('filesystem_available')} "
             f"(root={caps.get('root_available')}), physical={caps.get('physical_available')}. "
             f"Izabrana metoda: {effective_method}.")

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
                       progress, cancelled=True, method=effective_method,
                       capabilities_dict=caps, fs_result=fs_result)

    # ── 4. Korisničko skladište (/sdcard) ────────────────────────────────
    pull = _pull_sdcard(adb, serial, ev, progress)
    if not pull["ok"]:
        notes.append("Preuzimanje korisničkog skladišta (/sdcard) nije u "
                     "potpunosti uspelo: " + str(pull.get("note")))
    cases_fs.append_log(cid, f"Preuzimanje /sdcard → data/media/0 "
                             f"(uspeh: {pull['ok']}). {pull.get('note') or ''}".strip())

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, 0, notes,
                       progress, cancelled=True, method=effective_method,
                       capabilities_dict=caps, fs_result=fs_result)

    # ── 5. Instalirane aplikacije ────────────────────────────────────────
    packages_count = _pull_packages(adb, serial, ev, progress)
    cases_fs.append_log(cid, f"Instaliranih paketa: {packages_count} "
                             f"(→ data/system/packages.list).")

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, packages_count, notes,
                       progress, cancelled=True, method=effective_method,
                       capabilities_dict=caps, fs_result=fs_result)

    # ── 5b. FILE-SYSTEM akvizicija /data (samo ako je metoda FILE_SYSTEM) ─
    if effective_method == capabilities.AcquisitionMethod.FILE_SYSTEM:
        fs_result = _pull_data_via_root(adb, serial, ev, progress, cid)
        if not (fs_result and fs_result.get("ok")):
            notes.append("File-system akvizicija /data nije uspela ("
                         + str((fs_result or {}).get("note")) + "). Prikupljeni su "
                         "logički podaci (/sdcard, svojstva, paketi); /data nije obuhvaćen.")

    # ── 6. Pošteno beleženje obima i ograničenja (spec §13,§46) ──────────
    if effective_method == capabilities.AcquisitionMethod.FILE_SYSTEM and fs_result and fs_result.get("ok"):
        note = (f"Metoda: FILE-SYSTEM (root). Pored /sdcard prikupljeni su i aplikacioni "
                f"privatni podaci: /data/data, /data/system, /data/misc, /data/user "
                f"({fs_result.get('extracted', 0)} fajlova iz /data).")
    else:
        note = ("Metoda: LOGICAL. Aplikacioni privatni podaci (/data/data/<paket>) NISU "
                "prikupljeni — nedostupni su bez root-a. Prikupljeno: /sdcard, svojstva "
                "uređaja, lista paketa. Baze SMS-a/poziva/aplikacija iz /data nisu obuhvaćene.")
    notes.append(note)
    notes.append("IMEI (modem/EFS particija), fizička particija i nealocirani/izbrisani "
                 "prostor nisu dostupni ovom akvizicijom (fizička metoda nije podržana "
                 "bez namenskog backend-a — spec §16).")
    progress.log(note)
    cases_fs.append_log(cid, note)

    if progress.cancelled():
        return _finish(cid, ev, case, device, None, False, packages_count, notes,
                       progress, cancelled=True, method=effective_method,
                       capabilities_dict=caps, fs_result=fs_result)

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
                   summary=summary, method=effective_method,
                   capabilities_dict=caps, fs_result=fs_result)


def _finish(cid, ev, case, device, manifest, capped, packages_count, notes,
            progress, cancelled=False, summary=None, method="logical",
            capabilities_dict=None, fs_result=None):
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
        acquisition_method=method,
        hashes={"manifest_files": summary["file_count"],
                "total_bytes": summary["total_bytes"],
                "total_size_human": summary["total_size_human"]},
    )

    if cancelled:
        progress.log("Akvizicija telefona otkazana — sačuvano je ono što je do "
                     "tada prikupljeno (uz manifest).")
    else:
        progress.update(100, "Akvizicija telefona završena.")

    if isinstance(device, dict):
        device = {**device, "acquisition_method": method}

    report_data = {
        "kind": "mobile",
        "case_id": cid,
        "device": device,
        "acquisition_method": method,
        "capabilities": capabilities_dict or {},
        "filesystem_result": fs_result,
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
