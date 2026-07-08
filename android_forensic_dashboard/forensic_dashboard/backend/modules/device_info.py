"""
modules/device_info.py
──────────────────────
Identifikacija uređaja i korisnika:
  - build.prop → model, Android verzija, build number
  - settings.db → vlasnik uređaja
  - shared_prefs (GMS, Google Account) → JWT token, email, ime
  - packages.xml → broj instaliranih paketa, datum instalacije
"""

import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from utils.dump_resolver import DumpResolver
from utils.helpers import (
    artifact, finding, module_result, not_found_result,
    try_decode_jwt, sha256_file,
)
from utils.db_reader import SafeDBReader


# ─── BUILD.PROP PARSER ────────────────────────────────────────────────────

def _parse_build_prop(path: Path) -> dict:
    props = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    props[key.strip()] = value.strip()
    except Exception:
        pass
    return props


def _merge_all_build_props(resolver: DumpResolver) -> dict:
    """
    Moderni Android (8+) deli build.prop na više particija:
    /system, /vendor, /odm, /product, /system_ext. Ključne vrednosti
    (proizvođač, model) često NISU u /system/build.prop nego u vendor/odm
    verziji, pod prefiksiranim ključevima (ro.product.vendor.model...).
    Zato spajamo SVE build.prop fajlove pronađene bilo gde u dump-u.
    Radi generički za bilo koji uređaj/OEM.
    """
    merged = {}
    for bp in resolver.find_files_by_regex(r"^build\.prop$"):
        for k, v in _parse_build_prop(bp).items():
            # ne gazi već postojeću ne-praznu vrednost praznom
            if k not in merged or (not merged[k] and v):
                merged[k] = v
    return merged


def _first_prop(props: dict, keys: list, default: str = "") -> str:
    """Vrati prvu ne-praznu vrednost za bilo koji od datih ključeva."""
    for k in keys:
        v = props.get(k)
        if v:
            return v
    return default


# Kandidat-ključevi za svaki podatak — pokrivaju sve particije (system,
# vendor, odm, product, system_ext) i sve OEM-ove (Samsung, Xiaomi, ...).
_MANUFACTURER_KEYS = [
    "ro.product.manufacturer", "ro.product.system.manufacturer",
    "ro.product.vendor.manufacturer", "ro.product.odm.manufacturer",
    "ro.product.product.manufacturer", "ro.product.system_ext.manufacturer",
]
_MODEL_KEYS = [
    "ro.product.model", "ro.product.system.model", "ro.product.vendor.model",
    "ro.product.odm.model", "ro.product.product.model", "ro.product.system_ext.model",
]
_DEVICE_KEYS = [
    "ro.product.device", "ro.product.system.device", "ro.product.vendor.device",
    "ro.product.odm.device", "ro.boot.hardware", "ro.hardware",
]
_BRAND_KEYS = [
    "ro.product.brand", "ro.product.system.brand", "ro.product.vendor.brand",
]
_CHIPSET_KEYS = [
    "ro.board.platform", "ro.soc.model", "ro.chipname", "ro.hardware.chipname",
    "ro.hardware",
]


# ─── JWT HUNT ─────────────────────────────────────────────────────────────

def _find_jwt_in_prefs(prefs_dir: Path) -> Optional[dict]:
    """
    Pretražuje sve XML shared_prefs fajlove u potrazi za JWT tokenima.
    Vraća dekodirani payload prvog pronađenog tokena.
    """
    if not prefs_dir or not prefs_dir.exists():
        return None

    jwt_re = re.compile(r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}')

    for xml_file in prefs_dir.rglob("*.xml"):
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")
            matches = jwt_re.findall(content)
            for token in matches:
                payload = try_decode_jwt(token)
                if payload and ("email" in payload or "sub" in payload):
                    return {
                        "token": token[:40] + "...",
                        "payload": payload,
                        "source_file": xml_file.name,
                    }
        except Exception:
            continue
    return None


def _find_google_account(resolver: DumpResolver) -> Optional[str]:
    """
    Pokušava da pronađe Google nalog iz više izvora:
    1. accounts.db u GMS
    2. shared_prefs XML fajlovi
    3. Direktno iz settings.db
    """
    # Pokušaj 1: accounts.db
    accounts_db = resolver.resolve_path(
        "data/data/com.google.android.gms/databases/accounts.db"
    )
    if accounts_db and accounts_db.exists():
        try:
            with SafeDBReader(accounts_db) as db:
                rows = db.query(
                    "SELECT name FROM accounts WHERE type='com.google' LIMIT 1"
                )
                if rows:
                    return rows[0].get("name")
        except Exception:
            pass

    # Pokušaj 2: GMS shared_prefs
    gms_prefs = resolver.resolve_path(
        "data/data/com.google.android.gms/shared_prefs"
    )
    if gms_prefs and gms_prefs.exists():
        email_re = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
        for xml_file in gms_prefs.glob("*.xml"):
            try:
                content = xml_file.read_text(encoding="utf-8", errors="replace")
                emails = email_re.findall(content)
                google_emails = [e for e in emails if "gmail.com" in e or "google" in e]
                if google_emails:
                    return google_emails[0]
            except Exception:
                continue

    return None


# Putanje codePath koje označavaju sistemske/predinstalirane pakete —
# ovi paketi nemaju "installer" (nisu instalirani preko Play Store-a) ali
# to je normalno za firmware, ne ukazuje na sideloading.
SYSTEM_CODE_PATH_PREFIXES = ("/system/", "/product/", "/vendor/", "/apex/", "/system_ext/")


def _parse_packages_xml(path: Path) -> dict:
    """Parsira packages.xml za listu instaliranih aplikacija."""
    packages = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for pkg in root.findall(".//package"):
            name = pkg.get("name", "")
            code_path = pkg.get("codePath", "")
            installer = pkg.get("installer", "")
            first_install = pkg.get("ft", "0")
            packages.append({
                "name": name,
                "code_path": code_path,
                "installer": installer,
                "first_install_ms": int(first_install, 16) if first_install else 0,
            })
    except Exception:
        pass

    # "Sideloaded" = nema installer ZAPISAN *i* nije sistemski/firmware paket
    # (sistemski paketi normalno nemaju installer, pa ih ne tretiramo kao sumnjive)
    sideloaded = [
        p for p in packages
        if not p["installer"] and not p["code_path"].startswith(SYSTEM_CODE_PATH_PREFIXES)
    ]

    return {
        "total": len(packages),
        "sideloaded": sideloaded,
        "all": packages,
    }


# ─── ROBUSTNA IDENTIFIKACIJA UREĐAJA (VIŠE IZVORA) ────────────────────────

# Generička mapa model-kod → marketinško ime za najčešće uređaje. NIJE nužna
# za rad (model-kod je dovoljan), ali daje čitljiviji prikaz. Lako proširiva.
_MODEL_MARKETING = {
    "SM-G973": "Galaxy S10", "SM-G975": "Galaxy S10+", "SM-G970": "Galaxy S10e",
    "SM-G991": "Galaxy S21", "SM-G998": "Galaxy S21 Ultra", "SM-G981": "Galaxy S20",
    "SM-N975": "Galaxy Note10+", "SM-N970": "Galaxy Note10", "SM-A515": "Galaxy A51",
    "SM-G950": "Galaxy S8", "SM-G960": "Galaxy S9", "SM-G965": "Galaxy S9+",
    "Pixel 3": "Pixel 3", "Pixel 4": "Pixel 4", "Pixel 5": "Pixel 5",
    "Pixel 6": "Pixel 6", "Pixel 7": "Pixel 7", "Pixel 8": "Pixel 8",
}


def _parse_fingerprint(fp: str) -> dict:
    """
    ro.build.fingerprint format:
      brand/product/device:release/id/incremental:type/tags
    npr: samsung/beyond1ltexx/beyond1:10/QP1A.190711.020/G973FXXS9DTK9:user/release-keys
    Iz njega izvlačimo brend, device i build_id (koji sadrži model-kod).
    """
    out = {}
    if not fp or "/" not in fp:
        return out
    try:
        brand_part, rest = fp.split("/", 1)
        out["brand"] = brand_part
        # device je pre prvog ':'
        if "/" in rest:
            product, rest2 = rest.split("/", 1)
            out["product"] = product
            device = rest2.split(":", 1)[0]
            out["device"] = device
        # build_id: token posle release-a (…:10/BUILD_ID/…)
        segments = fp.replace(":", "/").split("/")
        for seg in segments:
            # model-kod tipa G973F, N975F, A515F (slovo+3-4 cifre+slovo)
            m = re.search(r"\b([A-Z]{1,2}\d{3,4}[A-Z]{0,2})\b", seg)
            if m and "build_model" not in out:
                out["build_model"] = m.group(1)
    except Exception:
        pass
    return out


def _model_from_build_id(build_id: str) -> str:
    """Izvuci model-kod iz build display id (npr. 'G973FXXS9DTK9' → 'G973F')."""
    if not build_id:
        return ""
    m = re.match(r"([A-Z]{1,2}\d{3,4}[A-Z]{0,2})", build_id)
    return m.group(1) if m else ""


def _marketing_name(model: str) -> str:
    """Vrati marketinško ime za dati model-kod ako je poznato."""
    if not model:
        return ""
    norm = model.replace("SM-", "SM-")  # zadrži kako jeste
    for prefix, name in _MODEL_MARKETING.items():
        if norm.startswith(prefix) or norm.replace("SM-", "").startswith(prefix.replace("SM-", "")):
            return name
    return ""


def _exif_device_fallback(resolver: DumpResolver) -> str:
    """
    Poslednja linija odbrane: ako build.prop ne da model, pročitaj Make/Model
    iz EXIF-a prve fotografije u DCIM-u (uređaj koji je snimio fotografije je
    najverovatnije sam analizirani uređaj). Radi bez ostalih modula.
    """
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return ""
    tag_make = next((k for k, v in ExifTags.TAGS.items() if v == "Make"), None)
    tag_model = next((k for k, v in ExifTags.TAGS.items() if v == "Model"), None)
    for rel in ("data/media/0/DCIM", "data/media/0/DCIM/Camera"):
        d = resolver.root / rel
        if not d.exists():
            continue
        for img in list(d.rglob("*.jpg"))[:30]:
            try:
                with Image.open(img) as im:
                    ex = im._getexif() or {}
                make = str(ex.get(tag_make, "")).strip()
                model = str(ex.get(tag_model, "")).strip()
                if make or model:
                    return f"{make} {model}".strip()
            except Exception:
                continue
    return ""


def _identify_device(resolver: DumpResolver, props: dict) -> dict:
    """
    Višeslojna identifikacija uređaja — pokušava redom sve izvore dok ne dobije
    proizvođača i model. Radi generički za bilo koji Android uređaj/verziju/OEM.
    Prioritet: build.prop ključevi (sve particije) → fingerprint → build_id →
    EXIF fotografija. Vraća dict sa manufacturer/model/device/chipset/source.
    """
    fp = _first_prop(props, ["ro.build.fingerprint", "ro.system.build.fingerprint",
                             "ro.vendor.build.fingerprint", "ro.bootimage.build.fingerprint"], "")
    fp_data = _parse_fingerprint(fp)

    manufacturer = _first_prop(props, _MANUFACTURER_KEYS, "")
    model        = _first_prop(props, _MODEL_KEYS, "")
    device       = _first_prop(props, _DEVICE_KEYS, "") or fp_data.get("device", "")
    brand        = _first_prop(props, _BRAND_KEYS, "") or fp_data.get("brand", "")
    chipset      = _first_prop(props, _CHIPSET_KEYS, "")
    build_id     = _first_prop(props, ["ro.build.display.id", "ro.build.id"], "")

    source = "build.prop"

    # Proizvođač: props → brend → fingerprint brend
    if not manufacturer:
        manufacturer = brand or fp_data.get("brand", "")
        if manufacturer:
            source = "fingerprint/brand"

    # Model: props → build_id → fingerprint model
    if not model:
        model = _model_from_build_id(build_id) or fp_data.get("build_model", "")
        if model:
            model = f"SM-{model}" if (manufacturer.lower().startswith("samsung") and not model.startswith("SM-")) else model
            source = "build_id/fingerprint"

    # EXIF fallback ako i dalje nema ni proizvođača ni modela
    if not manufacturer and not model:
        exif_dev = _exif_device_fallback(resolver)
        if exif_dev:
            parts = exif_dev.split(" ", 1)
            manufacturer = parts[0]
            model = parts[1] if len(parts) > 1 else ""
            source = "EXIF fotografije"

    # Lepši prikaz
    if manufacturer and manufacturer.islower():
        manufacturer = manufacturer.capitalize()
    marketing = _marketing_name(model)
    model_display = f"{model} ({marketing})" if marketing else model

    return {
        "manufacturer": manufacturer or "Nepoznat",
        "model": model or "Nepoznat",
        "model_display": model_display or "Nepoznat",
        "device": device,
        "chipset": chipset,
        "build_id": build_id or "Nepoznat",
        "fingerprint": fp,
        "source": source,
    }


# ─── MAIN ANALYZE FUNCTION ────────────────────────────────────────────────

def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)
    findings = []
    artifacts_list = []
    alerts = []

    # ── 1. build.prop (spoji sve particije, generički za bilo koji OEM) ───
    build_prop_path = resolver.resolve("build_prop") or (
        resolver.find_files_by_regex(r"^build\.prop$") or [None]
    )[0]
    props = _merge_all_build_props(resolver)
    if not props and build_prop_path:
        props = _parse_build_prop(build_prop_path)

    # Višeslojna identifikacija (build.prop svih particija → fingerprint →
    # build_id → EXIF fotografije). Ne vraća "Nepoznat" ako ijedan izvor postoji.
    dev = _identify_device(resolver, props)
    manufacturer = dev["manufacturer"]
    model        = dev["model"]
    device       = dev["device"]
    chipset      = dev["chipset"]
    build_id     = dev["build_id"]
    fingerprint  = dev["fingerprint"]
    android_ver  = _first_prop(props, ["ro.build.version.release", "ro.build.version.release_or_codename"], "Nepoznat")
    sdk          = props.get("ro.build.version.sdk", "?")
    security_patch = props.get("ro.build.version.security_patch", "Nepoznat")

    findings += [
        finding("Proizvođač", manufacturer),
        finding("Model", dev["model_display"]),
        finding("Android verzija", f"{android_ver} (SDK {sdk})" if android_ver != "Nepoznat" else "Nepoznat"),
        finding("Build ID", build_id),
        finding("Bezbednosna zakrpa", security_patch),
        finding("Identifikovano iz", dev["source"]),
    ]
    if chipset:
        findings.append(finding("Čipset", chipset))
    if fingerprint:
        findings.append(finding("Fingerprint", fingerprint[:70] + "..." if len(fingerprint) > 70 else fingerprint))

    if manufacturer != "Nepoznat" or model != "Nepoznat":
        device_str = f"{manufacturer} {model}".strip()
        artifacts_list.append(artifact(
            "account", f"Uređaj: {device_str}, Android {android_ver}",
            build_prop_path.name if hasattr(build_prop_path, "name") else "build.prop",
            extra={"manufacturer": manufacturer, "model": model, "device": device,
                   "chipset": chipset, "android": android_ver, "identify_source": dev["source"]},
        ))
    else:
        alerts.append(
            "Podaci o uređaju (proizvođač/model) nisu pronađeni ni u jednom izvoru "
            "(build.prop, fingerprint, EXIF) — moguće nepotpun dump."
        )

    # ── 2. Google nalog ───────────────────────────────────────────────────
    google_email = _find_google_account(resolver)
    if google_email:
        findings.append(finding("Google nalog", google_email))
        artifacts_list.append(artifact(
            "account", f"Google nalog: {google_email}",
            "GMS databases/shared_prefs",
            extra={"email": google_email},
        ))

    # ── 3. JWT token hunt ─────────────────────────────────────────────────
    # Traži po svim shared_prefs u data/data (ili alternativnim data root-ovima)
    jwt_result = None
    for data_root in ("data/data", "data/user/0", "data/user_de/0"):
        data_dir = resolver.root / data_root
        if data_dir.exists():
            jwt_result = _find_jwt_in_prefs(data_dir)
            if jwt_result:
                break

    if jwt_result:
        payload = jwt_result["payload"]
        email_from_jwt = payload.get("email", payload.get("sub", "N/A"))
        name_from_jwt  = payload.get("name", payload.get("display_name", "N/A"))
        findings += [
            finding("JWT email", email_from_jwt),
            finding("JWT ime", name_from_jwt),
            finding("JWT izvor", jwt_result["source_file"]),
        ]
        artifacts_list.append(artifact(
            "account",
            f"JWT token → email: {email_from_jwt}, ime: {name_from_jwt}",
            jwt_result["source_file"],
            extra={"jwt_email": email_from_jwt, "jwt_name": name_from_jwt},
        ))
        if not google_email and email_from_jwt != "N/A":
            alerts.append(f"Identitet iz JWT tokena: {email_from_jwt} ({name_from_jwt})")

    # ── 4. WiFi MAC adresa (iz build.prop ili wifi config) ────────────────
    wifi_mac = props.get("ro.boot.wifimacaddr", props.get("wifi.interface", ""))
    if wifi_mac:
        findings.append(finding("WiFi MAC (build.prop)", wifi_mac))
        if wifi_mac.startswith(("02:", "da:", "5e:", "be:", "aa:")):
            alerts.append(f"Randomizovana MAC adresa detektovana: {wifi_mac}")

    # ── 5. packages.xml ───────────────────────────────────────────────────
    pkg_xml = resolver.resolve("packages_xml")
    if pkg_xml:
        pkg_data = _parse_packages_xml(pkg_xml)
        findings.append(finding("Instalirane aplikacije", str(pkg_data["total"])))
        findings.append(finding("Side-loaded (bez installer-a)", str(len(pkg_data["sideloaded"]))))

        sideloaded_names = [p["name"] for p in pkg_data["sideloaded"] if p["name"]]
        for pkg_name in sideloaded_names:
            artifacts_list.append(artifact(
                "app",
                f"Side-loaded: {pkg_name}",
                "packages.xml",
                extra={"package": pkg_name, "sideloaded": True},
            ))

        if sideloaded_names:
            preview = ", ".join(sideloaded_names[:10])
            if len(sideloaded_names) > 10:
                preview += f", ... (+{len(sideloaded_names) - 10})"
            alerts.append(
                f"{len(sideloaded_names)} paket(a) instalirano bez Play Store installer-a "
                f"(potencijalno sideloaded): {preview}"
            )

    # ── 6. SHA-256 dump integriteta ───────────────────────────────────────
    try:
        root_path = resolver.root
        # Hash prvog pronađenog artefakta kao referenca
        if build_prop_path:
            h = sha256_file(build_prop_path)
            findings.append(finding("SHA-256 (build.prop)", h[:32] + "..."))
    except Exception:
        pass

    # ── Rezime ────────────────────────────────────────────────────────────
    if not build_prop_path:
        alerts.append("build.prop nije pronađen – moguće nepotpun dump")

    return module_result(
        status="completed" if findings else "not_found",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
