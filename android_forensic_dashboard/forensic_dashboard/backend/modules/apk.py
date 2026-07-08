"""
modules/apk.py
───────────────
Statička analiza APK fajlova pronađenih u dump-u (data/app, sdcard/Download...):
  - Manifest: package name, verzija, dozvole (preko androguard-a ako je dostupan)
  - Detekcija opasnih kombinacija dozvola (SMS + INTERNET, CALL_LOG + INTERNET...)
  - Lagana DEX statička analiza: pretraga čitljivih stringova u classes.dex
    za sumnjive klase/API pozive (Cipher, SmsManager, wallet, itd.) — radi
    BEZ androguard-a, čistim zipfile + regex pristupom.
  - Poređenje sa očekivanim potpisom poznatih open-source aplikacija
    (npr. OmniNotes) radi detekcije trojanizovanih/modifikovanih verzija.
"""

import re
import zipfile
from pathlib import Path
from collections import defaultdict

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result, sha256_file

MAX_APKS = 25

# Dozvole koje, kombinovane, ukazuju na mogućnost presretanja/eksfiltracije
DANGEROUS_PERMISSION_GROUPS = {
    "SMS presretanje/slanje": {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"},
    "Pristup pozivima": {"android.permission.READ_CALL_LOG", "android.permission.PROCESS_OUTGOING_CALLS"},
    "Praćenje lokacije": {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"},
    "Snimanje audio/video": {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"},
}
NETWORK_PERMISSION = "android.permission.INTERNET"

# Sumnjivi DEX string pattern-i grupisani po kategoriji
DEX_KEYWORD_GROUPS = {
    "Kriptografske operacije": [b"javax/crypto/Cipher", b"AES", b"SecretKeySpec", b"Cipher.getInstance"],
    "SMS API": [b"SmsManager", b"sendTextMessage", b"sendMultipartTextMessage", b"content://sms"],
    "Kriptovalute / wallet": [b"bitcoin:", b"ethereum:", b"wallet", b"BreadWallet", b"BIP39", b"mnemonic", b"privateKey"],
    "Dinamičko učitavanje koda": [b"DexClassLoader", b"loadClass", b"dlopen"],
    "Mrežna komunikacija": [b"HttpURLConnection", b"okhttp3", b"Socket"],
}

# Poznati legitimni paketi i njihove "očekivane" karakteristike — za detekciju trojanizacije
KNOWN_PACKAGES = {
    "it.feio.android.omninotes": {
        "display_name": "OmniNotes (open-source notes app)",
        "unexpected_categories": ["SMS API", "Kriptografske operacije"],
    },
    "com.breadwallet": {
        "display_name": "BRD Wallet",
        "unexpected_categories": [],
    },
}


def _printable_strings(data: bytes, min_len: int = 5) -> set[bytes]:
    """Izvuci sve ASCII printable substringove iz binarnih podataka (DEX)."""
    return set(re.findall(rb"[ -~]{%d,}" % min_len, data))


def _scan_dex_strings(apk_zip: zipfile.ZipFile) -> dict[str, list[str]]:
    """
    Skenira sve classes*.dex fajlove unutar APK-a za sumnjive keyword grupe.
    Vraća mapu kategorija → lista pronađenih konkretnih stringova (do 5 po kategoriji).
    """
    findings_by_category: dict[str, set[bytes]] = defaultdict(set)

    dex_names = [n for n in apk_zip.namelist() if re.match(r"classes\d*\.dex$", n)]
    for dex_name in dex_names:
        try:
            data = apk_zip.read(dex_name)
        except Exception:
            continue

        for category, keywords in DEX_KEYWORD_GROUPS.items():
            for kw in keywords:
                if kw in data:
                    findings_by_category[category].add(kw)

    return {cat: sorted(s.decode("utf-8", "replace") for s in strs) for cat, strs in findings_by_category.items()}


def _try_androguard_manifest(apk_path: Path) -> dict | None:
    """Pokušaj parsiranja manifest-a preko androguard-a. Vraća None ako nije dostupan."""
    try:
        from androguard.core.bytecodes.apk import APK
    except ImportError:
        return None

    try:
        a = APK(str(apk_path))
        return {
            "package": a.get_package(),
            "version_name": a.get_androidversion_name(),
            "version_code": a.get_androidversion_code(),
            "permissions": list(a.get_permissions()),
            "main_activity": a.get_main_activity(),
            "app_name": a.get_app_name(),
        }
    except Exception:
        return None


def _guess_package_from_path(apk_path: Path, resolver: DumpResolver) -> str:
    """Ako je APK u data/app/<package>-*/base.apk, izvuci ime paketa iz putanje."""
    try:
        rel = apk_path.relative_to(resolver.root / "data/app")
        first_part = rel.parts[0]
        return re.sub(r"-[A-Za-z0-9_]+$", "", first_part)  # ukloni hash suffix
    except Exception:
        return ""


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    apk_files = resolver.find_apks()

    if not apk_files:
        return module_result(
            status="not_found",
            findings=[finding("Status", "Nisu pronađeni APK fajlovi u data/app ili Download")],
            artifacts=[],
            alerts=[],
        )

    truncated = len(apk_files) > MAX_APKS
    apk_files = apk_files[:MAX_APKS]

    findings = [finding("Pronađeno APK fajlova", str(len(apk_files)) + (" (ograničeno)" if truncated else ""))]
    artifacts_list = []
    alerts = []

    used_androguard = False

    for apk_path in apk_files:
        rel_path = str(apk_path.relative_to(resolver.root)) if resolver.root in apk_path.parents else str(apk_path)
        size_kb = apk_path.stat().st_size // 1024

        manifest_info = _try_androguard_manifest(apk_path)
        package = ""
        version = ""
        permissions: list[str] = []

        if manifest_info:
            used_androguard = True
            package = manifest_info["package"]
            version = f"{manifest_info['version_name']} ({manifest_info['version_code']})"
            permissions = manifest_info["permissions"]
        else:
            package = _guess_package_from_path(apk_path, resolver)

        # ── DEX string sken (radi bez androguard-a) ─────────────────────────
        dex_categories = {}
        try:
            with zipfile.ZipFile(apk_path) as z:
                dex_categories = _scan_dex_strings(z)
        except Exception:
            pass

        # ── Dozvole: opasne kombinacije ─────────────────────────────────────
        perm_set = set(permissions)
        dangerous_groups_found = []
        for group_name, group_perms in DANGEROUS_PERMISSION_GROUPS.items():
            if group_perms & perm_set and NETWORK_PERMISSION in perm_set:
                dangerous_groups_found.append(group_name)

        # ── Glavni artefakt za APK ──────────────────────────────────────────
        label = package or apk_path.name
        value = f"APK: {label}"
        if version:
            value += f" v{version}"
        value += f" ({size_kb} KB)"

        artifacts_list.append(artifact(
            "app",
            value,
            rel_path,
            extra={
                "package": package,
                "permissions_count": len(permissions),
                "dangerous_groups": dangerous_groups_found,
                "dex_categories": list(dex_categories.keys()),
            },
        ))

        findings.append(finding(f"Paket: {label}", f"{size_kb} KB, SHA-256: {sha256_file(apk_path)[:16]}..."))

        if permissions:
            findings.append(finding(f"  Dozvole ({label})", str(len(permissions))))

        # Kombinacije osetljivih dozvola beležimo kao INFORMATIVNI nalaz, ne kao
        # upozorenje — npr. lokacija+internet je sasvim normalna za mape/vremensku
        # prognozu/prevoz i sama po sebi NIJE indikator kompromitacije. Ovim se
        # izbegavaju lažni pozitivi na legitimnim aplikacijama.
        if dangerous_groups_found:
            findings.append(finding(
                f"  Osetljive dozvole ({label})",
                ", ".join(dangerous_groups_found) + " + INTERNET",
            ))

        # UPOZORENJE samo za GENUINO anomalan obrazac (generički, bez oslanjanja
        # na naziv paketa): sposobnost slanja/presretanja SMS-a ZAJEDNO sa
        # kriptografskim operacijama u kodu = obrazac trojanizovane komunikacione
        # aplikacije (kao OmniNotes). Legitimne mape/vremenska prognoza/kupovina/
        # browser nemaju ovu kombinaciju, pa nema lažnih pozitiva.
        sms_perm = bool(DANGEROUS_PERMISSION_GROUPS["SMS presretanje/slanje"] & perm_set)
        sms_dex = "SMS API" in dex_categories
        crypto_dex = "Kriptografske operacije" in dex_categories
        if (sms_perm or sms_dex) and crypto_dex:
            alerts.append(
                f"APK '{label}' kombinuje SMS slanje/presretanje sa kriptografskim "
                f"operacijama u kodu — obrazac trojanizovane komunikacione aplikacije "
                f"(prikrivena šifrovana SMS komunikacija)."
            )
            artifacts_list.append(artifact(
                "app",
                f"⚠ Sumnjiv obrazac: {label} — SMS + kriptografija (moguća trojanizacija)",
                rel_path,
                extra={"package": package, "suspicious": True,
                       "signals": {"sms_perm": sms_perm, "sms_dex": sms_dex, "crypto_dex": crypto_dex}},
            ))

        for category, strings_found in dex_categories.items():
            findings.append(finding(f"  DEX kategorija ({label}): {category}", ", ".join(strings_found[:5])))
            artifacts_list.append(artifact(
                "app",
                f"DEX analiza '{label}': pronađena referenca na [{category}] — {', '.join(strings_found[:3])}",
                f"{rel_path}::classes.dex",
                extra={"package": package, "category": category, "strings": strings_found},
            ))

        # ── Poređenje sa poznatim paketima (detekcija trojanizacije) ────────
        known = KNOWN_PACKAGES.get(package)
        if known:
            unexpected = [c for c in known.get("unexpected_categories", []) if c in dex_categories]
            if unexpected:
                alerts.append(
                    f"KRITIČNO: '{known['display_name']}' ({package}) sadrži neočekivane DEX referense "
                    f"za {', '.join(unexpected)} — indikator MODIFIKOVANE/TROJANIZOVANE verzije "
                    f"legitimne open-source aplikacije."
                )
                artifacts_list.append(artifact(
                    "app",
                    f"⚠ Trojanizovana aplikacija: {known['display_name']} sadrži {', '.join(unexpected)}",
                    rel_path,
                    extra={"package": package, "trojanized": True, "categories": unexpected},
                ))

    if not used_androguard:
        alerts.append(
            "androguard nije dostupan — manifest (paket/verzija/dozvole) nije parsiran iz binarnog "
            "AndroidManifest.xml. DEX string analiza je i dalje izvršena. Instaliraj 'androguard' za potpunu analizu."
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
