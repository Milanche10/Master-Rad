"""
modules/crypto.py
───────────────────
Detekcija kriptovalutnih artefakata u dump-u:
  - QR kodovi u slikama (DCIM/Pictures/Download) → bitcoin:/ethereum: URI ili adrese
  - Regex pretraga BTC/ETH/LTC adresa kroz shared_prefs, baze i tekstualne fajlove
  - Detekcija instaliranih wallet aplikacija (BRD, MetaMask, Trust Wallet, Electrum...)

QR dekodiranje koristi OpenCV (cv2.QRCodeDetector) — ako opencv nije
instaliran, taj korak se preskače uz upozorenje, ali regex pretraga
i detekcija wallet aplikacija se i dalje izvršavaju.
"""

import re
from pathlib import Path

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result
from utils.crypto_validate import is_valid_btc, validate_eth, is_noise

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp"}
IMAGE_SEARCH_DIRS = [
    "data/media/0/DCIM",
    "data/media/0/Pictures",
    "data/media/0/Download",
]
MAX_IMAGES_FOR_QR = 300

TEXT_EXTENSIONS = {".xml", ".json", ".txt", ".db", ".sqlite"}
# data/data je obično symlink na data/user/0 — neki dump-ovi sadrže samo
# data/user/0 (i/ili data/user_de/0 za Device Encrypted storage)
TEXT_SEARCH_ROOTS = ["data/data", "data/user/0", "data/user_de/0"]
MAX_TEXT_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_TEXT_FILES = 2000

BTC_RE = re.compile(rb"\b(bc1[a-z0-9]{25,90}|[13][a-zA-Z0-9]{25,34})\b")
ETH_RE = re.compile(rb"\b0x[a-fA-F0-9]{40}\b")
CRYPTO_URI_RE = re.compile(rb"\b(bitcoin|ethereum|litecoin|bitcoincash|dogecoin):[A-Za-z0-9:/?=&.]+")

KNOWN_WALLET_PACKAGES = {
    "com.breadwallet": "BRD Wallet (Bitcoin/Ethereum)",
    "io.metamask": "MetaMask",
    "com.wallet.crypto.trustapp": "Trust Wallet",
    "org.electrum.electrum": "Electrum",
    "com.coinbase.android": "Coinbase",
    "com.binance.dev": "Binance",
    "piuk.blockchain.android": "Blockchain.com Wallet",
    "com.exodus.exodus": "Exodus",
}

# Stringovi koji izoluju "šum" lažnih pozitiva (testni/placeholder podaci)
NOISE_HINTS = (b"example", b"test", b"placeholder", b"0000000000000000000000000000000000000000")


def _is_valid_btc(addr: bytes) -> bool:
    """Gruba sanity provera dužine — puna Base58Check validacija nije neophodna za triage."""
    return 25 <= len(addr) <= 90


# Dijagnostika QR skenera (zašto QR nije radio) — vidi analyze()
_QR_STATUS = {"engine": None, "reason": ""}


def _scan_qr_codes(resolver: DumpResolver) -> list[dict]:
    results = []
    try:
        import cv2
        _QR_STATUS["engine"] = "opencv"
    except Exception as _e:
        _QR_STATUS["engine"] = None
        _QR_STATUS["reason"] = (
            f"opencv nedostupan ({type(_e).__name__}: {str(_e)[:60]}). "
            f"Popravka: pip install \"numpy<2\"  ili  pip install --upgrade opencv-python-headless."
        )
        return results

    detector = cv2.QRCodeDetector()

    image_files: list[Path] = []
    for rel_dir in IMAGE_SEARCH_DIRS:
        full_dir = resolver.root / rel_dir
        if full_dir.exists():
            for f in full_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in IMAGE_EXTENSIONS:
                    image_files.append(f)

    for img_path in image_files[:MAX_IMAGES_FOR_QR]:
        try:
            img = cv2.imread(str(img_path))
            if img is None:
                continue
            data, points, _ = detector.detectAndDecode(img)
        except Exception:
            continue

        if data:
            rel_path = str(img_path.relative_to(resolver.root)) if resolver.root in img_path.parents else str(img_path)
            results.append({"file": rel_path, "filename": img_path.name, "data": data})

    return results


def _classify_qr_content(data: str) -> tuple[str, str]:
    """Vraća (tip, normalizovana_vrednost) za sadržaj QR koda."""
    if data.startswith(("bitcoin:", "ethereum:", "litecoin:", "bitcoincash:", "dogecoin:")):
        scheme, _, rest = data.partition(":")
        address = rest.split("?")[0]
        return f"{scheme.upper()} URI", address
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", data):
        return "ETH adresa", data
    if re.fullmatch(r"(bc1[a-z0-9]{25,90}|[13][a-zA-Z0-9]{25,34})", data):
        return "BTC adresa", data
    return "generički QR", data


def _scan_text_for_addresses(resolver: DumpResolver) -> dict[str, set]:
    """Regex pretraga BTC/ETH adresa kroz shared_prefs, baze i tekstualne fajlove."""
    found_btc: set[bytes] = set()
    found_eth: set[bytes] = set()
    found_uris: set[bytes] = set()
    sources: dict[bytes, set] = {}

    files_scanned = 0
    for root_rel in TEXT_SEARCH_ROOTS:
        root_dir = resolver.root / root_rel
        if not root_dir.exists():
            continue
        for f in root_dir.rglob("*"):
            if files_scanned >= MAX_TEXT_FILES:
                break
            if not f.is_file() or f.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                if f.stat().st_size > MAX_TEXT_FILE_SIZE:
                    continue
                data = f.read_bytes()
            except Exception:
                continue

            files_scanned += 1

            for m in BTC_RE.finditer(data):
                addr = m.group(0)
                addr_str = addr.decode("ascii", "ignore")
                # PRAVA validacija (Base58Check/Bech32) — odbacuje hash vrednosti,
                # UUID-ove i slične stringove koji samo liče na adresu. Ovim se
                # eliminišu lažni pozitivi na izvoru (ranije se brojalo ~175 lažnih).
                if is_noise(addr_str) or not is_valid_btc(addr_str):
                    continue
                if any(h in data[max(0, m.start()-20):m.end()+20] for h in NOISE_HINTS):
                    continue
                found_btc.add(addr)
                sources.setdefault(addr, set()).add(str(f.relative_to(resolver.root)))

            for m in ETH_RE.finditer(data):
                addr = m.group(0)
                addr_str = addr.decode("ascii", "ignore")
                if not validate_eth(addr_str) or addr.lower() == b"0x" + b"0" * 40:
                    continue
                if any(h in data[max(0, m.start()-20):m.end()+20] for h in NOISE_HINTS):
                    continue
                found_eth.add(addr)
                sources.setdefault(addr, set()).add(str(f.relative_to(resolver.root)))

            for m in CRYPTO_URI_RE.finditer(data):
                found_uris.add(m.group(0))

    return {"btc": found_btc, "eth": found_eth, "uris": found_uris, "sources": sources}


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    # ── 1. Instalirani wallet-i ───────────────────────────────────────────
    installed = set(resolver.list_installed_packages())
    found_wallets = {pkg: name for pkg, name in KNOWN_WALLET_PACKAGES.items() if pkg in installed}

    findings.append(finding("Detektovane wallet aplikacije", str(len(found_wallets)) or "0"))
    for pkg, name in found_wallets.items():
        findings.append(finding(f"  Wallet app", f"{name} ({pkg})"))
        artifacts_list.append(artifact(
            "crypto",
            f"Instalirana wallet aplikacija: {name} ({pkg})",
            "data/data (installed packages)",
            extra={"package": pkg, "wallet": name},
        ))
        alerts.append(f"Detektovana kriptovalutna wallet aplikacija: {name} ({pkg})")

    # ── 2. QR kodovi ───────────────────────────────────────────────────────
    qr_results = _scan_qr_codes(resolver)
    crypto_qr = []
    for qr in qr_results:
        qr_type, value = _classify_qr_content(qr["data"])
        if qr_type != "generički QR":
            crypto_qr.append({**qr, "qr_type": qr_type, "value": value})

    if crypto_qr:
        findings.append(finding("QR kodovi sa kripto sadržajem", str(len(crypto_qr))))
        for qr in crypto_qr:
            artifacts_list.append(artifact(
                "crypto",
                f"QR kod [{qr['qr_type']}]: {qr['value']} (slika: {qr['filename']})",
                qr["file"],
                extra={"qr_type": qr["qr_type"], "address_or_uri": qr["value"], "filename": qr["filename"]},
            ))
        alerts.append(
            f"Pronađeno {len(crypto_qr)} QR kod(ova) sa kriptovalutnim sadržajem "
            f"(adrese/transfer URI) u korisničkim slikama."
        )
    elif qr_results:
        findings.append(finding("QR kodovi (generički, nekripto)", str(len(qr_results))))
    else:
        findings.append(finding("QR kodovi", "Nisu pronađeni"))

    # Dijagnostika QR skenera — ako je opencv slomljen, JASNO reci zašto + fix.
    # (Kripto adrese ovog slučaja su u QR kodovima na screenshot-ovima, pa bez
    #  opencv-a blockchain modul nema šta da verifikuje.)
    if _QR_STATUS["engine"] is None and _QR_STATUS["reason"]:
        findings.append(finding("QR skener (opencv)", _QR_STATUS["reason"]))
        alerts.append(
            "QR skener nije radio (" + _QR_STATUS["reason"].split(".")[0] + "). "
            "Kripto adrese u QR kodovima nisu očitane — zato blockchain modul "
            "nema adresa za verifikaciju. Popravi opencv/numpy pa ponovo pokreni."
        )

    # ── 3. Regex pretraga adresa ─────────────────────────────────────────
    text_results = _scan_text_for_addresses(resolver)
    btc_addrs = text_results["btc"]
    eth_addrs = text_results["eth"]
    sources = text_results["sources"]

    findings.append(finding("BTC adrese pronađene u fajlovima", str(len(btc_addrs))))
    findings.append(finding("ETH adrese pronađene u fajlovima", str(len(eth_addrs))))

    for addr in sorted(btc_addrs)[:15]:
        addr_str = addr.decode()
        src_files = sources.get(addr, set())
        artifacts_list.append(artifact(
            "crypto",
            f"BTC adresa: {addr_str}",
            ", ".join(sorted(src_files))[:120] or "data/data",
            extra={"address": addr_str, "chain": "BTC", "sources": sorted(src_files)},
        ))

    for addr in sorted(eth_addrs)[:15]:
        addr_str = addr.decode()
        src_files = sources.get(addr, set())
        artifacts_list.append(artifact(
            "crypto",
            f"ETH adresa: {addr_str}",
            ", ".join(sorted(src_files))[:120] or "data/data",
            extra={"address": addr_str, "chain": "ETH", "sources": sorted(src_files)},
        ))

    if btc_addrs or eth_addrs:
        alerts.append(
            f"Pronađeno {len(btc_addrs)} BTC i {len(eth_addrs)} ETH adresa u konfiguracionim/baznim "
            f"fajlovima aplikacija — moguć finansijski trag za korelaciju sa blockchain modulom."
        )

    if not (found_wallets or crypto_qr or btc_addrs or eth_addrs):
        return module_result(
            status="not_found",
            findings=findings + [finding("Status", "Nisu pronađeni kriptovalutni artefakti")],
            artifacts=[],
            alerts=[],
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
