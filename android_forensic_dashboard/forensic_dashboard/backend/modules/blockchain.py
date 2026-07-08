"""
modules/blockchain.py
────────────────────────
Verifikacija kriptovalutnih adresa pronađenih u dump-u:
  - Ponovo koristi regex/QR detekciju iz modules/crypto.py da skupi
    BTC/ETH adrese i URI-jeve
  - Strogi kandidat-regex (Base58 charset bez 0/O/I/l) + pre-filter koji
    odbacuje čiste hex stringove i čiste cifre (hash vrednosti, UUID-ovi)
  - Base58Check validacija legacy BTC adresa (matematička provera
    checksum-a, bez potrebe za eksternim bibliotekama)
  - Bech32/Bech32m validacija SegWit (bc1...) adresa po BIP-173 referenci
  - Format validacija ETH adresa (0x + 40 hex)
  - Opcionalna online provera balansa preko javnih block explorer API-ja
    (blockchain.info za BTC, blockscout za ETH). Ako nema interneta,
    modul to jasno naznači i nastavlja sa offline rezultatima —
    forenzička analiza ne zavisi od konekcije.
"""

import hashlib
import re

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result
from modules.crypto import _scan_text_for_addresses, _scan_qr_codes, _classify_qr_content

MAX_VERIFY_ONLINE = 5
HTTP_TIMEOUT = 4

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ── Strogi kandidat-regexi ────────────────────────────────────────────────
# Legacy BTC (P2PKH/P2SH): strogi Base58 charset — isključuje 0, O, I, l.
LEGACY_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
# SegWit (BIP-173): bc1 + bech32 charset. Prihvata se i cela-velika-slova
# varijanta (BC1...); mešana slova su po BIP-173 nevalidna.
BECH32_BTC_RE = re.compile(
    r"\b(?:bc1[qpzry9x8gf2tvdw0s3jln54khce6mua7l]{8,87}"
    r"|BC1[QPZRY9X8GF2TVDW0S3JLN54KHCE6MUA7L]{8,87})\b"
)
# Pre-filter: čisti hex (npr. MD5/SHA hash, UUID segment) nikad nije validna
# Base58/bech32 adresa vrednog razmatranja — odbaci pre validacije.
PURE_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # BIP-173 kanonski redosled (32 karaktera)
BECH32_CONST = 1            # BIP-173 (SegWit v0)
BECH32M_CONST = 0x2BC830A3  # BIP-350 (SegWit v1+, npr. Taproot)


def _is_noise_candidate(s: str) -> bool:
    """Pre-filter: čisti hex stringovi i čiste cifre su false-positives."""
    return bool(PURE_HEX_RE.fullmatch(s)) or s.isdigit()


def _base58_decode(s: str) -> bytes | None:
    try:
        if not s:
            return None
        num = 0
        for char in s:
            if char not in BASE58_ALPHABET:
                return None
            num = num * 58 + BASE58_ALPHABET.index(char)

        # Broj leading '1' karaktera = broj leading 0x00 bajtova
        n_leading_zeros = len(s) - len(s.lstrip("1"))

        full_bytes = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        return b"\x00" * n_leading_zeros + full_bytes
    except Exception:
        return None


def _validate_btc_base58check(address: str) -> bool:
    """
    Puna Base58Check validacija legacy (P2PKH/P2SH) adrese.

    Adresa se base58-dekodira u TAČNO 25 bajtova:
      [1 bajt version | 20 bajtova hash160 | 4 bajta checksum]
    Checksum = sha256(sha256(prvih 21 bajt))[:4].
    Leading '1' karakteri predstavljaju leading 0x00 bajtove (obrađeno
    u _base58_decode), pa dužina od 25 bajtova važi i za adrese tipa "1111...".
    """
    decoded = _base58_decode(address)
    if decoded is None or len(decoded) != 25:
        return False

    payload, checksum = decoded[:21], decoded[21:]
    hash1 = hashlib.sha256(payload).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2[:4] == checksum


def _bech32_polymod(values: list[int]) -> int:
    """BIP-173 referentni polymod nad 5-bitnim vrednostima."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    """BIP-173 ekspanzija human-readable dela za checksum."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _validate_bech32(address: str) -> bool:
    """
    Bech32/Bech32m checksum validacija po BIP-173/BIP-350 referenci.

    Prihvata hrp 'bc' (Bitcoin mainnet) sa bech32 konstantom (1, SegWit v0)
    ili bech32m konstantom (0x2BC830A3, SegWit v1+/Taproot).
    Mešana velika/mala slova su nevalidna; cela-velika forma je dozvoljena.
    """
    if address != address.lower() and address != address.upper():
        return False  # mixed case — nevalidno po BIP-173
    addr = address.lower()

    if len(addr) > 90 or any(not (33 <= ord(c) <= 126) for c in addr):
        return False

    sep = addr.rfind("1")
    if sep < 1 or sep + 7 > len(addr):
        return False

    hrp, data_part = addr[:sep], addr[sep + 1:]
    if hrp != "bc":
        return False

    try:
        data = [BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return False

    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    return const in (BECH32_CONST, BECH32M_CONST)


def _validate_eth_format(address: str) -> bool:
    """
    Format validacija ETH adrese: 0x + tačno 40 hex karaktera.

    OGRANIČENJE: puna EIP-55 mixed-case checksum verifikacija zahteva
    Keccak-256. Python stdlib NEMA Keccak-256 — hashlib.sha3_256 je
    standardizovani SHA-3 (drugačiji padding od originalnog Keccak-a
    koji Ethereum koristi), pa bi dao pogrešan checksum. Zato se EIP-55
    provera preskače i prihvata se svaka adresa ispravnog formata.
    """
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", address))


def _query_btc_balance(address: str) -> dict | None:
    try:
        import requests
        resp = requests.get(
            f"https://blockchain.info/rawaddr/{address}?limit=0",
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "balance_btc": data.get("final_balance", 0) / 1e8,
                "n_tx": data.get("n_tx", 0),
                "total_received_btc": data.get("total_received", 0) / 1e8,
            }
    except Exception:
        return None
    return None


def _query_eth_balance(address: str) -> dict | None:
    try:
        import requests
        resp = requests.get(
            "https://eth.blockscout.com/api",
            params={"module": "account", "action": "balance", "address": address},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "1":
                return {"balance_eth": int(data["result"]) / 1e18}
    except Exception:
        return None
    return None


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    # ── 1. Skupi adrese (regex + QR) ─────────────────────────────────────
    text_results = _scan_text_for_addresses(resolver)
    btc_candidates = {a.decode() for a in text_results["btc"]}
    eth_candidates = {a.decode() for a in text_results["eth"]}

    qr_results = _scan_qr_codes(resolver)
    for qr in qr_results:
        qr_type, value = _classify_qr_content(qr["data"])
        if qr_type == "BTC adresa":
            btc_candidates.add(value)
        elif qr_type == "ETH adresa":
            eth_candidates.add(value)
        elif qr_type.startswith("BITCOIN"):
            btc_candidates.add(value)
        elif qr_type.startswith("ETHEREUM"):
            eth_candidates.add(value)

    if not btc_candidates and not eth_candidates:
        from modules.crypto import _QR_STATUS
        reason = ("Nema validnih kripto adresa za verifikaciju. Napomena: adrese "
                  "u ovom slučaju su u QR kodovima na screenshot-ovima; ")
        if _QR_STATUS.get("engine") is None:
            reason += f"QR skener (opencv) nije radio — {_QR_STATUS.get('reason', 'nedostupan')} "
            reason += "Popravi to pa ponovo pokreni 'crypto' i 'blockchain'."
        else:
            reason += "QR skener je radio ali nije našao validne adrese; tekstualni kandidati su odbačeni kao nevalidni (hash vrednosti)."
        return module_result(
            status="not_found",
            findings=[finding("Status", reason)],
            artifacts=[],
            alerts=[],
        )

    # ── 2. Pre-filter + stroga validacija ────────────────────────────────
    # Pipeline za BTC kandidate:
    #   1) pre-filter (čisti hex / čiste cifre → odmah false-positive)
    #   2) strogi kandidat-regex (Base58 bez 0/O/I/l, odn. bech32 charset)
    #   3) kriptografska provera checksum-a (Base58Check ili Bech32/Bech32m)
    valid_legacy_btc: list[str] = []
    valid_bech32_btc: list[str] = []
    invalid_btc: list[str] = []

    for addr in sorted(btc_candidates):
        if _is_noise_candidate(addr):
            invalid_btc.append(addr)
        elif addr.lower().startswith("bc1"):
            if BECH32_BTC_RE.fullmatch(addr) and _validate_bech32(addr):
                valid_bech32_btc.append(addr)
            else:
                invalid_btc.append(addr)
        else:
            if LEGACY_BTC_RE.fullmatch(addr) and _validate_btc_base58check(addr):
                valid_legacy_btc.append(addr)
            else:
                invalid_btc.append(addr)

    valid_btc = valid_legacy_btc + valid_bech32_btc

    valid_eth: list[str] = []
    invalid_eth: list[str] = []
    for addr in sorted(eth_candidates):
        if not _is_noise_candidate(addr) and _validate_eth_format(addr):
            valid_eth.append(addr)
        else:
            invalid_eth.append(addr)

    findings += [
        finding("BTC adrese — validan checksum", str(len(valid_btc))),
        finding("BTC adrese — neispravan format/checksum", str(len(invalid_btc))),
        finding("Bech32 (SegWit) adrese — validne", str(len(valid_bech32_btc))),
        finding("ETH adrese — valid format", str(len(valid_eth))),
        finding("ETH adrese — neispravan format", str(len(invalid_eth))),
    ]

    # Nevalidni kandidati NE postaju artefakti niti pojedinačni alerti —
    # samo jedan zbirni alert sa brojem i do 3 primera.
    invalid_all = invalid_btc + invalid_eth
    if invalid_all:
        alerts.append(
            f"{len(invalid_all)} stringova koji liče na kripto adrese ne prolaze validaciju "
            f"(Base58Check/Bech32 checksum ili format) — verovatno false-positives "
            f"(hash vrednosti, UUID-ovi, delimični stringovi). "
            f"Primeri: {', '.join(invalid_all[:3])}..."
        )

    # ── 3. Online verifikacija (best-effort) ──────────────────────────────
    online_checked = 0
    online_available = True

    for addr in valid_btc[:MAX_VERIFY_ONLINE]:
        result = _query_btc_balance(addr)
        online_checked += 1
        if result is None:
            online_available = False
            artifacts_list.append(artifact(
                "crypto",
                f"BTC {addr} — validan checksum, online verifikacija nedostupna (offline)",
                "blockchain.info",
                extra={"address": addr, "chain": "BTC", "valid": True, "online": False},
            ))
        else:
            artifacts_list.append(artifact(
                "crypto",
                f"BTC {addr} — balans: {result['balance_btc']:.8f} BTC, "
                f"{result['n_tx']} transakcija, ukupno primljeno {result['total_received_btc']:.8f} BTC",
                "blockchain.info (live)",
                extra={"address": addr, "chain": "BTC", "valid": True, "online": True, **result},
            ))
            if result["n_tx"] > 0:
                alerts.append(
                    f"BTC adresa {addr} ima {result['n_tx']} potvrđenih transakcija "
                    f"(balans {result['balance_btc']:.8f} BTC) — aktivna novčanik adresa."
                )

    for addr in valid_eth[:MAX_VERIFY_ONLINE]:
        result = _query_eth_balance(addr)
        online_checked += 1
        if result is None:
            online_available = False
            artifacts_list.append(artifact(
                "crypto",
                f"ETH {addr} — validan format, online verifikacija nedostupna (offline)",
                "blockscout",
                extra={"address": addr, "chain": "ETH", "valid": True, "online": False},
            ))
        else:
            artifacts_list.append(artifact(
                "crypto",
                f"ETH {addr} — balans: {result['balance_eth']:.6f} ETH",
                "blockscout (live)",
                extra={"address": addr, "chain": "ETH", "valid": True, "online": True, **result},
            ))
            if result["balance_eth"] > 0:
                alerts.append(f"ETH adresa {addr} ima nenulti balans ({result['balance_eth']:.6f} ETH).")

    # Preostale validne adrese koje nisu online provereni (zbog limita)
    for addr in (valid_btc[MAX_VERIFY_ONLINE:] + valid_eth[MAX_VERIFY_ONLINE:]):
        chain = "BTC" if addr in valid_btc else "ETH"
        artifacts_list.append(artifact(
            "crypto",
            f"{chain} {addr} — validan format (online verifikacija preskočena, limit {MAX_VERIFY_ONLINE})",
            "lokalna validacija",
            extra={"address": addr, "chain": chain, "valid": True, "online": False},
        ))

    if online_checked and not online_available:
        alerts.append(
            "Online verifikacija balansa nije dostupna (nema internet konekcije ili je explorer API nedostupan) — "
            "prikazani su samo rezultati lokalne (offline) validacije adresa."
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
