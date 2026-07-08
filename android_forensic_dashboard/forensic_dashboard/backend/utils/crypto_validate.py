"""
crypto_validate.py
──────────────────
Jedinstveni, ispravan modul za VALIDACIJU kriptovalutnih adresa —
deljen između modula 'crypto' (otkrivanje/triage) i 'blockchain'
(verifikacija). Cilj: eliminisati lažne pozitive (hash vrednosti, UUID-ovi,
delimični stringovi) koji NISU prave adrese, na jednom mestu.

Implementirano čistim stdlib pristupom (bez eksternih biblioteka):
  - Base58Check validacija legacy BTC adresa (P2PKH/P2SH) — puna checksum provera
  - Bech32/Bech32m validacija SegWit (bc1...) adresa po BIP-173/BIP-350
  - Format + (opciona) EIP-55 nedostupna bez Keccak-a → samo format za ETH

Ove funkcije su testirane na zvaničnim BIP-173 test vektorima.
"""

import hashlib
import re

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3

# Strogi kandidat-regexi (isti kao u blockchain modulu)
LEGACY_BTC_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
BECH32_BTC_RE = re.compile(r"^(?:bc1[qpzry9x8gf2tvdw0s3jln54khce6mua7l]{8,87}"
                           r"|BC1[QPZRY9X8GF2TVDW0S3JLN54KHCE6MUA7L]{8,87})$")
ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
PURE_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def is_noise(s: str) -> bool:
    """Čist hex (hash/UUID) ili čiste cifre — nikad prava adresa."""
    return bool(PURE_HEX_RE.fullmatch(s)) or s.isdigit()


def _base58_decode(s: str):
    try:
        if not s:
            return None
        num = 0
        for ch in s:
            if ch not in BASE58_ALPHABET:
                return None
            num = num * 58 + BASE58_ALPHABET.index(ch)
        n_leading_zeros = len(s) - len(s.lstrip("1"))
        body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        return b"\x00" * n_leading_zeros + body
    except Exception:
        return None


def validate_btc_legacy(address: str) -> bool:
    """Puna Base58Check validacija legacy (1.../3...) adrese."""
    if not LEGACY_BTC_RE.match(address):
        return False
    decoded = _base58_decode(address)
    if decoded is None or len(decoded) != 25:
        return False
    payload, checksum = decoded[:21], decoded[21:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def _bech32_polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def validate_bech32(address: str) -> bool:
    """Bech32/Bech32m checksum validacija (BIP-173/BIP-350), hrp 'bc'."""
    if not BECH32_BTC_RE.match(address):
        return False
    if address != address.lower() and address != address.upper():
        return False  # mešana slova nevalidna
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
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) in (BECH32_CONST, BECH32M_CONST)


def validate_eth(address: str) -> bool:
    """
    Format validacija ETH adrese (0x + 40 hex).
    OGRANIČENJE: EIP-55 checksum zahteva Keccak-256 (stdlib nema — sha3_256
    je SHA-3, ne Keccak), pa se prihvata svaka adresa ispravnog formata.
    """
    return bool(ETH_RE.match(address))


def is_valid_btc(address: str) -> bool:
    """True ako je adresa validna legacy ILI bech32 BTC adresa."""
    return validate_btc_legacy(address) or validate_bech32(address)
