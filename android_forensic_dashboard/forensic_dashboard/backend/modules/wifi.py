"""
modules/wifi.py
────────────────
Analiza WiFi konfiguracija:
  - WifiConfigStore.xml (Android 9+) → SSID, sačuvane lozinke (PSK), BSSID, lastConnected
  - wpa_supplicant.conf (stariji Android / root dump-ovi) → network blokovi
  - Detekcija javnih/hotelskih/sumnjivih mreža i poklapanje vremena poslednje konekcije
    sa drugim modulima (npr. EXIF timestamp fotografija) radi geolokacijske korelacije.

Format WifiConfigStore.xml se razlikuje između AOSP verzija, pa parser
pokušava nekoliko poznatih šema taga (<Network>/<WifiConfiguration> i <string name="SSID">...).
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result, ms_to_iso

# Reči koje ukazuju na javne/tranzitne mreže (hoteli, aerodromi, kafiće...)
PUBLIC_NETWORK_HINTS = [
    "hotel", "airport", "guest", "free", "public", "cafe", "coffee",
    "lounge", "wifi", "wi-fi", "hostel", "motel", "resort", "starbucks",
    "mcdonalds", "train", "station", "library",
]


def _strip_quotes(value: str) -> str:
    if value is None:
        return ""
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _is_public_hotspot(ssid: str) -> bool:
    if not ssid:
        return False
    low = ssid.lower()
    return any(hint in low for hint in PUBLIC_NETWORK_HINTS)


def _parse_wifi_config_store(path: Path) -> list[dict]:
    """
    Parsira WifiConfigStore.xml (Android 9+).
    Struktura (uobičajena):
      <WifiConfigStoreData>
        <NetworkList>
          <Network>
            <WifiConfiguration>
              <string name="SSID">"MyNetwork"</string>
              <string name="PreSharedKey">"secret123"</string>
              <string name="ConfigKey">"MyNetwork"WPA_PSK</string>
              ...
            </WifiConfiguration>
            <NetworkStatus>
              <string name="SelectionStatus">NETWORK_SELECTION_ENABLED</string>
            </NetworkStatus>
          </Network>
        </NetworkList>
      </WifiConfigStoreData>

    Stariji formati ponekad imaju ravnu listu <WifiConfiguration> elemenata
    direktno ispod root-a — parser pokriva oba slučaja.
    """
    networks = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        return networks

    # Pronađi sve <WifiConfiguration> elemente bilo gde u stablu
    for wc in root.iter("WifiConfiguration"):
        entry = {}
        for child in wc.iter():
            name = child.attrib.get("name")
            if not name:
                continue
            tag = child.tag.lower()
            text = (child.text or "").strip()
            if tag in ("string", "int", "long", "boolean"):
                entry[name] = text

        ssid = _strip_quotes(entry.get("SSID", ""))
        psk = _strip_quotes(entry.get("PreSharedKey", ""))
        bssid = entry.get("BSSID", "")
        config_key = _strip_quotes(entry.get("ConfigKey", ""))
        last_connected = entry.get("lastConnectedTimestampMs") or entry.get("LastConnectUid")
        creator_uid = entry.get("creatorUid", "")
        meterd = entry.get("meteredHint", "")
        hidden = entry.get("hiddenSSID", "")

        if not ssid:
            continue

        # Security tip iz ConfigKey suffixa ili prisustva PSK-a
        security = "OPEN"
        if "WPA_PSK" in config_key or psk:
            security = "WPA/WPA2-PSK"
        elif "WEP" in config_key:
            security = "WEP"
        elif "EAP" in config_key:
            security = "EAP/Enterprise"

        networks.append({
            "ssid": ssid,
            "psk": psk,
            "bssid": bssid,
            "security": security,
            "hidden": hidden == "true",
            "metered": meterd == "true",
            "last_connected_ms": int(last_connected) if last_connected and str(last_connected).isdigit() else None,
        })

    return networks


def _parse_wpa_supplicant(path: Path) -> list[dict]:
    """
    Parsira wpa_supplicant.conf (stariji format):
      network={
          ssid="MyNetwork"
          psk="secret123"
          key_mgmt=WPA-PSK
      }
    """
    networks = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return networks

    for block in re.findall(r"network=\{([^}]*)\}", content, re.DOTALL):
        entry = {}
        for line in block.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                entry[key.strip()] = _strip_quotes(value.strip())

        ssid = entry.get("ssid", "")
        if not ssid:
            continue

        key_mgmt = entry.get("key_mgmt", "")
        psk = entry.get("psk", "")
        security = "OPEN"
        if "WPA" in key_mgmt or psk:
            security = "WPA/WPA2-PSK"
        elif "WEP" in key_mgmt:
            security = "WEP"
        elif "EAP" in key_mgmt:
            security = "EAP/Enterprise"

        networks.append({
            "ssid": ssid,
            "psk": psk,
            "bssid": entry.get("bssid", ""),
            "security": security,
            "hidden": entry.get("scan_ssid") == "1",
            "metered": False,
            "last_connected_ms": None,
        })

    return networks


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    networks: list[dict] = []
    source_label = ""

    config_store = resolver.resolve("wifi_config")
    if config_store:
        networks = _parse_wifi_config_store(config_store)
        source_label = "WifiConfigStore.xml"

    if not networks:
        supplicant = resolver.resolve("wifi_config_alt")
        if supplicant:
            networks = _parse_wpa_supplicant(supplicant)
            source_label = "wpa_supplicant.conf"

    if not networks:
        return module_result(
            status="not_found",
            findings=[finding("Status", "WiFi konfiguracija nije pronađena u dump-u")],
            artifacts=[],
            alerts=[],
        )

    findings.append(finding("Sačuvane WiFi mreže", str(len(networks))))

    open_networks = [n for n in networks if n["security"] == "OPEN"]
    public_networks = [n for n in networks if _is_public_hotspot(n["ssid"])]
    with_psk = [n for n in networks if n["psk"]]

    findings.append(finding("Sa sačuvanom lozinkom (PSK)", str(len(with_psk))))
    findings.append(finding("Otvorene (bez enkripcije)", str(len(open_networks))))
    findings.append(finding("Javne/tranzitne mreže (po nazivu)", str(len(public_networks))))

    # Sortiraj po vremenu zadnje konekcije (najnovije prvo) ako postoji
    networks_sorted = sorted(
        networks,
        key=lambda n: n["last_connected_ms"] or 0,
        reverse=True,
    )

    for net in networks_sorted:
        ts = ms_to_iso(net["last_connected_ms"]) if net["last_connected_ms"] else None
        flags = []
        if _is_public_hotspot(net["ssid"]):
            flags.append("JAVNA/TRANZITNA")
        if net["security"] == "OPEN":
            flags.append("BEZ ENKRIPCIJE")
        if net["hidden"]:
            flags.append("SKRIVENA")

        flag_str = f" [{', '.join(flags)}]" if flags else ""
        value = f"SSID \"{net['ssid']}\" — {net['security']}{flag_str}"
        if net["bssid"]:
            value += f" (BSSID {net['bssid']})"

        artifacts_list.append(artifact(
            "location",
            value,
            source_label,
            ts=ts,
            extra={
                "ssid": net["ssid"],
                "bssid": net["bssid"],
                "security": net["security"],
                "has_psk": bool(net["psk"]),
                "public_hint": _is_public_hotspot(net["ssid"]),
            },
        ))

        finding_value = net["security"]
        if net["psk"]:
            finding_value += f" — lozinka: {net['psk']}"
        findings.append(finding(f"SSID: {net['ssid']}", finding_value))

    # ── Upozorenja ─────────────────────────────────────────────────────────
    for net in public_networks:
        ts = ms_to_iso(net["last_connected_ms"]) if net["last_connected_ms"] else "nepoznato vreme"
        alerts.append(
            f"Povezivanje na javnu/tranzitnu mrežu \"{net['ssid']}\" ({ts}) — "
            f"mogući indikator fizičke lokacije (hotel/aerodrom/kafić)."
        )

    if open_networks:
        alerts.append(
            f"{len(open_networks)} sačuvanih mreža bez enkripcije — "
            f"potencijalno povećan rizik od presretanja saobraćaja."
        )

    if with_psk:
        alerts.append(
            f"{len(with_psk)} WiFi lozinki sačuvano u čistom tekstu (WifiConfigStore) — "
            f"mogu se koristiti za pristup istoj mreži."
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
