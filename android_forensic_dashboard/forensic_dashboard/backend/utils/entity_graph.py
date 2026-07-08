"""
entity_graph.py
───────────────
Sloj za multi-source korelaciju entiteta i pripremu grafa za vizualizaciju.

Iz artefakata svih modula ekstrahuje entitete (telefonski brojevi, email
adrese, kripto adrese, paketi aplikacija, SSID mreže, nalozi, domeni) i
gradi graf entitet-relacija pogodan za force-directed prikaz na frontendu.

Javne funkcije:
- extract_entities(results)            → lista entiteta
- build_entity_graph(results, correlations) → {"nodes", "edges", "stats"}

Koristi isključivo stdlib (re). Nikada ne podiže izuzetak
na malformiranim artefaktima — takvi se preskaču.
"""

import re

# Maksimalan broj čvorova koji se šalje frontendu (force-graph performanse)
MAX_NODES = 300

# ─── REGEX ŠABLONI ────────────────────────────────────────────────────────

# Telefonski broj u međunarodnom formatu (posle uklanjanja separatora)
_PHONE_RE = re.compile(r"\+\d{7,15}")
# Karakteri koji se uklanjaju pri normalizaciji telefona
_PHONE_STRIP_RE = re.compile(r"[\s\-()]")
# Email adresa
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
# Reverse-DNS naziv paketa (npr. com.example.app.module)
_PACKAGE_RE = re.compile(r"^[a-z][\w]*(\.[\w]+){2,}$")
# Hostname iz URL-a (šema://host...)
_URL_HOST_RE = re.compile(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s?#]+)")


# ─── INTERNI HELPERS ──────────────────────────────────────────────────────

def _norm_phone(value) -> str:
    """Normalizuje telefonski broj: uklanja razmake, crtice i zagrade."""
    if value is None:
        return ""
    return _PHONE_STRIP_RE.sub("", str(value)).strip()


def _hostname_from_url(text) -> str:
    """Ekstrahuje hostname iz URL stringa (lowercase, bez porta/kredencijala)."""
    if not text:
        return ""
    try:
        m = _URL_HOST_RE.search(str(text))
        if not m:
            return ""
        host = m.group(1)
        # ukloni user:pass@ deo ako postoji
        if "@" in host:
            host = host.rsplit("@", 1)[-1]
        # ukloni port
        host = host.split(":", 1)[0].strip().lower()
        return host
    except Exception:
        return ""


def _entities_from_artifact(art) -> set:
    """
    Ekstrahuje sve entitete iz jednog artefakta.

    Vraća skup tuple-ova (tip, normalizovana_vrednost).
    Defanzivno: extra može biti None ili pogrešnog tipa, value može
    sadržati unicode — malformirani artefakti se tiho preskaču.
    """
    entities = set()
    if not isinstance(art, dict):
        return entities
    try:
        value = art.get("value")
        value = "" if value is None else str(value)
        extra = art.get("extra")
        if not isinstance(extra, dict):
            extra = {}

        # ── telefon: extra["phone"] + regex preko value ──
        phone = extra.get("phone")
        if phone:
            norm = _norm_phone(phone)
            if norm:
                entities.add(("phone", norm))
        stripped_value = _PHONE_STRIP_RE.sub("", value)
        for match in _PHONE_RE.findall(stripped_value):
            entities.add(("phone", match))

        # ── email: extra["email"] + regex preko value ──
        email = extra.get("email")
        if email:
            norm = str(email).strip().lower()
            if norm:
                entities.add(("email", norm))
        for match in _EMAIL_RE.findall(value):
            entities.add(("email", match.lower()))

        # ── kripto adresa ──
        address = extra.get("address") or extra.get("address_or_uri")
        if address:
            norm = str(address).strip()
            if norm:
                entities.add(("crypto_address", norm))

        # ── paket aplikacije (reverse-DNS format) ──
        package = extra.get("package") or extra.get("package_name")
        if package:
            norm = str(package).strip()
            if _PACKAGE_RE.match(norm):
                entities.add(("package", norm))

        # ── SSID WiFi mreže ──
        ssid = extra.get("ssid")
        if ssid:
            norm = str(ssid).strip()
            if norm:
                entities.add(("ssid", norm))

        # ── korisnički nalog ──
        account = extra.get("username") or extra.get("account")
        if account:
            norm = str(account).strip()
            if norm:
                entities.add(("account", norm))

        # ── domen: samo za web artefakte, hostname iz value/extra["url"] ──
        if art.get("type") == "web":
            for candidate in (value, extra.get("url")):
                host = _hostname_from_url(candidate)
                if host:
                    entities.add(("domain", host))
    except Exception:
        # nikada ne rušimo analizu zbog jednog lošeg artefakta
        return set()
    return entities


def _iter_artifacts(results):
    """Generator: prolazi kroz sve artefakte svih modula (modul, artefakt)."""
    if not isinstance(results, dict):
        return
    for module_name, module_data in results.items():
        if not isinstance(module_data, dict):
            continue
        artifacts = module_data.get("artifacts")
        if not isinstance(artifacts, list):
            continue
        for art in artifacts:
            if isinstance(art, dict):
                yield str(module_name), art


# ─── JAVNE FUNKCIJE ───────────────────────────────────────────────────────

def extract_entities(results: dict) -> list:
    """
    Skenira sve artefakte svih modula i ekstrahuje jedinstvene entitete.

    Tipovi entiteta: phone, email, crypto_address, package, ssid,
    account, domain.

    Vraća listu:
        {"id": "tip:vrednost", "type": str, "label": str,
         "count": int, "modules": [str]}

    - id       : f"{tip}:{normalizovana_vrednost}" (deduplikacija)
    - count    : ukupan broj artefakata u kojima se entitet pojavljuje
    - modules  : sortirani jedinstveni nazivi modula
    """
    registry = {}
    for module_name, art in _iter_artifacts(results):
        for etype, norm in _entities_from_artifact(art):
            eid = f"{etype}:{norm}"
            entity = registry.get(eid)
            if entity is None:
                entity = {
                    "id": eid,
                    "type": etype,
                    "label": norm,
                    "count": 0,
                    "modules": set(),
                }
                registry[eid] = entity
            entity["count"] += 1
            entity["modules"].add(module_name)

    entities = []
    for entity in registry.values():
        entity["modules"] = sorted(entity["modules"])
        entities.append(entity)
    # deterministički redosled: najfrekventniji prvi
    entities.sort(key=lambda e: (-e["count"], e["id"]))
    return entities


def build_entity_graph(results: dict, correlations: list) -> dict:
    """
    Gradi graf entitet-relacija za force-directed vizualizaciju.

    Vraća:
        {"nodes": [...], "edges": [...], "stats": {...}}

    - nodes : entiteti iz extract_entities (id, label, type, count, modules)
    - edges : {"source", "target", "weight", "relation"}
        a) "co_occurrence" — dva entiteta iz ISTOG artefakta;
           weight = broj zajedničkih artefakata
        b) "correlation"  — parovi entiteta iz linked_artifacts jedne
           korelacije; polje "via" nosi ID-jeve korelacija
    - stats : {"total_entities", "total_edges", "truncated"}

    Ako graf ima više od MAX_NODES čvorova, zadržava se top MAX_NODES
    po count vrednosti, ivice ka odbačenim čvorovima se uklanjaju i
    truncated se postavlja na True.
    """
    entities = extract_entities(results)
    node_ids = {e["id"] for e in entities}

    # ključ: (manji_id, veći_id, relacija) → {"weight", "via"}
    edge_acc = {}

    def _add_edge(a, b, relation, via=None):
        if a == b:
            return
        key = (min(a, b), max(a, b), relation)
        record = edge_acc.get(key)
        if record is None:
            record = {"weight": 0, "via": set()}
            edge_acc[key] = record
        record["weight"] += 1
        if via is not None:
            record["via"].add(str(via))

    # ── a) co-occurrence: entiteti iz istog artefakta ──
    for _module, art in _iter_artifacts(results):
        ids = sorted(f"{t}:{n}" for t, n in _entities_from_artifact(art))
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                _add_edge(ids[i], ids[j], "co_occurrence")

    # ── b) correlation: parovi entiteta iz linked_artifacts ──
    if isinstance(correlations, list):
        for corr in correlations:
            if not isinstance(corr, dict):
                continue
            linked = corr.get("linked_artifacts")
            if not isinstance(linked, list):
                continue
            corr_id = corr.get("id")
            corr_entity_ids = set()
            for art in linked:
                for etype, norm in _entities_from_artifact(art):
                    corr_entity_ids.add(f"{etype}:{norm}")
            # samo entiteti koji postoje kao čvorovi grafa
            ids = sorted(corr_entity_ids & node_ids)
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    _add_edge(ids[i], ids[j], "correlation", via=corr_id)

    edges = []
    for (a, b, relation), record in edge_acc.items():
        edge = {"source": a, "target": b, "weight": record["weight"],
                "relation": relation}
        if relation == "correlation":
            edge["via"] = sorted(record["via"])
        edges.append(edge)
    edges.sort(key=lambda e: (-e["weight"], e["source"], e["target"],
                              e["relation"]))

    # ── ograničenje veličine grafa ──
    truncated = False
    if len(entities) > MAX_NODES:
        truncated = True
        entities = entities[:MAX_NODES]  # već sortirani po count opadajuće
        kept = {e["id"] for e in entities}
        edges = [e for e in edges
                 if e["source"] in kept and e["target"] in kept]

    return {
        "nodes": entities,
        "edges": edges,
        "stats": {
            "total_entities": len(entities),
            "total_edges": len(edges),
            "truncated": truncated,
        },
    }
