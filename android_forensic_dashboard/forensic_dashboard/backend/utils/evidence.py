"""
evidence.py — Evidence Integrity & Normalization Layer (P0)
──────────────────────────────────────────────────────────
Sloj koji stoji IZMEĐU ekstrakcije (modules/*.py) i analize. Ne dira 12
modula — obogaćuje njihove artefakte POST-HOC u jedinstvenu (unified)
forenzički-validnu šemu:

  - id          : deterministički identitet artefakta (sha1)
  - case_id     : vezivanje za slučaj (opciono)
  - type        : kanonski tip (message/location/file/log/system) + originalni
  - source_app  : aplikacija/paket izvora (iz extra ili heuristika)
  - raw_source  : provenance — {file (apsolutna putanja), rel, table, rowid}
  - hash_set    : {md5, sha1, sha256} IZVORNOG fajla (chain of custody)
  - confidence  : numerički 0-100 (ne string)
  - value/ts/extra/source : zadržani (backward-compat)

Dizajn:
  - Idempotentno: već obogaćen artefakt se ne dira ponovo.
  - Heš izvornih fajlova se KEŠIRA po apsolutnoj putanji (skupo je).
  - "original vs processed": originalni artefakt se ne menja u mestu — vraća
    se NOVI dict sa dodatnim poljima; sirova vrednost ostaje u 'value'/'extra'.
  - Sve lokalno, bez mreže.
"""

import re
import hashlib
from pathlib import Path

# Mapiranje internih tipova modula na kanonske DFIR kategorije
_CANON_TYPE = {
    "comm": "message", "sms": "message", "message": "message",
    "call": "call",
    "location": "location",
    "web": "web",
    "crypto": "crypto",
    "app": "system", "apk": "system", "device": "system", "account": "account",
    "contact": "contact",
    "media": "file",
    "anti_forensic": "system",
}

# Bazna pouzdanost po kanonskom tipu (0-100) — polazna tačka, dalje se koriguje
_TYPE_BASE = {
    "call": 80, "message": 78, "location": 72, "contact": 75,
    "account": 68, "crypto": 65, "system": 60, "file": 55, "web": 45,
}

_HASH_CACHE: dict = {}   # {abs_path_str: {md5, sha1, sha256}}


def hash_file_all(path: Path) -> dict:
    """MD5 + SHA1 + SHA256 izvornog fajla u JEDNOM prolazu (chunked). Kešira se."""
    key = str(path)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        out = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
    except Exception:
        out = {"md5": None, "sha1": None, "sha256": None}
    _HASH_CACHE[key] = out
    return out


def make_artifact_id(module: str, source: str, type_: str, value: str, ts) -> str:
    """Deterministički identitet artefakta — sha1(module|source|type|value|ts)[:16]."""
    basis = f"{module}|{source}|{type_}|{value}|{ts or ''}"
    return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]


def canonical_type(type_: str) -> str:
    return _CANON_TYPE.get((type_ or "").lower(), "system")


def resolve_source_file(resolver, source: str):
    """
    Prevedi 'source' string artefakta u apsolutnu putanju u dump-u, ako je moguće.
    Vraća (abs_path|None, rel_path|None). Radi za relativne putanje i bare imena baza.
    """
    if not source:
        return None, None
    root = resolver.root.resolve()
    s = source.strip().lstrip("/\\")

    # 1) direktno kao relativna putanja
    cand = (root / s)
    try:
        if cand.exists() and cand.is_file():
            return cand.resolve(), str(cand.resolve().relative_to(root))
    except Exception:
        pass

    # 2) po imenu fajla (npr. "mmssms.db", "History", "packages.xml")
    base = Path(s).name
    # skini sufikse tipa "Chrome/History" -> "History"
    if "/" in s or "\\" in s:
        base = re.split(r"[\\/]", s)[-1]
    # ukloni oznake tipa "Calllog (calllog.db)" -> uzmi deo u zagradi ako postoji
    m = re.search(r"\(([^)]+)\)", base)
    if m:
        base = m.group(1)
    if base:
        try:
            matches = resolver.find_files_by_regex(rf"^{re.escape(base)}$")
        except Exception:
            matches = []
        if matches:
            try:
                matches.sort(key=lambda p: p.stat().st_size, reverse=True)
            except Exception:
                pass
            p = matches[0].resolve()
            try:
                return p, str(p.relative_to(root))
            except Exception:
                return p, str(p)
    return None, None


def _source_app(art: dict) -> str:
    extra = art.get("extra") or {}
    for k in ("package", "package_name", "source_app", "creator"):
        v = extra.get(k)
        if v:
            return str(v)
    return ""


def artifact_confidence(art: dict, has_provenance: bool) -> int:
    """
    Numerička pouzdanost artefakta (0-100), deterministička i objašnjiva:
      baza po tipu + provenance bonus + timestamp bonus + jaki indikatori.
    """
    ctype = canonical_type(art.get("type"))
    score = _TYPE_BASE.get(ctype, 50)
    if has_provenance:
        score += 15          # dokaz vezan za stvarni fajl u dump-u
    if art.get("ts"):
        score += 5           # postoji vremenska oznaka
    extra = art.get("extra") or {}
    if any(extra.get(k) for k in ("encryption", "trojanized", "suspicious")):
        score += 10          # jak forenzički indikator
    if extra.get("valid") is False:
        score -= 25          # npr. nevalidna kripto adresa
    return max(0, min(100, score))


def enrich_artifact(art: dict, module: str, resolver, case_id: str = None) -> dict:
    """
    Vrati NOVI artefakt u unified šemi (original se ne menja). Idempotentno.
    """
    if art.get("_enriched"):
        return art

    source = art.get("source", "")
    abs_path, rel_path = resolve_source_file(resolver, source) if resolver else (None, None)
    has_prov = abs_path is not None
    hash_set = hash_file_all(abs_path) if abs_path else {"md5": None, "sha1": None, "sha256": None}

    extra = art.get("extra") or {}
    out = dict(art)  # kopija — original vs processed separacija
    out.update({
        "_enriched": True,
        "id": make_artifact_id(module, source, art.get("type"), art.get("value"), art.get("ts")),
        "case_id": case_id,
        "module": module,
        "type_canonical": canonical_type(art.get("type")),
        "source_app": _source_app(art),
        "raw_source": {
            "file": str(abs_path) if abs_path else None,
            "rel": rel_path,
            "table": extra.get("table") or extra.get("source_table"),
            "rowid": extra.get("rowid"),
        },
        "hash_set": hash_set,
        "confidence": artifact_confidence(art, has_prov),
    })
    return out


def enrich_results(results: dict, resolver, case_id: str = None) -> dict:
    """
    Obogati SVE artefakte u svim modulima. Vraća novi results dict; ne menja
    ulazni. Ovo je 'Normalization Layer' iz ciljne arhitekture.
    """
    out = {}
    for module, data in (results or {}).items():
        new_data = dict(data)
        arts = data.get("artifacts") or []
        new_data["artifacts"] = [enrich_artifact(a, module, resolver, case_id) for a in arts]
        out[module] = new_data
    return out
