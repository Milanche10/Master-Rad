"""
dump_resolver.py
────────────────
Pronalazi tačne putanje unutar Android dump-a bez obzira na to
kako je dump organizovan (direktno raspakovan, sa prefiksom, itd.)

Android dump-ovi mogu imati različite strukture:
  /dump_root/data/data/...          ← najčešće
  /dump_root/sdcard/...             ← alternativa za media
  /dump_root/userdata/data/data/... ← neki alati dodaju particiju kao folder
"""

import os
import re
import sqlite3
from pathlib import Path
from typing import Optional

# Deljeni keš po root putanji dump-a: {str(root): {"files": [...], "sqlite": {...}}}.
# Svi DumpResolver-i za isti dump dele skupi walk + SQLite indeks (jedan walk
# po dump-u umesto po modulu). Očisti se clear_scan_cache() na novoj sesiji.
_SHARED_CACHE: dict = {}


def clear_scan_cache(root: str = None):
    """Očisti deljeni keš (za dati root ili sve)."""
    if root is None:
        _SHARED_CACHE.clear()
    else:
        _SHARED_CACHE.pop(str(root), None)


# Magični potpis na početku svakog nešifrovanog SQLite fajla.
# Koristi se da bez oslanjanja na ekstenziju/putanju prepoznamo bazu
# ma gde bila i kako god se zvala (sakrivena, preimenovana, .db.bak...).
SQLITE_MAGIC = b"SQLite format 3\x00"

# Direktorijumi koje preskačemo pri rekurzivnom skeniranju (bez foren. vrednosti,
# a mogu biti ogromni) — ubrzava pretragu na velikim dump-ovima.
SKIP_DIR_NAMES = {
    "cache", "code_cache", "app_webview", "app_textures", ".thumbnails",
    "node_modules", "__pycache__",
}

# Potpisi baza po skupu tabela — omogućava prepoznavanje baze po SADRŽAJU
# (koje tabele ima), nezavisno od Android verzije, proizvođača i putanje.
# any_of: dovoljno je da baza ima BILO KOJU od tabela (za baze čija se šema
# razlikuje po verziji); u suprotnom moraju sve navedene biti prisutne.
DB_SCHEMA_SIGNATURES = {
    "calllog":        {"tables": {"calls"}, "any_of": False},
    "contacts2":      {"tables": {"raw_contacts", "view_contacts", "contacts"}, "any_of": True},
    "mmssms":         {"tables": {"sms", "pdu", "threads"}, "any_of": True},
    "chrome_history": {"tables": {"urls", "visits"}, "any_of": False},
    "chrome_login":   {"tables": {"logins"}, "any_of": False},
    "chrome_cookies": {"tables": {"cookies"}, "any_of": False},
}

# Rezervni obrasci naziva fajla (regex) po ključu — kada kanonska putanja
# ne postoji, tražimo fajl po imenu bilo gde u dump-u.
FILENAME_PATTERNS = {
    "calllog":        [r"^calllog\.db$", r"^calls?\.db$", r"contacts2\.db$"],
    "contacts2":      [r"^contacts2\.db$", r"^contacts\.db$"],
    "mmssms":         [r"^mmssms\.db$", r"^messages?\.db$", r"^sms\.db$", r"^telephony\.db$"],
    "chrome_history": [r"^History$"],
    "chrome_login":   [r"^Login Data$"],
    "chrome_cookies": [r"^Cookies$"],
    "wifi_config":    [r"^WifiConfigStore\.xml$", r"^wpa_supplicant\.conf$"],
    "build_prop":     [r"^build\.prop$"],
}


# Alternativni "data root"-ovi za podatke po paketu. Na realnom uređaju
# /data/data je symlink na /data/user/0 — neki alati za ekstrakciju ne
# prate symlink-ove pa se sadržaj nalazi pod data/user/0/<pkg> ili
# data/user_de/0/<pkg> (Device Encrypted storage) umesto data/data/<pkg>.
DATA_ROOTS = ["data/data", "data/user/0", "data/user_de/0"]

# Kanonske putanje unutar Android fajl sistema
KNOWN_ANCHORS = [
    "data/data/com.android.providers.telephony",
    "data/data/com.android.providers.contacts",
    "data/user/0/com.android.providers.telephony",
    "data/user/0/com.android.providers.contacts",
    "data/misc/wifi",
    "data/media/0/DCIM",
    "data/system",
]

# Mapiranje kratkih naziva na stvarne putanje u dump-u
PATHS = {
    # SQLite baze
    "mmssms":    "data/data/com.android.providers.telephony/databases/mmssms.db",
    "calllog":   "data/data/com.android.providers.contacts/databases/calllog.db",
    "contacts2": "data/data/com.android.providers.contacts/databases/contacts2.db",

    # Samsung-specific alternativne putanje (Samsung Galaxy uređaji koriste
    # com.samsung.android.providers.contacts umesto AOSP paketa)
    "calllog_samsung":   "data/data/com.samsung.android.providers.contacts/databases/calllog.db",
    "contacts2_samsung": "data/data/com.samsung.android.providers.contacts/databases/contacts2.db",
    # Samsung telephony (mmssms je ponekad ovde)
    "mmssms_samsung": "data/data/com.samsung.android.providers.telephony/databases/mmssms.db",

    # Chrome
    "chrome_history":    "data/data/com.android.chrome/app_chrome/Default/History",
    "chrome_login":      "data/data/com.android.chrome/app_chrome/Default/Login Data",
    "chrome_cookies":    "data/data/com.android.chrome/app_chrome/Default/Cookies",
    "chrome_web_data":   "data/data/com.android.chrome/app_chrome/Default/Web Data",

    # WiFi
    "wifi_config":   "data/misc/wifi/WifiConfigStore.xml",
    "wifi_config_alt": "data/misc/wifi/wpa_supplicant.conf",

    # Sistemske informacije
    "build_prop":    "system/build.prop",
    "settings_db":   "data/data/com.android.providers.settings/databases/settings.db",

    # Media direktorijumi
    "dcim":          "data/media/0/DCIM",
    "pictures":      "data/media/0/Pictures",
    "downloads":     "data/media/0/Download",
    "screenshots":   "data/media/0/DCIM/Screenshots",

    # Shared prefs (Google nalog, JWT tokeni)
    "google_prefs":  "data/data/com.google.android.gms/shared_prefs",
    "system_prefs":  "data/system/users/0/settings_global.xml",

    # OmniNotes
    "omninotes_db":  "data/data/it.feio.android.omninotes/databases/db",
    "omninotes_prefs": "data/data/it.feio.android.omninotes/shared_prefs",

    # Signal
    "signal_db":     "data/data/org.thoughtcrime.securesms/databases/signal.db",
    "signal_prefs":  "data/data/org.thoughtcrime.securesms/shared_prefs",

    # BRD Wallet
    "brd_db":        "data/data/com.breadwallet/databases/BreadWallet.db",
    "brd_prefs":     "data/data/com.breadwallet/shared_prefs",

    # Package manager (instalirane aplikacije)
    "packages_xml":  "data/system/packages.xml",
    "packages_list": "data/system/packages.list",

    # APK direktorijumi
    "apk_dir":       "data/app",
    "apk_dir_alt":   "data/media/0/Download",
}


class DumpResolver:
    """
    Inicijalizuje se sa putanjom do dump-a i pronalazi pravi root.
    Nakon inicijalizacije koristi .resolve(key) ili .resolve_path(rel_path)
    za dobijanje apsolutnih putanja.
    """

    def __init__(self, dump_path: str):
        self.dump_path = Path(dump_path)
        self.root = self._find_root()
        # Lazy kešovi za generičku pretragu (grade se pri prvom pozivu)
        self._file_index: Optional[list[Path]] = None      # svi fajlovi u dump-u
        self._sqlite_index: Optional[dict] = None           # {Path: frozenset(tabele)}
        self._smart_cache: dict = {}                        # {key: Path|None}

    def _find_root(self) -> Path:
        """
        Traži root Android fajl sistema unutar dump-a — pravi Android FS root
        je onaj direktorijum ispod kojeg postoji neki od KNOWN_ANCHORS
        (npr. data/data/…). Neki alati pakuju dump u ugnežđene foldere
        (ime uređaja / 'Dump' / particija), pa pretražujemo do dubine 4.
        """
        MAX_DEPTH = 4
        # BFS kroz direktorijume do MAX_DEPTH; prvi koji ima anchor je root.
        queue = [(self.dump_path, 0)]
        while queue:
            candidate, depth = queue.pop(0)
            if not candidate.is_dir():
                continue
            for anchor in KNOWN_ANCHORS:
                if (candidate / anchor).exists():
                    return candidate
            if depth < MAX_DEPTH:
                try:
                    for sub in candidate.iterdir():
                        if sub.is_dir():
                            queue.append((sub, depth + 1))
                except (PermissionError, OSError):
                    continue
        # Fallback: vrati dump_path bez obzira
        return self.dump_path

    def resolve(self, key: str) -> Optional[Path]:
        """Vrati apsolutnu putanju za poznati ključ, ili None ako ne postoji."""
        rel = PATHS.get(key)
        if rel is None:
            return None
        return self.resolve_path(rel)

    def resolve_path(self, rel_path: str) -> Optional[Path]:
        """
        Vrati apsolutnu putanju za proizvoljnu relativnu putanju.
        Ako putanja počinje sa "data/data/" i ne postoji, probaj
        alternativne data root-ove (data/user/0, data/user_de/0).
        """
        full = self.root / rel_path
        if full.exists():
            return full

        for alt_root in DATA_ROOTS[1:]:
            if rel_path.startswith("data/data/"):
                alt = self.root / alt_root / rel_path[len("data/data/"):]
                if alt.exists():
                    return alt

        return None

    def resolve_dir(self, key: str) -> Optional[Path]:
        """Isto kao resolve() ali proverava da je direktorijum."""
        p = self.resolve(key)
        return p if p and p.is_dir() else None

    # ═══════════════════════════════════════════════════════════════════════
    # GENERIČKA PRETRAGA — radi za BILO KOJI uređaj / Android verziju / OEM,
    # ne samo za kanonske AOSP putanje. Baze se nalaze po imenu (regex) ili
    # po SADRŽAJU (koje tabele imaju), pa se pronalaze i preimenovane,
    # premeštene ili "sakrivene" baze na nestandardnim putanjama.
    # ═══════════════════════════════════════════════════════════════════════

    def _all_files(self) -> list[Path]:
        """
        Rekurzivno indeksira sve fajlove u dump-u. DELJENI KEŠ po root putanji:
        svih 12+ modula pravi sopstveni DumpResolver, ali dele isti walk (jedan
        walk po dump-u umesto po modulu) — bitna ušteda I/O na velikim dump-ovima.
        """
        if self._file_index is not None:
            return self._file_index

        rootkey = str(self.root)
        cached = _SHARED_CACHE.get(rootkey, {}).get("files")
        if cached is not None:
            self._file_index = cached
            return cached

        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Preskoči direktorijume bez forenzičke vrednosti (cache itd.)
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIR_NAMES]
            for name in filenames:
                try:
                    files.append(Path(dirpath) / name)
                except Exception:
                    continue
        self._file_index = files
        _SHARED_CACHE.setdefault(rootkey, {})["files"] = files
        return files

    def find_files_by_regex(self, patterns) -> list[Path]:
        """
        Vrati sve fajlove čije IME odgovara nekom od datih regex obrazaca,
        bilo gde u dump-u (nezavisno od putanje/dubine).
        `patterns` je string ili lista stringova.
        """
        if isinstance(patterns, str):
            patterns = [patterns]
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE))
            except re.error:
                continue
        matches = []
        for f in self._all_files():
            if any(rx.match(f.name) for rx in compiled):
                matches.append(f)
        return matches

    @staticmethod
    def _is_sqlite(path: Path) -> bool:
        """Brza provera: da li fajl počinje SQLite magičnim potpisom."""
        try:
            with open(path, "rb") as fh:
                return fh.read(16) == SQLITE_MAGIC
        except Exception:
            return False

    def _table_names(self, path: Path) -> frozenset:
        """Pročitaj imena tabela iz SQLite baze (read-only, bez izmena)."""
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            try:
                cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                return frozenset(r[0] for r in cur.fetchall())
            finally:
                conn.close()
        except Exception:
            return frozenset()

    def _build_sqlite_index(self) -> dict:
        """
        Napravi indeks svih pravih SQLite baza u dump-u → {putanja: {tabele}}.
        Šifrovane baze (SQLCipher, npr. Signal) nemaju plaintext SQLite header
        pa se ovde prirodno preskaču (ne mogu se ni čitati bez ključa).
        """
        if self._sqlite_index is not None:
            return self._sqlite_index

        rootkey = str(self.root)
        cached = _SHARED_CACHE.get(rootkey, {}).get("sqlite")
        if cached is not None:
            self._sqlite_index = cached
            return cached

        index: dict = {}
        for f in self._all_files():
            if self._is_sqlite(f):
                tables = self._table_names(f)
                if tables:
                    index[f] = tables
        self._sqlite_index = index
        _SHARED_CACHE.setdefault(rootkey, {})["sqlite"] = index
        return index

    def find_db_by_schema(self, required_tables, any_of: bool = False) -> Optional[Path]:
        """
        Pronađi SQLite bazu po SADRŽAJU — koja sadrži tražene tabele —
        nezavisno od imena i putanje. `required_tables` je skup/lista.
        any_of=True: dovoljna je bilo koja tabela; inače sve moraju postojati.
        Vraća najveću bazu koja odgovara (heuristika: prava baza > prazna kopija).
        """
        required = set(required_tables)
        candidates = []
        for path, tables in self._build_sqlite_index().items():
            hit = (required & tables) if any_of else (required <= tables)
            if hit:
                try:
                    candidates.append((path.stat().st_size, path))
                except Exception:
                    candidates.append((0, path))
        if not candidates:
            return None
        candidates.sort(reverse=True)  # najveća baza prva
        return candidates[0][1]

    def resolve_db(self, key: str) -> Optional[Path]:
        """
        Pametno razrešavanje baze za bilo koji uređaj, redom:
          1) kanonska putanja (PATHS) — najbrže
          2) rezervni ključevi (npr. Samsung varijante)
          3) pretraga po imenu fajla (regex, bilo gde u dump-u)
          4) pretraga po šemi (koje tabele baza sadrži)
        Rezultat se kešira po ključu.
        """
        if key in self._smart_cache:
            return self._smart_cache[key]

        # 1) kanonska putanja
        result = self.resolve(key)

        # 2) poznate alternative (Samsung itd.)
        if not result:
            for alt_key in (f"{key}_samsung", f"{key}_alt"):
                if alt_key in PATHS:
                    result = self.resolve(alt_key)
                    if result:
                        break

        # 3) po imenu fajla
        if not result and key in FILENAME_PATTERNS:
            matches = self.find_files_by_regex(FILENAME_PATTERNS[key])
            # preferiraj najveći fajl (prava baza, ne prazan stub)
            if matches:
                try:
                    matches.sort(key=lambda p: p.stat().st_size, reverse=True)
                except Exception:
                    pass
                result = matches[0]

        # 4) po šemi (sadržaju baze)
        if not result and key in DB_SCHEMA_SIGNATURES:
            sig = DB_SCHEMA_SIGNATURES[key]
            result = self.find_db_by_schema(sig["tables"], any_of=sig["any_of"])

        self._smart_cache[key] = result
        return result

    def discovery_report(self) -> dict:
        """
        Dijagnostika otkrivanja baza: za svaki poznati ključ prikaži da li je
        i KAKO pronađen (kanonski / regex / šema / nije). Korisno za izveštaj
        "Artifact Discovery Status" kod nestandardnih dump-ova.
        """
        report = {}
        for key in DB_SCHEMA_SIGNATURES:
            canonical = self.resolve(key)
            smart = self.resolve_db(key)
            if canonical:
                method = "kanonska putanja"
            elif smart:
                # da li je nađen po imenu ili po šemi
                method = "po imenu fajla" if key in FILENAME_PATTERNS and \
                    self.find_files_by_regex(FILENAME_PATTERNS[key]) else "po šemi baze"
            else:
                method = "nije pronađen"
            report[key] = {
                "found": bool(smart),
                "method": method,
                "path": str(smart) if smart else None,
            }
        return report

    def find_apks(self) -> list[Path]:
        """Pronađi sve APK fajlove u dump-u."""
        apk_files = []
        for search_dir in [self.root / "data/app", self.root / "data/media/0/Download"]:
            if search_dir.exists():
                apk_files.extend(search_dir.rglob("*.apk"))
        return apk_files

    def pkg_root(self, package_name: str) -> Optional[Path]:
        """Vrati prvi postojeći data direktorijum za dati paket (data/data, data/user/0, ...)."""
        for data_root in DATA_ROOTS:
            candidate = self.root / data_root / package_name
            if candidate.exists():
                return candidate
        return None

    def find_databases_for_package(self, package_name: str) -> list[Path]:
        """Vrati sve SQLite baze za dati paket."""
        root = self.pkg_root(package_name)
        if not root:
            return []
        db_dir = root / "databases"
        if not db_dir.exists():
            return []
        return list(db_dir.glob("*.db"))

    def find_shared_prefs_for_package(self, package_name: str) -> list[Path]:
        """Vrati sve XML shared_prefs fajlove za dati paket."""
        root = self.pkg_root(package_name)
        if not root:
            return []
        prefs_dir = root / "shared_prefs"
        if not prefs_dir.exists():
            return []
        return list(prefs_dir.glob("*.xml"))

    def list_installed_packages(self) -> list[str]:
        """Vrati listu instaliranih paketa na osnovu data root direktorijuma."""
        packages = set()
        for data_root in DATA_ROOTS:
            data_dir = self.root / data_root
            if data_dir.exists():
                packages.update(d.name for d in data_dir.iterdir() if d.is_dir())
        return sorted(packages)

    def summary(self) -> dict:
        """Vrati kratak pregled dump-a za dijagnostiku."""
        found = {key: str(self.resolve(key)) for key in PATHS if self.resolve(key)}
        missing = [key for key in PATHS if not self.resolve(key)]
        return {
            "dump_path": str(self.dump_path),
            "resolved_root": str(self.root),
            "found_artifacts": found,
            "missing_artifacts": missing,
            "installed_packages": self.list_installed_packages(),
        }
