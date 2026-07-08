"""
modules/signal_brd.py
────────────────────────
Analiza dva specifična paketa koji se često pojavljuju zajedno u
slučajevima sa šifrovanom komunikacijom i kriptovalutnim transferima:

  - Signal (org.thoughtcrime.securesms):
      * Detekcija SQLCipher enkriptovane baze (signal.db / *.db)
      * Plaintext shared_prefs (registrovan broj telefona, ako postoji
        u starijim verzijama bez full keystore enkripcije)
      * Lista priloga (attachments) — broj, ukupna veličina, vremenski raspon

  - BRD Wallet (com.breadwallet):
      * Detekcija enkripcije baze (SQLCipher vs plaintext SQLite)
      * Ako je plaintext: ekstrakcija tabela i kripto adresa/transakcija
      * shared_prefs sa konfiguracijom novčanika

Oba paketa se traže generički preko data/data/<package>/ — modul radi
i ako je samo jedan od njih prisutan.
"""

import re
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from utils.dump_resolver import DumpResolver
from utils.db_reader import SafeDBReader
from utils.helpers import artifact, finding, module_result

SIGNAL_PKG = "org.thoughtcrime.securesms"
BRD_PKG = "com.breadwallet"

PHONE_RE = re.compile(r"\+\d{8,15}")
ADDR_RE = re.compile(r"\b(0x[a-fA-F0-9]{40}|[13][a-zA-Z0-9]{25,34}|bc1[a-z0-9]{25,90})\b")


def _is_sqlcipher_encrypted(db_path: Path) -> bool:
    """Pokušaj otvoriti bazu standardnim sqlite3 — SQLCipher baze ne mogu se pročitati."""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.execute("SELECT count(*) FROM sqlite_master")
        conn.close()
        return False
    except sqlite3.DatabaseError:
        return True
    except Exception:
        return False


def _file_mtime_iso(path: Path) -> str | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _analyze_signal(resolver: DumpResolver, findings: list, artifacts_list: list, alerts: list):
    pkg_root = resolver.pkg_root(SIGNAL_PKG)
    if not pkg_root:
        findings.append(finding("Signal (org.thoughtcrime.securesms)", "Nije pronađen u dump-u"))
        return

    pkg_rel = str(pkg_root.relative_to(resolver.root))

    findings.append(finding("Signal paket", "Detektovan"))
    artifacts_list.append(artifact(
        "app",
        "Instalirana aplikacija: Signal (org.thoughtcrime.securesms)",
        pkg_rel,
        extra={"package": SIGNAL_PKG},
    ))

    # ── Baza(e) ──────────────────────────────────────────────────────────
    db_dir = pkg_root / "databases"
    if db_dir.exists():
        for db_file in db_dir.glob("*.db"):
            encrypted = _is_sqlcipher_encrypted(db_file)
            size_kb = db_file.stat().st_size // 1024
            status = "SQLCipher enkriptovana" if encrypted else "plaintext SQLite"
            findings.append(finding(f"  DB {db_file.name}", f"{status}, {size_kb} KB"))
            artifacts_list.append(artifact(
                "comm",
                f"Signal baza '{db_file.name}': {status} ({size_kb} KB)",
                f"{pkg_rel}/databases/{db_file.name}",
                extra={"encrypted": encrypted, "size_kb": size_kb},
            ))
            if encrypted:
                alerts.append(
                    f"Signal baza '{db_file.name}' je SQLCipher enkriptovana — sadržaj poruka "
                    f"nije dostupan bez ključa iz Android Keystore-a."
                )

    # ── Shared prefs (plaintext, ako postoji) ───────────────────────────
    prefs_dir = pkg_root / "shared_prefs"
    found_phone = None
    if prefs_dir.exists():
        for xml_file in prefs_dir.glob("*.xml"):
            try:
                content = xml_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            m = PHONE_RE.search(content)
            if m and "local_number" in content.lower():
                found_phone = m.group(0)
                break

    if found_phone:
        findings.append(finding("Registrovan broj (Signal)", found_phone))
        artifacts_list.append(artifact(
            "account",
            f"Signal registrovan broj telefona: {found_phone}",
            f"{pkg_rel}/shared_prefs",
            extra={"phone": found_phone},
        ))
        alerts.append(f"Signal registrovan na broj {found_phone} — identifikacioni artefakt.")
    else:
        findings.append(finding("Registrovan broj (Signal)", "Nije pronađen (enkriptovano ili nedostupno)"))

    # ── Attachments ──────────────────────────────────────────────────────
    attach_candidates = [pkg_root / "files" / "attachments", pkg_root / "app_part1", pkg_root / "app_parts"]
    for attach_dir in attach_candidates:
        if attach_dir.exists():
            files = [f for f in attach_dir.rglob("*") if f.is_file()]
            if not files:
                continue
            total_size_mb = sum(f.stat().st_size for f in files) / (1024 * 1024)
            mtimes = sorted(filter(None, (_file_mtime_iso(f) for f in files)))
            findings.append(finding("Signal prilozi (attachments)", f"{len(files)} fajlova, {total_size_mb:.1f} MB"))
            if mtimes:
                findings.append(finding("  Raspon vremena priloga", f"{mtimes[0]} → {mtimes[-1]}"))
            artifacts_list.append(artifact(
                "comm",
                f"Signal prilozi: {len(files)} fajlova ({total_size_mb:.1f} MB) u {attach_dir.name}",
                f"{pkg_rel}/{attach_dir.relative_to(pkg_root)}",
                ts=mtimes[-1] if mtimes else None,
                extra={"count": len(files), "total_mb": round(total_size_mb, 2)},
            ))
            alerts.append(
                f"Signal sadrži {len(files)} enkriptovanih priloga ({total_size_mb:.1f} MB) — "
                f"sadržaj nedostupan bez dekriptovanja baze, ali metapodaci (vreme/veličina) su iskoristivi."
            )


def _analyze_brd(resolver: DumpResolver, findings: list, artifacts_list: list, alerts: list):
    pkg_root = resolver.pkg_root(BRD_PKG)
    if not pkg_root:
        findings.append(finding("BRD Wallet (com.breadwallet)", "Nije pronađen u dump-u"))
        return

    pkg_rel = str(pkg_root.relative_to(resolver.root))

    findings.append(finding("BRD Wallet paket", "Detektovan"))
    artifacts_list.append(artifact(
        "crypto",
        "Instalirana aplikacija: BRD Wallet (com.breadwallet)",
        pkg_rel,
        extra={"package": BRD_PKG},
    ))

    db_dir = pkg_root / "databases"
    addresses_found = set()
    if db_dir.exists():
        # BUGFIX: `glob(a) or glob(b)` je uvek uzimao prvi generator (uvek
        # truthy), pa se .sqlite fajlovi nikad nisu skenirali. Spajamo obe liste.
        db_files = list(db_dir.glob("*.db")) + list(db_dir.glob("*.sqlite"))
        for db_file in db_files:
            encrypted = _is_sqlcipher_encrypted(db_file)
            size_kb = db_file.stat().st_size // 1024
            status = "SQLCipher enkriptovana" if encrypted else "plaintext SQLite"
            findings.append(finding(f"  DB {db_file.name}", f"{status}, {size_kb} KB"))

            if encrypted:
                alerts.append(f"BRD baza '{db_file.name}' je enkriptovana — sadržaj transakcija nedostupan bez ključa.")
                artifacts_list.append(artifact(
                    "crypto",
                    f"BRD baza '{db_file.name}': enkriptovana ({size_kb} KB)",
                    f"{pkg_rel}/databases/{db_file.name}",
                    extra={"encrypted": True, "size_kb": size_kb},
                ))
                continue

            try:
                with SafeDBReader(db_file) as db:
                    tables = db.tables()
                    findings.append(finding(f"  Tabele u {db_file.name}", ", ".join(tables[:10])))

                    for table in tables:
                        try:
                            rows = db.query(f"SELECT * FROM {table} LIMIT 200")
                        except Exception:
                            continue
                        for row in rows:
                            for col, val in row.items():
                                if isinstance(val, str):
                                    for m in ADDR_RE.finditer(val):
                                        addresses_found.add((m.group(0), table))
                                elif isinstance(val, bytes):
                                    try:
                                        decoded = val.decode("utf-8", "ignore")
                                        for m in ADDR_RE.finditer(decoded):
                                            addresses_found.add((m.group(0), table))
                                    except Exception:
                                        pass
            except Exception:
                pass

    for addr, table in sorted(addresses_found)[:20]:
        artifacts_list.append(artifact(
            "crypto",
            f"BRD Wallet adresa: {addr} (tabela: {table})",
            f"{pkg_rel}/databases",
            extra={"address": addr, "source_table": table, "wallet": "BRD"},
        ))

    if addresses_found:
        findings.append(finding("BRD adrese pronađene u bazi", str(len(addresses_found))))
        alerts.append(
            f"Pronađeno {len(addresses_found)} kriptovalutnih adresa direktno u BRD Wallet bazi "
            f"— direktan dokaz korišćenja wallet-a, koristiti za korelaciju sa modulom 'blockchain'."
        )

    # shared_prefs konfiguracija
    prefs_dir = pkg_root / "shared_prefs"
    if prefs_dir.exists():
        for xml_file in prefs_dir.glob("*.xml"):
            try:
                content = xml_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in ADDR_RE.finditer(content):
                artifacts_list.append(artifact(
                    "crypto",
                    f"BRD shared_prefs adresa: {m.group(0)} ({xml_file.name})",
                    f"{pkg_rel}/shared_prefs/{xml_file.name}",
                    extra={"address": m.group(0), "wallet": "BRD", "source": "shared_prefs"},
                ))


def analyze(dump_path: str) -> dict:
    resolver = DumpResolver(dump_path)

    findings = []
    artifacts_list = []
    alerts = []

    _analyze_signal(resolver, findings, artifacts_list, alerts)
    _analyze_brd(resolver, findings, artifacts_list, alerts)

    signal_present = resolver.pkg_root(SIGNAL_PKG) is not None
    brd_present = resolver.pkg_root(BRD_PKG) is not None

    if not signal_present and not brd_present:
        return module_result(
            status="not_found",
            findings=findings + [finding("Status", "Ni Signal ni BRD Wallet nisu pronađeni u dump-u")],
            artifacts=[],
            alerts=[],
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
