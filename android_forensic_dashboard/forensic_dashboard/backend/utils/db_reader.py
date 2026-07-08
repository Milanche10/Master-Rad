"""
db_reader.py
────────────
Siguran read-only pristup SQLite bazama iz Android dump-a.
Podržava WAL (Write-Ahead Log) fajlove i journal fajlove.
Nikad ne modifikuje originalnu bazu.
"""

import sqlite3
import shutil
import tempfile
import os
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SafeDBReader:
    """
    Context manager koji otvara SQLite bazu u read-only modu.
    Ako je baza zaključana (WAL fajl), pravi privremenu kopiju.

    Upotreba:
        with SafeDBReader("/path/to/mmssms.db") as db:
            rows = db.query("SELECT * FROM sms LIMIT 10")
    """

    def __init__(self, db_path: Path, copy_if_locked: bool = True):
        self.db_path = Path(db_path)
        self.copy_if_locked = copy_if_locked
        self._conn: Optional[sqlite3.Connection] = None
        self._tmp_dir: Optional[str] = None
        self._working_path: Optional[Path] = None

    def __enter__(self) -> "SafeDBReader":
        self._working_path = self.db_path

        # Ako postoji WAL fajl, SQLite je bio aktivan – kopiraj da bi mogao pročitati
        wal_path = Path(str(self.db_path) + "-wal")
        shm_path = Path(str(self.db_path) + "-shm")

        if wal_path.exists() and self.copy_if_locked:
            self._tmp_dir = tempfile.mkdtemp(prefix="forensic_db_")
            tmp_db = Path(self._tmp_dir) / self.db_path.name
            shutil.copy2(self.db_path, tmp_db)
            if wal_path.exists():
                shutil.copy2(wal_path, Path(self._tmp_dir) / wal_path.name)
            if shm_path.exists():
                shutil.copy2(shm_path, Path(self._tmp_dir) / shm_path.name)
            self._working_path = tmp_db
            logger.debug(f"WAL detected, working from temp copy: {tmp_db}")

        # Otvori u read-only URI modu
        uri = f"file:{self._working_path}?mode=ro"
        try:
            self._conn = sqlite3.connect(uri, uri=True)
            self._conn.row_factory = sqlite3.Row  # pristup kolonama po imenu
            # Postavi read-only PRAGMA
            self._conn.execute("PRAGMA query_only = ON")
            self._conn.execute("PRAGMA journal_mode = OFF")
        except sqlite3.OperationalError as e:
            # Ako read-only URI ne radi (stari SQLite), otvori normalno
            logger.warning(f"URI mode failed ({e}), falling back to standard open")
            self._conn = sqlite3.connect(str(self._working_path))
            self._conn.row_factory = sqlite3.Row

        return self

    def __exit__(self, *args):
        if self._conn:
            self._conn.close()
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        """Izvrši SELECT i vrati listu dict-ova. (Tolerantna verzija — vraća [] na grešci.)"""
        if not self._conn:
            raise RuntimeError("DB not open")
        try:
            cur = self._conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Query failed: {sql[:80]} → {e}")
            return []

    def query_strict(self, sql: str, params: tuple = ()) -> list[dict]:
        """
        Kao query() ali DIŽE grešku umesto da je tiho proguta. Za forenzički
        kritične upite (freelist, integrity, rowid) gde tiho [] = gubitak dokaza.
        """
        if not self._conn:
            raise RuntimeError("DB not open")
        cur = self._conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def iter_query(self, sql: str, params: tuple = (), batch: int = 1000):
        """
        Memorijski-bezbedan streaming velikih tabela: fetchmany umesto fetchall.
        Ne učitava celu tabelu u RAM. Generator dict-ova.
        """
        if not self._conn:
            raise RuntimeError("DB not open")
        cur = self._conn.execute(sql, params)
        while True:
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for row in rows:
                yield dict(row)

    def row_count(self, table: str) -> int:
        try:
            return self.query_strict(f'SELECT COUNT(*) c FROM "{table}"')[0]["c"]
        except Exception:
            return -1

    def max_rowid(self, table: str) -> int:
        """Najveći rowid — poređenje sa row_count otkriva obrisane redove (gaps)."""
        try:
            r = self.query_strict(f'SELECT MAX(rowid) m FROM "{table}"')
            return r[0]["m"] if r and r[0]["m"] is not None else 0
        except Exception:
            return 0

    def freelist_count(self) -> int:
        """Broj slobodnih stranica (obrisani sadržaj) — indikator brisanja."""
        try:
            return self.query_strict("PRAGMA freelist_count")[0].get("freelist_count", 0)
        except Exception:
            try:
                cur = self._conn.execute("PRAGMA freelist_count")
                return cur.fetchone()[0]
            except Exception:
                return -1

    def wal_frame_count(self) -> int:
        """Grubi broj WAL frame-ova (nepreuzeti obrisani/izmenjeni redovi)."""
        wal = Path(str(self.db_path) + "-wal")
        try:
            if wal.exists():
                size = wal.stat().st_size
                # WAL header 32B, svaki frame = 24B header + page_size (obično 4096)
                return max(0, (size - 32) // (24 + 4096))
        except Exception:
            pass
        return 0

    def tables(self) -> list[str]:
        """Vrati listu tabela u bazi."""
        rows = self.query("SELECT name FROM sqlite_master WHERE type='table'")
        return [r["name"] for r in rows]

    def columns(self, table: str) -> list[str]:
        """Vrati listu kolona za datu tabelu."""
        rows = self.query(f"PRAGMA table_info({table})")
        return [r["name"] for r in rows]

    def count(self, table: str) -> int:
        """Broj redova u tabeli."""
        rows = self.query(f"SELECT COUNT(*) as cnt FROM {table}")
        return rows[0]["cnt"] if rows else 0


def open_db(db_path: Path) -> Optional[SafeDBReader]:
    """
    Factory funkcija – vrati SafeDBReader ili None ako fajl ne postoji.
    """
    if not db_path or not db_path.exists():
        return None
    return SafeDBReader(db_path)
