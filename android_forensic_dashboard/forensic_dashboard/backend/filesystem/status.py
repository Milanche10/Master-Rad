"""
status.py — status akvizicije po fajlu i po lokaciji (spec §9) + metapodaci (spec §10)
"""

from dataclasses import dataclass, asdict


class FileStatus(str):
    ACQUIRED = "ACQUIRED"
    SKIPPED = "SKIPPED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NOT_PRESENT = "NOT_PRESENT"
    NOT_MOUNTED = "NOT_MOUNTED"
    ENCRYPTED = "ENCRYPTED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class LocationStatus(str):
    AVAILABLE = "AVAILABLE"
    NOT_PRESENT = "NOT_PRESENT"
    NOT_MOUNTED = "NOT_MOUNTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    ENCRYPTED = "ENCRYPTED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class FileStat:
    """Metapodaci jednog entry-ja sa uređaja (spec §10). Ništa se ne izmišlja —
    polja koja filesystem/uređaj ne daju ostaju None."""
    path: str
    entry_type: str = "file"        # file | dir | link | other
    size: int | None = None
    mode: str | None = None         # oktalne dozvole (npr. '660')
    uid: str | None = None
    gid: str | None = None
    inode: str | None = None
    mtime: str | None = None        # ISO 8601 UTC
    atime: str | None = None
    ctime: str | None = None
    link_target: str | None = None
    readable: bool = True

    def to_dict(self):
        return asdict(self)
