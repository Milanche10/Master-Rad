"""
filesystem — Android File System Acquisition (nova metoda oko postojeće aplikacije)
──────────────────────────────────────────────────────────────────────────────────
Dodaje stvarnu file-system akviziciju kao ZASEBAN mode za Android telefon, bez
diranja postojećih (Logical / SD / USB / dump import). Reutilizuje postojeći ADB
transport (acquisition.detect), hashing/manifest (acquisition.base), storage
(acquisition.cases_fs) i analizu (DumpResolver čita rezultujući Android-FS raspored).

Ključni sloj apstrakcije (spec §6): pristup filesystem-u je iza interfejsa
IFileSystemAccess, sa implementacijama:
  • AdbFileSystemAccess         — ono što adb daje bez root-a (npr. /sdcard),
  • PrivilegedFileSystemAccess  — pun /data kada je root LEGITIMNO prisutan (su),
  • MockFileSystemAccess        — za testove (simulira uređaj: denied/link/encrypted…).

Ništa se ne izmišlja: svaki fajl/lokacija dobija stvarni STATUS
(ACQUIRED/PERMISSION_DENIED/NOT_PRESENT/ENCRYPTED/…).
"""

from . import status, access, fs_acquire  # noqa: F401
