"""
provisioning — automatsko obezbeđivanje runtime zavisnosti
───────────────────────────────────────────────────────────
Aplikacija sama preuzme i instalira ono što joj treba, da korisnik NE mora ništa
ručno da instalira:
  • adb (Android platform-tools)  → akvizicija telefona (mali paket, ~15 MB, auto)
  • Ollama + AI model             → AI zaključak (veliko, GB; na izričit zahtev)

Sve lokalno; jedini odlazak na internet je preuzimanje zvaničnih paketa
(Google platform-tools, Ollama). Ništa se od korisničkih podataka ne šalje.
"""

from . import provision  # noqa: F401
