"""
acquisition — Sloj akvizicije dokaza (Acquisition Layer)
────────────────────────────────────────────────────────
Prikuplja podatke iz različitih izvora (telefon/USB, SIM čitač, SD kartica,
USB fleš) i pakuje ih u Evidence/ strukturu koju POSTOJEĆI analitički engine
već očekuje. Analitički engine ostaje NETAKNUT — dobija samo putanju do
Evidence foldera i radi kao i do sada.

Ključno pravilo: nijedan izvor ne izmišlja podatke. Ako hardver/alat nije
prisutan (adb, PC/SC čitač, uklonjivi disk), akvizicija se gasi sa jasnom
greškom i logom — nikad lažni rezultat (forenzička validnost, chain of custody).
"""

from . import base, cases_fs, jobs  # noqa: F401
