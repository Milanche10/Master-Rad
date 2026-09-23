"""
imaging — Faza 4: analiza sirovih forenzičkih imidža (The Sleuth Kit / pytsk3)
──────────────────────────────────────────────────────────────────────────────
Fizička akvizicija ('dd') daje sirov imidž particije (npr. userdata.img). Ovaj
sloj ga PARSIRA preko pytsk3 (Python binding za The Sleuth Kit): pronalazi
filesystem(e), rekurzivno vadi fajlove (uklj. OBRISANE/unallocated) u Android-FS
raspored koji postojeći DumpResolver/analitički engine čita — bez novog analysis
engine-a (spec §17,§18). pytsk3 je opcion: ako nije instaliran, sloj se gasi uz
jasnu poruku (ostatak aplikacije radi).
"""

from . import image_parser  # noqa: F401
