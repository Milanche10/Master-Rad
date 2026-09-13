"""
backends.py — Arhitektura backend-ova akvizicije (spec §11–16)
────────────────────────────────────────────────────────────────
Zajednički ABC + tri backend-a (Logical / File-System / Physical). Svaki:
  • detect(caps)  → da li je metoda dostupna + razlog (NEDESTRUKTIVNO),
  • acquire(...)  → pokreće akviziciju (delegira jedinstvenom orkestratoru
                    acquisition.phone.acquire_phone koji radi capability
                    validaciju, AUTO razrešenje i rutiranje po metodi).

Načelo poštenja (spec §16,§46): PhysicalAcquisitionBackend prijavljuje
AVAILABLE samo ako stvarno postoji podržan mehanizam — trenutno ga nema
(bez eksploita), pa je uvek UNAVAILABLE uz jasan razlog.
"""

from abc import ABC, abstractmethod

from . import capabilities


class AcquisitionBackend(ABC):
    method: str = ""
    label: str = ""

    @abstractmethod
    def detect(self, caps: dict) -> dict:
        """Vrati {'available': bool, 'reason': str} na osnovu sposobnosti uređaja."""
        ...

    @abstractmethod
    def acquire(self, progress, serial: str = "", examiner: str = "",
                device_info: dict = None) -> dict:
        ...


class LogicalAcquisitionBackend(AcquisitionBackend):
    method = capabilities.AcquisitionMethod.LOGICAL
    label = "Logical (ADB)"

    def detect(self, caps: dict) -> dict:
        return {"available": bool(caps.get("logical_available")),
                "reason": caps.get("logical_reason")}

    def acquire(self, progress, serial="", examiner="", device_info=None) -> dict:
        from . import phone
        return phone.acquire_phone(progress, serial=serial, examiner=examiner,
                                   device_info=device_info, method=self.method)


class FileSystemAcquisitionBackend(AcquisitionBackend):
    method = capabilities.AcquisitionMethod.FILE_SYSTEM
    label = "File System (root)"

    def detect(self, caps: dict) -> dict:
        return {"available": bool(caps.get("filesystem_available")),
                "reason": caps.get("filesystem_reason")}

    def acquire(self, progress, serial="", examiner="", device_info=None) -> dict:
        from . import phone
        return phone.acquire_phone(progress, serial=serial, examiner=examiner,
                                   device_info=device_info, method=self.method)


class PhysicalAcquisitionBackend(AcquisitionBackend):
    method = capabilities.AcquisitionMethod.PHYSICAL
    label = "Physical"

    def detect(self, caps: dict) -> dict:
        return {"available": bool(caps.get("physical_available")),
                "reason": caps.get("physical_reason")}

    def acquire(self, progress, serial="", examiner="", device_info=None) -> dict:
        # Nema podržanog mehanizma bez eksploita → nikad ne izvršava (spec §16).
        raise RuntimeError(
            "Fizička akvizicija nije podržana: nema podržanog backend-a za ovaj "
            "uređaj/konfiguraciju (bez eksploita/zaobilaženja zaštite).")


BACKENDS = {
    b.method: b for b in (
        LogicalAcquisitionBackend(),
        FileSystemAcquisitionBackend(),
        PhysicalAcquisitionBackend(),
    )
}

# Redosled za prikaz u UI (spec §6): Logical, File System, Physical.
_ORDER = [capabilities.AcquisitionMethod.LOGICAL,
          capabilities.AcquisitionMethod.FILE_SYSTEM,
          capabilities.AcquisitionMethod.PHYSICAL]


def list_methods(caps: dict) -> list:
    """
    Za UI: lista metoda sa dostupnošću i razlogom (nedostupne se onemogućuju,
    spec §6,§39). AUTO se dodaje kao poseban izbor ako postoji ijedna dostupna.
    """
    out = []
    for m in _ORDER:
        b = BACKENDS[m]
        d = b.detect(caps)
        out.append({"method": m, "label": b.label,
                    "available": d["available"], "reason": d.get("reason")})
    any_available = any(x["available"] for x in out)
    out.append({"method": capabilities.AcquisitionMethod.AUTO, "label": "Auto (najbolja dostupna)",
                "available": any_available,
                "reason": ("Bira najbolju dostupnu metodu." if any_available
                           else "Nema dostupne metode.")})
    return out
