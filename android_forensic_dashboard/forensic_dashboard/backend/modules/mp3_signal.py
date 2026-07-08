"""
modules/mp3_signal.py
───────────────────────
Analiza audio fajlova (MP3/WAV/AMR/OGG) radi detekcije steganografije
ili "signal" pattern-a (npr. audio fajl korišćen kao nosač skrivenih
podataka u kriminalnoj komunikaciji):

  - Mutagen metapodaci: trajanje, bitrate, codec
  - Poređenje očekivane veličine fajla (bitrate × trajanje) sa stvarnom
    veličinom — značajan višak ukazuje na dodate (appended) podatke
  - Shannon entropija poslednjeg bloka fajla — visoka entropija nakon
    audio stream-a ukazuje na enkriptovani/skriveni payload
  - Detekcija fajlova sa audio ekstenzijom ali bez validnih audio
    zaglavlja (npr. .mp3 koji je u stvari arhiva ili binarni blob)
"""

from pathlib import Path

from utils.dump_resolver import DumpResolver
from utils.helpers import artifact, finding, module_result, shannon_entropy

AUDIO_EXTENSIONS = {".mp3", ".wav", ".amr", ".ogg", ".m4a", ".flac"}
SEARCH_DIRS = [
    "data/media/0/Music",
    "data/media/0/Download",
    "data/media/0/Recordings",
    "data/media/0/WhatsApp/Media/WhatsApp Audio",
    "data/media/0/Notifications",
]
MAX_FILES = 200
TAIL_SIZE = 4096          # poslednjih N bajtova za entropy analizu
ENTROPY_THRESHOLD = 7.5    # blizu max 8.0 = praktično random podaci
SIZE_OVERHEAD_THRESHOLD = 0.15  # >15% veći nego očekivano = sumnjivo


def _expected_size_bytes(duration_sec: float, bitrate_bps: int) -> int:
    if not duration_sec or not bitrate_bps:
        return 0
    return int((bitrate_bps / 8) * duration_sec)


def analyze(dump_path: str) -> dict:
    try:
        import mutagen
    except ImportError:
        return module_result(
            status="error",
            findings=[finding("Greška", "mutagen nije instaliran — 'pip install mutagen'")],
            artifacts=[],
            alerts=[],
            error="mutagen not installed",
        )

    resolver = DumpResolver(dump_path)

    audio_files: list[Path] = []
    for rel_dir in SEARCH_DIRS:
        full_dir = resolver.root / rel_dir
        if full_dir.exists():
            for f in full_dir.rglob("*"):
                if f.is_file() and f.suffix.lower() in AUDIO_EXTENSIONS:
                    audio_files.append(f)

    if not audio_files:
        return module_result(
            status="not_found",
            findings=[finding("Status", "Nisu pronađeni audio fajlovi u Music/Download/Recordings")],
            artifacts=[],
            alerts=[],
        )

    truncated = len(audio_files) > MAX_FILES
    audio_files = audio_files[:MAX_FILES]

    findings = [finding("Analiziranih audio fajlova", str(len(audio_files)) + (" (ograničeno)" if truncated else ""))]
    artifacts_list = []
    alerts = []

    suspicious_count = 0
    unreadable_count = 0

    for f in audio_files:
        rel_path = str(f.relative_to(resolver.root)) if resolver.root in f.parents else str(f)
        actual_size = f.stat().st_size

        try:
            meta = mutagen.File(f)
        except Exception:
            meta = None

        if meta is None or meta.info is None:
            unreadable_count += 1
            artifacts_list.append(artifact(
                "media",
                f"⚠ {f.name} — audio metapodaci nisu pročitani (mogući lažni/oštećen format)",
                rel_path,
                extra={"filename": f.name, "size_bytes": actual_size, "unreadable": True},
            ))
            continue

        duration = getattr(meta.info, "length", 0) or 0
        bitrate = getattr(meta.info, "bitrate", 0) or 0
        expected_size = _expected_size_bytes(duration, bitrate)

        # ── Entropija tail-a ────────────────────────────────────────────
        try:
            with open(f, "rb") as fh:
                if actual_size > TAIL_SIZE:
                    fh.seek(-TAIL_SIZE, 2)
                tail = fh.read(TAIL_SIZE)
            tail_entropy = round(shannon_entropy(tail), 3)
        except Exception:
            tail_entropy = 0.0

        size_overhead = 0.0
        if expected_size > 0:
            size_overhead = (actual_size - expected_size) / expected_size

        flags = []
        if expected_size > 0 and size_overhead > SIZE_OVERHEAD_THRESHOLD:
            flags.append(f"VIŠAK PODATAKA +{size_overhead*100:.0f}% u odnosu na očekivanu veličinu")
        if tail_entropy >= ENTROPY_THRESHOLD:
            flags.append(f"VISOKA ENTROPIJA na kraju fajla ({tail_entropy}/8.0)")

        value = f"{f.name} — {duration:.1f}s, {bitrate//1000 if bitrate else '?'}kbps, {actual_size//1024}KB"
        if flags:
            value += f" [{'; '.join(flags)}]"
            suspicious_count += 1
            alerts.append(
                f"Audio fajl '{f.name}' pokazuje indikatore steganografije: {'; '.join(flags)}."
            )

        artifacts_list.append(artifact(
            "media",
            value,
            rel_path,
            extra={
                "filename": f.name,
                "duration_sec": round(duration, 2),
                "bitrate_bps": bitrate,
                "size_bytes": actual_size,
                "expected_size_bytes": expected_size,
                "size_overhead_pct": round(size_overhead * 100, 1),
                "tail_entropy": tail_entropy,
                "suspicious": bool(flags),
            },
        ))

    findings += [
        finding("Sumnjivi audio fajlovi (mogući stego)", str(suspicious_count)),
        finding("Fajlovi sa nečitljivim audio zaglavljem", str(unreadable_count)),
    ]

    if unreadable_count > 0:
        alerts.append(
            f"{unreadable_count} fajl(ova) sa audio ekstenzijom nema validno audio zaglavlje — "
            f"mogući binarni podaci maskirani kao audio."
        )

    return module_result(
        status="completed",
        findings=findings,
        artifacts=artifacts_list,
        alerts=alerts,
    )
