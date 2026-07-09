# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec za Android Forensic Dashboard.
# Pakuje backend (Python + sve zavisnosti) + izgrađen React frontend (build/)
# u samostalnu aplikaciju — korisniku NE treba Python ni Node.
#
# Build:  pyinstaller afd.spec   (iz korena projekta, posle 'npm run build')
# Rezultat: dist/AndroidForensicDashboard/  (onedir; WiX ga pakuje u .msi)

import os
from PyInstaller.utils.hooks import collect_all, collect_submodules

ROOT = os.path.abspath(os.getcwd())

# Frontend build ide u paket kao 'build/'
datas = [(os.path.join(ROOT, "build"), "build")]
binaries = []

# adb (Android platform-tools) se UGRAĐUJE u instaler ako je preuzet u
# tools/platform-tools (build_installer.bat ga skine pre pakovanja) → akvizicija
# telefona radi odmah, offline, bez ručne instalacije. Ako ga nema, aplikacija
# ga preuzme sama pri prvom korišćenju (provisioning.ensure_adb).
_platform_tools = os.path.join(ROOT, "tools", "platform-tools")
if os.path.isdir(_platform_tools):
    datas.append((_platform_tools, os.path.join("tools", "platform-tools")))
hiddenimports = collect_submodules("uvicorn") + [
    "PIL", "PIL.Image", "PIL.ExifTags",
    "mutagen", "mutagen.mp4",
    "reportlab", "reportlab.pdfbase", "reportlab.pdfbase.ttfonts",
    "docx", "requests", "sqlite3", "anyio", "starlette", "email_validator",
    # Acquisition/export slojevi — phone.py i sim.py se lenjivo uvoze (unutar
    # funkcija), pa ih PyInstaller statička analiza ne bi sama uhvatila.
    "acquisition", "acquisition.base", "acquisition.cases_fs", "acquisition.jobs",
    "acquisition.detect", "acquisition.storage", "acquisition.phone", "acquisition.sim",
    "export", "export.exporters", "export.packager",
    "tarfile", "zipfile", "csv",
]

# Teški paketi sa dinamičkim importima / data fajlovima
for pkg in ("androguard", "cv2"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

a = Analysis(
    ["backend/app_desktop.py"],
    pathex=["backend"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AndroidForensicDashboard",
    debug=False,
    strip=False,
    upx=False,
    console=True,               # konzolni prozor (log + zaustavljanje zatvaranjem)
    icon="public/favicon.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="AndroidForensicDashboard",
)
