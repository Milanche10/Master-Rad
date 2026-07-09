@echo off
setlocal enabledelayedexpansion
title AFD - Pravljenje MSI instalera
cd /d "%~dp0"

echo ============================================================
echo    Android Forensic Dashboard - Pravljenje MSI instalera
echo ============================================================
echo.
echo Preduslovi (jednom): Python 3.11, Node.js, .NET SDK.
echo Skripta sve ostalo (PyInstaller, WiX) instalira sama.
echo.
pause

REM ---------- 1. Frontend build ----------
echo.
echo [1/4] Node zavisnosti + gradnja frontenda...
call npm install || ( echo GRESKA: npm install & pause & exit /b 1 )
call npm run build || ( echo GRESKA: npm run build & pause & exit /b 1 )

REM ---------- 2. Python + PyInstaller ----------
echo.
echo [2/4] Python zavisnosti + PyInstaller...
python -m pip install --upgrade pip -q
python -m pip install -r backend\requirements.txt -q || ( echo GRESKA: pip requirements & pause & exit /b 1 )
python -m pip install pyinstaller -q || ( echo GRESKA: pip pyinstaller & pause & exit /b 1 )

REM ---------- 3. Pakovanje aplikacije (samostalni .exe) ----------
echo.
echo [3/4] Pakovanje aplikacije (PyInstaller - moze potrajati)...
python -m PyInstaller afd.spec --noconfirm --distpath dist --workpath build_pyi ^
  || ( echo GRESKA: PyInstaller & pause & exit /b 1 )

REM ---------- 4. MSI (WiX) ----------
echo.
echo [4/4] Pravljenje MSI (WiX Toolset)...
where wix >nul 2>&1
if errorlevel 1 (
    where dotnet >nul 2>&1
    if errorlevel 1 (
        echo    .NET SDK nije pronadjen - potreban je za WiX.
        echo    Instaliraj: https://dotnet.microsoft.com/download  pa ponovo pokreni.
        start "" https://dotnet.microsoft.com/download
        pause
        exit /b 1
    )
    echo    Instaliram WiX Toolset (dotnet tool)...
    dotnet tool install --global wix || ( echo GRESKA: instalacija WiX & pause & exit /b 1 )
    set "PATH=%PATH%;%USERPROFILE%\.dotnet\tools"
)

wix build installer\AFD.wxs -o dist\AndroidForensicDashboard-Setup.msi ^
  || ( echo GRESKA: WiX build & pause & exit /b 1 )

echo.
echo ============================================================
echo    GOTOVO!
echo    MSI instaler: dist\AndroidForensicDashboard-Setup.msi
echo    Podeli SAMO taj .msi - korisnik ga instalira dvoklikom.
echo ============================================================
echo.
pause
