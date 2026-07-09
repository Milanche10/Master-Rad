@echo off
setlocal enabledelayedexpansion
title AFD - Pravljenje MSI instalera
cd /d "%~dp0"
set "ROOT=%CD%"
set "DIST=%ROOT%\dist\AndroidForensicDashboard"
set "WIX=%ROOT%\installer\wix3"
set "OBJ=%ROOT%\installer\obj"

echo ============================================================
echo    Android Forensic Dashboard - Pravljenje MSI instalera
echo ============================================================
echo.
echo Preduslovi (jednom): Python 3.11 i Node.js.
echo WiX 3 se preuzima automatski (trazi samo .NET Framework
echo koji postoji na svakom Windows-u - NE .NET SDK).
echo.
pause

REM ---------- 1. Frontend build ----------
echo.
echo [1/5] Node zavisnosti + gradnja frontenda...
call npm install || ( echo GRESKA: npm install & pause & exit /b 1 )
call npm run build || ( echo GRESKA: npm run build & pause & exit /b 1 )

REM ---------- 2. Python + PyInstaller ----------
echo.
echo [2/5] Python zavisnosti + PyInstaller...
python -m pip install --upgrade pip -q
python -m pip install -r backend\requirements.txt -q || ( echo GRESKA: pip requirements & pause & exit /b 1 )
python -m pip install pyinstaller -q || ( echo GRESKA: pip pyinstaller & pause & exit /b 1 )

REM ---------- 2b. adb (Android platform-tools) — ugradi u instaler ----------
echo.
echo [2b] Preuzimanje adb (Android platform-tools) za ugradnju u instaler...
if not exist "%ROOT%\tools\platform-tools\adb.exe" (
    powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $global:ProgressPreference='SilentlyContinue'; New-Item -ItemType Directory -Force -Path '%ROOT%\tools' ^| Out-Null; Invoke-WebRequest -Uri 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip' -OutFile '%ROOT%\tools\pt.zip'; Expand-Archive -Path '%ROOT%\tools\pt.zip' -DestinationPath '%ROOT%\tools' -Force; Remove-Item '%ROOT%\tools\pt.zip'" ^
      || ( echo UPOZORENJE: adb nije preuzet - aplikacija ce ga skinuti sama pri prvom koriscenju. )
) else (
    echo    adb vec postoji, preskacem.
)

REM ---------- 3. Pakovanje aplikacije (samostalni .exe) ----------
echo.
echo [3/5] Pakovanje aplikacije (PyInstaller - moze potrajati)...
python -m PyInstaller afd.spec --noconfirm --distpath dist --workpath build_pyi ^
  || ( echo GRESKA: PyInstaller & pause & exit /b 1 )

REM ---------- 4. WiX 3 alati (preuzmi ako fale) ----------
echo.
echo [4/5] WiX 3 alati...
if not exist "%WIX%\candle.exe" (
    echo    Preuzimam WiX 3 binarne alate sa GitHub-a...
    powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $p='SilentlyContinue'; $global:ProgressPreference=$p; New-Item -ItemType Directory -Force -Path '%WIX%' ^| Out-Null; Invoke-WebRequest -Uri 'https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip' -OutFile '%WIX%\wix.zip'; Expand-Archive -Path '%WIX%\wix.zip' -DestinationPath '%WIX%' -Force; Remove-Item '%WIX%\wix.zip'" ^
      || ( echo GRESKA: preuzimanje WiX & pause & exit /b 1 )
)

REM ---------- 5. MSI: heat (harvest) -> candle (compile) -> light (link) ----------
echo.
echo [5/5] Pravljenje MSI...
if not exist "%OBJ%" mkdir "%OBJ%"
"%WIX%\heat.exe" dir "%DIST%" -cg AppFiles -dr INSTALLFOLDER -gg -g1 -sfrag -srd -sreg -scom ^
  -var var.SourceDir -out "installer\AppFiles.wxs" || ( echo GRESKA: heat & pause & exit /b 1 )
"%WIX%\candle.exe" -nologo -arch x64 "-dSourceDir=%DIST%" "-dProjectRoot=%ROOT%" ^
  -out "%OBJ%\AFD.wixobj" "installer\AFD.wxs" || ( echo GRESKA: candle AFD & pause & exit /b 1 )
"%WIX%\candle.exe" -nologo -arch x64 "-dSourceDir=%DIST%" "-dProjectRoot=%ROOT%" ^
  -out "%OBJ%\AppFiles.wixobj" "installer\AppFiles.wxs" || ( echo GRESKA: candle AppFiles & pause & exit /b 1 )
"%WIX%\light.exe" -nologo -ext WixUIExtension -sice:ICE61 -sice:ICE91 -spdb ^
  -out "dist\AndroidForensicDashboard-Setup.msi" ^
  "%OBJ%\AFD.wixobj" "%OBJ%\AppFiles.wixobj" || ( echo GRESKA: light & pause & exit /b 1 )

echo.
echo ============================================================
echo    GOTOVO!
echo    MSI instaler: dist\AndroidForensicDashboard-Setup.msi
echo    Podeli SAMO taj .msi - korisnik ga instalira dvoklikom.
echo ============================================================
echo.
pause
