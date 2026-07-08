@echo off
setlocal enabledelayedexpansion
title Android Forensic Dashboard - Instalacija
cd /d "%~dp0"

echo ============================================================
echo    ANDROID FORENSIC DASHBOARD - Instalacija
echo ============================================================
echo.
echo Ovaj instaler ce proveriti i (po potrebi) preuzeti sve sto
echo je potrebno: Python, Node.js, Ollama + Qwen AI model, i sve
echo module aplikacije. Ne trebas rucno kopirati foldere.
echo.
pause

REM ---------- 1. Python ----------
echo.
echo [1/5] Provera Python 3.10+ ...
python --version >nul 2>&1
if errorlevel 1 (
    echo    Python NIJE pronadjen. Pokusavam automatsku instalaciju preko winget...
    winget install -e --id Python.Python.3.11 --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo    Automatska instalacija nije uspela.
        echo    Preuzmi Python 3.11 rucno: https://www.python.org/downloads/
        echo    VAZNO: pri instalaciji cekiraj "Add Python to PATH".
        start "" https://www.python.org/downloads/
        pause
        exit /b 1
    )
    echo    Python instaliran. Mozda ce trebati da ponovo pokrenes ovaj instaler.
) else (
    for /f "tokens=2" %%v in ('python --version 2^>^&1') do echo    Python %%v OK
)

REM ---------- 2. Node.js ----------
echo.
echo [2/5] Provera Node.js 18+ ...
node --version >nul 2>&1
if errorlevel 1 (
    echo    Node.js NIJE pronadjen. Pokusavam winget...
    winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo    Preuzmi Node.js LTS rucno: https://nodejs.org/
        start "" https://nodejs.org/
        pause
        exit /b 1
    )
) else (
    for /f %%v in ('node --version') do echo    Node %%v OK
)

REM ---------- 3. Ollama (opciono, za AI) ----------
echo.
echo [3/5] Provera Ollama (za AI forenzicki zakljucak) ...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo    Ollama NIJE pronadjen. Pokusavam winget...
    winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo    Preuzmi Ollama rucno: https://ollama.com
        echo    NAPOMENA: AI je OPCIONI - aplikacija radi i bez njega.
        start "" https://ollama.com
    )
) else (
    echo    Ollama OK
)

REM ---------- 4. Zavisnosti aplikacije ----------
echo.
echo [4/5] Instalacija Python i Node zavisnosti (moze potrajati par minuta) ...
pushd backend
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt
if errorlevel 1 ( echo    GRESKA pri pip install zavisnosti. & popd & pause & exit /b 1 )
popd
call npm install
if errorlevel 1 ( echo    GRESKA pri npm install. & pause & exit /b 1 )
echo    Gradim frontend (npm run build) ...
call npm run build
if errorlevel 1 ( echo    GRESKA pri npm run build. & pause & exit /b 1 )

REM ---------- 5. AI model (Qwen) ----------
echo.
echo [5/5] AI model (Qwen preko Ollama) ...
ollama --version >nul 2>&1
if not errorlevel 1 (
    echo.
    echo    Koji AI model da preuzmem?
    echo      [1] qwen3:32b   - najbolji, ~20 GB, trazi jacu masinu/GPU  ^(podrazumevano^)
    echo      [2] qwen2.5:7b  - laksi, ~5 GB, radi i na slabijim masinama
    echo      [3] preskoci    - podesicu kasnije rucno
    echo.
    set /p MODCHOICE="    Izbor (1/2/3): "
    if "!MODCHOICE!"=="2" (
        ollama pull qwen2.5:7b
        setx AI_MODEL "qwen2.5:7b" >nul
        echo    Postavljeno AI_MODEL=qwen2.5:7b
    ) else if "!MODCHOICE!"=="3" (
        echo    Preskacem preuzimanje modela. Kasnije: ollama pull qwen3:32b
    ) else (
        ollama pull qwen3:32b
    )
) else (
    echo    Ollama nije dostupan - preskacem AI model ^(aplikacija radi i bez AI-a^).
)

REM ---------- Precica na Desktop-u (ikonica aplikacije) ----------
echo.
echo    Kreiram precicu "Android Forensic Dashboard" na Desktop-u...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$d=[Environment]::GetFolderPath('Desktop'); $s=(New-Object -ComObject WScript.Shell).CreateShortcut($d+'\Android Forensic Dashboard.lnk'); $s.TargetPath='%~dp0run.bat'; $s.WorkingDirectory='%~dp0'; $s.IconLocation='%~dp0public\favicon.ico'; $s.Description='Android Forensic Dashboard'; $s.Save()" 2>nul
if exist "%USERPROFILE%\Desktop\Android Forensic Dashboard.lnk" (
    echo    Precica kreirana - dvoklik na nju pokrece aplikaciju.
) else (
    echo    Precicu nije bilo moguce kreirati automatski - koristi run.bat.
)

echo.
echo ============================================================
echo    INSTALACIJA ZAVRSENA!
echo    Pokreni aplikaciju: dvoklik na "Android Forensic Dashboard"
echo    ikonicu na Desktop-u  (ili run.bat u ovom folderu).
echo ============================================================
echo.
pause
