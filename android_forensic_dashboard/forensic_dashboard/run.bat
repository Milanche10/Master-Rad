@echo off
title Android Forensic Dashboard
cd /d "%~dp0"

echo Pokretanje Android Forensic Dashboard...
echo.

REM Pokreni Ollama server u pozadini (ako je instaliran)
where ollama >nul 2>&1
if not errorlevel 1 (
    start "" /B ollama serve >nul 2>&1
)

if exist "build\index.html" (
    REM Frontend je izgradjen -> backend servira i UI na jednom portu
    echo Aplikacija ce se otvoriti na: http://localhost:8000
    start "" /B cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:8000"
    pushd backend
    python -m uvicorn main:app --port 8000
    popd
) else (
    REM Dev mod: backend + npm start
    echo Frontend nije izgradjen - dev mod ^(http://localhost:3000^)
    pushd backend
    start "" /B python -m uvicorn main:app --port 8000
    popd
    start "" /B cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:3000"
    call npm start
)
