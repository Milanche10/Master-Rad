@echo off
echo.
echo   Android Forensic Dashboard
echo   ─────────────────────────
echo.

echo   [1/2] Pokretanje backenda...
cd backend
pip install -r requirements.txt -q
start /B uvicorn main:app --port 8000
cd ..

timeout /t 2 /nobreak >nul
echo   Backend spreman na http://localhost:8000

echo   [2/2] Pokretanje frontenda...
call npm install --silent
start /B npm start

echo.
echo   Dashboard dostupan na http://localhost:3000
echo   Zatvori ovaj prozor za zaustavljanje
echo.
pause
