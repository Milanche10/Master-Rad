#!/usr/bin/env bash
set -e

echo ""
echo "  Android Forensic Dashboard"
echo "  ─────────────────────────"
echo ""

# Backend
echo "  [1/2] Pokretanje backenda..."
cd backend
pip install -r requirements.txt -q
uvicorn main:app --port 8000 &
BACKEND_PID=$!
cd ..

# Čekaj da backend krene
sleep 2
echo "  Backend spreman na http://localhost:8000"

# Frontend
echo "  [2/2] Pokretanje frontenda..."
npm install --silent
npm start &
FRONTEND_PID=$!

echo ""
echo "  ✓ Dashboard dostupan na http://localhost:3000"
echo "  Ctrl+C za zaustavljanje"
echo ""

# Čekaj na signal za gašenje
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo '  Zaustavljeno.'; exit 0" SIGINT SIGTERM
wait
