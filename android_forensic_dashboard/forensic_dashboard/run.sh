#!/usr/bin/env bash
# Android Forensic Dashboard — pokretanje (Linux / macOS)
set -e
cd "$(dirname "$0")"

# Ollama server u pozadini (ako je instaliran i nije vec pokrenut)
if command -v ollama >/dev/null 2>&1; then
  (ollama serve >/dev/null 2>&1 &) || true
fi

open_browser() {
  sleep 3
  if command -v xdg-open >/dev/null 2>&1; then xdg-open "$1"
  elif command -v open >/dev/null 2>&1; then open "$1"; fi
}

if [ -f build/index.html ]; then
  # Frontend izgradjen -> backend servira i UI na jednom portu (8000)
  echo "Aplikacija: http://localhost:8000"
  open_browser "http://localhost:8000" &
  cd backend && exec python3 -m uvicorn main:app --port 8000
else
  # Dev mod
  echo "Frontend nije izgradjen - dev mod (http://localhost:3000)"
  ( cd backend && python3 -m uvicorn main:app --port 8000 & )
  open_browser "http://localhost:3000" &
  exec npm start
fi
