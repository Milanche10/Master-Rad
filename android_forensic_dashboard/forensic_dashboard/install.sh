#!/usr/bin/env bash
# Android Forensic Dashboard — instaler (Linux / macOS)
# Proverava i po potrebi preuzima: Python, Node, Ollama + Qwen, sve zavisnosti.
set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "   ANDROID FORENSIC DASHBOARD - Instalacija"
echo "============================================================"
echo

# Detektuj menadzer paketa
if command -v brew >/dev/null 2>&1; then PM="brew install"
elif command -v apt-get >/dev/null 2>&1; then PM="sudo apt-get install -y"
elif command -v dnf >/dev/null 2>&1; then PM="sudo dnf install -y"
elif command -v pacman >/dev/null 2>&1; then PM="sudo pacman -S --noconfirm"
else PM=""; fi

have() { command -v "$1" >/dev/null 2>&1; }

echo "[1/5] Python 3.10+ ..."
if ! have python3; then
  echo "   Python nije pronadjen."
  if [ -n "$PM" ]; then $PM python3 || { echo "   Instaliraj rucno: https://python.org"; exit 1; }
  else echo "   Instaliraj Python 3.11: https://python.org"; exit 1; fi
else echo "   $(python3 --version) OK"; fi

echo "[2/5] Node.js 18+ ..."
if ! have node; then
  echo "   Node nije pronadjen."
  if [ -n "$PM" ]; then $PM nodejs npm || { echo "   Instaliraj rucno: https://nodejs.org"; exit 1; }
  else echo "   Instaliraj Node LTS: https://nodejs.org"; exit 1; fi
else echo "   node $(node --version) OK"; fi

echo "[3/5] Ollama (za AI, opciono) ..."
if ! have ollama; then
  echo "   Ollama nije pronadjen. Pokusavam instalaciju (zvanicna skripta)..."
  curl -fsSL https://ollama.com/install.sh | sh || echo "   Preskacem (AI je opcioni). Rucno: https://ollama.com"
else echo "   Ollama OK"; fi

echo "[4/5] Zavisnosti aplikacije (moze potrajati) ..."
( cd backend && python3 -m pip install --upgrade pip -q && python3 -m pip install -r requirements.txt )
npm install
echo "   Gradim frontend (npm run build) ..."
npm run build

echo "[5/5] AI model (Qwen) ..."
if have ollama; then
  echo "     [1] qwen3:32b  (~20GB, jaca masina/GPU)  [podrazumevano]"
  echo "     [2] qwen2.5:7b (~5GB, slabije masine)"
  echo "     [3] preskoci"
  read -p "   Izbor (1/2/3): " M
  case "$M" in
    2) ollama pull qwen2.5:7b; echo 'export AI_MODEL="qwen2.5:7b"' >> "$HOME/.bashrc"; echo "   Postavljeno AI_MODEL=qwen2.5:7b (novi terminal)";;
    3) echo "   Preskacem. Kasnije: ollama pull qwen3:32b";;
    *) ollama pull qwen3:32b;;
  esac
else
  echo "   Ollama nedostupan - preskacem model (aplikacija radi i bez AI-a)."
fi

chmod +x run.sh 2>/dev/null || true
echo
echo "============================================================"
echo "   INSTALACIJA ZAVRSENA!  Pokreni: ./run.sh"
echo "============================================================"
