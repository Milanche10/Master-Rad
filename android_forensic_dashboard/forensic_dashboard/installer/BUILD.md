# Pravljenje MSI instalera

Ovim se prави jedan **`AndroidForensicDashboard-Setup.msi`** koji korisniku
instalira aplikaciju kao pravu Windows aplikaciju — bez potrebe za Python-om
ili Node-om na njegovoj mašini.

## Preduslovi (samo na mašini koja PRAVI instaler)

| Alat | Za šta | Instalacija |
|------|--------|-------------|
| **Python 3.11** | PyInstaller pakovanje | python.org |
| **Node.js 18+** | build frontenda | nodejs.org |
| **.NET SDK 6+** | WiX Toolset | dotnet.microsoft.com/download |

PyInstaller i WiX se instaliraju automatski iz build skripte.

## Pravljenje (jedan klik)

Iz korena projekta:

```
build_installer.bat
```

Skripta radi 4 koraka:
1. `npm install` + `npm run build` — gradi React frontend u `build/`
2. `pip install` backend zavisnosti + PyInstaller
3. `pyinstaller afd.spec` — pakuje backend + frontend u `dist/AndroidForensicDashboard/`
   (samostalni `.exe`, ~330 MB, ne treba Python/Node)
4. `wix build installer\AFD.wxs` — pravi `dist\AndroidForensicDashboard-Setup.msi`

## Rezultat

`dist\AndroidForensicDashboard-Setup.msi` — podeliš **samo taj fajl**.
Korisnik ga instalira dvoklikom; dobija:
- aplikaciju u `Program Files\Android Forensic Dashboard`
- **Desktop + Start Menu prečicu** (ikonica lupe)
- pravi **uninstaller** (Add/Remove Programs)

Pri pokretanju aplikacija otvara `http://127.0.0.1:8000`. Podaci slučajeva i
audit se čuvaju u `%LOCALAPPDATA%\AndroidForensicDashboard` (upisiv folder,
ne u Program Files).

## AI (Ollama) — i dalje odvojeno

Ollama + Qwen model (~20 GB) se **ne pakuju** u MSI (preveliki + Ollama je
zasebna aplikacija). Korisnik jednom instalira Ollama sa <https://ollama.com>
i pokrene `ollama pull qwen3:32b` (ili lakši `qwen2.5:7b`). Bez toga cela
aplikacija radi normalno — samo AI zaključak prikaže uputstvo.

## Ručno (koraci pojedinačno)

```
npm install && npm run build
pip install -r backend\requirements.txt pyinstaller
pyinstaller afd.spec --noconfirm
dotnet tool install --global wix
wix build installer\AFD.wxs -o dist\AndroidForensicDashboard-Setup.msi
```
