# Pravljenje MSI instalera

Ovim se pravi jedan **`AndroidForensicDashboard-Setup.msi`** koji korisniku
instalira aplikaciju kao pravu Windows aplikaciju — bez potrebe za Python-om
ili Node-om na njegovoj mašini.

## Preduslovi (samo na mašini koja PRAVI instaler)

| Alat | Za šta | Instalacija |
|------|--------|-------------|
| **Python 3.11** | PyInstaller pakovanje | python.org |
| **Node.js 18+** | build frontenda | nodejs.org |

> **Ne treba .NET SDK.** Instaler koristi **WiX 3** (binarni alati `heat`/`candle`/`light`)
> koji traže samo .NET Framework — a on postoji na svakom Windows-u. Build skripta
> sama preuzme WiX 3 sa GitHub-a (~3 MB) ako ga nema. PyInstaller se instalira iz `pip`-a.

## Pravljenje (jedan klik)

Iz korena projekta:

```
build_installer.bat
```

Skripta radi 5 koraka:
1. `npm install` + `npm run build` — gradi React frontend u `build/`
2. `pip install` backend zavisnosti + PyInstaller
3. `pyinstaller afd.spec` — pakuje backend + frontend u `dist/AndroidForensicDashboard/`
   (samostalni `.exe`, ~330 MB, ne treba Python/Node)
4. Preuzima **WiX 3** alate (ako fale) u `installer/wix3/`
5. `heat` (popiše sve fajlove) → `candle` (kompajlira) → `light` (poveže) →
   `dist\AndroidForensicDashboard-Setup.msi`

## Rezultat

`dist\AndroidForensicDashboard-Setup.msi` (~135 MB, CAB-kompresovan) — podeliš
**samo taj fajl**. Korisnik ga instalira dvoklikom; dobija:
- instalacioni **čarobnjak** (Dobrodošli → Licenca → Folder → Instaliraj)
- aplikaciju u `Program Files\Android Forensic Dashboard`
- **Desktop + Start Menu prečicu** (ikonica lupe)
- pravi **uninstaller** (Add/Remove Programs)

Pri pokretanju aplikacija otvara `http://127.0.0.1:8000`. Podaci slučajeva i
audit se čuvaju u `%LOCALAPPDATA%\AndroidForensicDashboard` (upisiv folder,
ne u Program Files).

> **Validacija MSI-ja bez instalacije:** `msiexec /a AndroidForensicDashboard-Setup.msi /qn TARGETDIR=%TEMP%\afd_test`
> raspakuje sadržaj bez izmena sistema (administrativna instalacija) — dobar način
> da se proveri da MSI sadrži `AndroidForensicDashboard.exe` i `_internal\build\`.

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

REM WiX 3 (jednom) — skini sa https://github.com/wixtoolset/wix3/releases u installer\wix3\
installer\wix3\heat.exe   dir dist\AndroidForensicDashboard -cg AppFiles -dr INSTALLFOLDER ^
                          -gg -g1 -sfrag -srd -sreg -scom -var var.SourceDir -out installer\AppFiles.wxs
installer\wix3\candle.exe -arch x64 "-dSourceDir=%CD%\dist\AndroidForensicDashboard" "-dProjectRoot=%CD%" ^
                          -out installer\obj\ installer\AFD.wxs installer\AppFiles.wxs
installer\wix3\light.exe  -ext WixUIExtension -out dist\AndroidForensicDashboard-Setup.msi ^
                          installer\obj\AFD.wixobj installer\obj\AppFiles.wixobj
```

## Fajlovi

| Fajl | Uloga |
|------|-------|
| `afd.spec` | PyInstaller recept (backend + `build/` + ikonica → samostalni exe) |
| `backend/app_desktop.py` | ulazna tačka (uvicorn + auto-otvaranje browsera, podaci u `%LOCALAPPDATA%`) |
| `installer/AFD.wxs` | WiX 3 izvor (čarobnjak, prečice, ikonica, uninstaller) |
| `installer/license.rtf` | tekst licence u čarobnjaku |
| `installer/AppFiles.wxs` | *generisano* (heat popiše svih ~3600 fajlova) — ne commit-uje se |
| `build_installer.bat` | sve gore, jednim klikom |
