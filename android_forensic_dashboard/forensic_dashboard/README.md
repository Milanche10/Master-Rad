# Android Forensic Dashboard (AFD)

Lokalni DFIR portal za forenzičku analizu Android filesystem dump-ova (ADB backup,
fizička ekstrakcija, TWRP/Magisk `dd` image, Cellebrite/MOBILedit izlaz i sl.).

Aplikacija objedinjuje **17 analitičkih modula** u jedan dashboard, automatski
**ukršta nalaze između modula** (korelacije sa numeričkim skorom 0–100),
gradi **hronološku vremensku liniju**, detektuje **anti-forenzičke tragove**,
pokušava **oporavak obrisanih podataka**, pruža **galeriju slika po albumima**,
izvlači **poruke iz aplikacija** (WhatsApp, Viber, Telegram, Signal, Instagram…),
**beleške i podsetnike**, i generiše **forenzički izveštaj** (tekst / PDF /
Word / HTML) uz opcioni **AI zaključak preko lokalnog modela**.

Pored analize, aplikacija sada **akvizira dokaze** iz više izvora (telefon preko
USB/adb, SIM čitač, SD kartica, USB fleš, ili postojeći dump) i svaki rezultat
**izvozi** u PDF / Word / HTML / TXT — kroz jedan objedinjeni forenzički tok.

Sve radi **lokalno i offline** — nijedan podatak ne napušta mašinu (bitno za
poverljivost i lanac nadležnosti). Aplikacija **ne menja originalne fajlove** —
sve čitanje je read-only (SQLite baze se otvaraju preko `file:...?mode=ro`, WAL
fajlovi se kopiraju u privremeni fajl pre čitanja; akvizicija samo čita izvor).

---

## Akvizicija dokaza (Acquisition Layer)

Na startu aplikacija otvara **čarobnjak za akviziciju** — izabereš ime veštaka
(chain of custody) i izvor dokaza:

| Izvor | Šta radi | Zahtev |
|-------|----------|--------|
| **📱 Mobilni telefon** | logička akvizicija preko `adb` (korisničko skladište `/sdcard`, `build.prop` iz `getprop`, lista paketa) **ili** analiza postojećeg dump-a | `adb` (Android platform-tools) na PATH + USB debugging |
| **📶 SIM kartica** | ICCID, IMSI, operater, MCC/MNC, kontakti (ADN), SMS — preko PC/SC APDU | `pyscard` + USB SIM čitač |
| **💾 SD kartica** | puna akvizicija svih fajlova uz očuvanje strukture i vremena | čitač (uklonjivi disk) |
| **🔌 USB fleš** | puna akvizicija svih fajlova uz očuvanje strukture i vremena | — |
| **📁 Postojeći dump** | otvori već napravljen Evidence/dump folder | — |

Svaka akvizicija pravi **forenzički slučaj na disku** (`Case_YYYY_NNNN/` sa
`Evidence/`, `Analysis/`, `Reports/`, `Exports/`, `Logs/`), računa **MD5 + SHA-1
+ SHA-256** svakog fajla u **manifest** (integritet svakog dokaza), i vodi
**log akvizicije**. Po završetku, `Evidence/` folder se prosleđuje **postojećem
analitičkom engine-u** — korisnik ne primeti razliku između ručnog dump-a i
uređaja akviziranog preko USB-a.

> **Pošteno (forenzička validnost):** ako alat/hardver nije prisutan (`adb`,
> SIM čitač, uklonjivi disk), akvizicija se gasi sa jasnom porukom — **nikad
> lažni podatak**. Bez root-a se sa telefona ne mogu izvući privatni podaci
> aplikacija (`/data/data`) ni IMEI (modem/EFS); to se jasno navodi.

## Univerzalni izvoz (Reporting & Export Layer)

**Svaki** prikaz se izvozi u **PDF / Word (.docx) / HTML / TXT** preko trake za
izvoz na vrhu svakog taba: Pregled, Timeline, Korelacije, **Evidence pregled**,
pojedinačni artefakt, i pun izveštaj. Ceo slučaj se preuzima kao **.zip paket**
(Evidence + Reports u sva 4 formata + Logs). SIM/SD/USB imaju i **namenske
izveštaje** (SIM identitet, manifest fajlova, statistika akvizicije).

---

## Preduslovi

| Alat | Verzija | Za šta |
|------|---------|--------|
| **Python** | 3.10+ (preporučeno 3.11) | backend (analiza) |
| **Node.js + npm** | 18+ | frontend (dashboard) |
| **Ollama** | najnovija | AI forenzički zaključak (opciono) |

> Backend automatski instalira sve Python zavisnosti (uklj. `opencv` za QR
> kripto adrese, `pillow`/`mutagen` za slike/video, `reportlab`/`python-docx`
> za PDF/Word) iz `backend/requirements.txt`.

---

## 1. Instalacija AI modela (Ollama + Qwen)

AI zaključak koristi **lokalni** open-source model preko Ollama-e. Bez ovoga
aplikacija radi normalno — samo dugme „🧠 AI Zaključak" neće raditi dok ne
podesiš model.

### Najlakše — jednim klikom iz aplikacije (preporučeno)

U aplikaciji otvori **⚙ Zavisnosti / Setup** (u sidebar-u ili na startnom
ekranu) i klikni **„Instaliraj AI (Ollama + model)"**. Aplikacija **sama**
preuzme i instalira Ollama i povuče model — bez ručnog rada. Isto važi i za
**adb** (dugme „Instaliraj adb"), ako ga instaler nije već ugradio.

> ⚠ AI model je **velik** (GB); preuzimanje može dugo trajati. adb je mali (~15 MB).

### Ručno (alternativa)

1. Preuzmi i instaliraj **Ollama**: <https://ollama.com>  (Windows/macOS/Linux)
2. U terminalu pokreni server (na Windows-u se pokreće sam posle instalacije):
   ```
   ollama serve
   ```
3. Preuzmi model **Qwen** (podrazumevani model aplikacije):
   ```
   ollama pull qwen3:32b
   ```

> ⚠️ `qwen3:32b` je velik model (~20 GB, traži jaču mašinu / GPU sa ~24 GB).
> **Za slabije računare** preuzmi lakši model i reci aplikaciji da ga koristi:
> ```
> ollama pull qwen2.5:7b
> ```
> pa postavi promenljivu okruženja pre pokretanja backenda:
> ```
> # Windows (PowerShell)
> setx AI_MODEL "qwen2.5:7b"
> # Linux/macOS
> export AI_MODEL="qwen2.5:7b"
> ```
> Podržani su i `llama3.1`, `gemma2` i drugi Ollama modeli.

---

## 2. Instalacija i pokretanje

### Preporučeno — instaler (jednim klikom)

Instaler sam proveri i (po potrebi) preuzme **sve** — Python, Node.js, Ollama,
Qwen model i sve zavisnosti aplikacije. Ne moraš ručno ništa kopirati.

**Windows:**
1. Dvoklik na **`install.bat`** (prati uputstva, izabereš AI model)
2. Instaler napravi **ikonicu na Desktop-u** — dvoklik na
   „Android Forensic Dashboard" pokreće aplikaciju (ili `run.bat`)

**Linux / macOS:**
```
./install.sh      # jednom, instalira sve
./run.sh          # svaki put za pokretanje
```

Aplikacija se otvara na **<http://localhost:8000>** (backend servira i UI kao
jedan proces).

### Napredno — ručno

```
# backend
cd backend && pip install -r requirements.txt && cd ..
# frontend (produkciona verzija koju servira backend)
npm install && npm run build
# pokretanje (jedan proces, UI + API na :8000)
cd backend && uvicorn main:app --port 8000
```

> Dev mod (hot-reload, dva porta): `start.bat` / `start.sh` — pokreće backend
> na `:8000` i React dev server na `:3000`.

### Distribucija kao MSI (jedan fajl, turnkey — bez ručnih instalacija)

Za deljenje kao prava Windows aplikacija: `build_installer.bat` upakuje sve
(PyInstaller → samostalni `.exe`, pa WiX 3 → MSI) u
**`AndroidForensicDashboard-Setup.msi`** (~135 MB). Korisnik dobija **samo taj
jedan `.msi`**, instalira ga dvoklikom kroz čarobnjak → aplikacija u Program
Files + **Desktop/Start Menu prečica** + uninstaller.

**Korisnik NE instalira ništa ručno:**
- **Python, Node, sav app kod** — ugrađeni u `.exe` (PyInstaller).
- **adb** (za telefon) — **ugrađen u instaler** (build ga preuzme). Ako fali,
  aplikacija ga **skine sama** pri prvom korišćenju.
- **Ollama + AI model** (veliko, GB) — ne pakuje se u MSI, ali aplikacija ga
  **instalira jednim klikom** iz **⚙ Zavisnosti / Setup** (vidi sekciju 1).

> Za **pravljenje** MSI-ja dovoljni su Python 3.11 i Node.js — **.NET SDK nije
> potreban** (WiX 3 alate skripta sama preuzme; oni traže samo .NET Framework
> koji je već na svakom Windows-u). Detalji: [installer/BUILD.md](installer/BUILD.md).

---

## 3. Korišćenje

1. Na startu izabereš **izvor dokaza** u čarobnjaku (telefon / SIM / SD / USB /
   postojeći dump) i uneseš ime veštaka. Za akviziciju sačekaš da se završi, pa
   klikneš **Analiziraj dokaze**; za postojeći dump uneseš putanju.
2. Klikni **Pokreni sve module** (ili pojedinačno u levom meniju).
3. Pregledaj rezultate kroz tabove (svaki ima traku za **izvoz** PDF/Word/HTML/TXT):
   - **Pregled** — rezime, uređaj, broj artefakata/upozorenja
   - **Korelacije** — ukrštanja između izvora sa skorom i citiranim dokazima
   - **Timeline** — hronologija (glavni događaji / detaljno)
   - **Evidence pregled** — svi artefakti u jednoj tabeli: pretraga, filteri,
     izbor i izvoz pojedinačnih dokaza
   - **Galerija** — sve slike i snimci **grupisano po albumima** (Camera,
     Screenshots, Instagram, WhatsApp…); klik = pun pregled + GPS, vreme,
     uređaj, SHA-256 heš, EXIF/stego detalji
   - **Izveštaj** — generiši i preuzmi (**.txt / PDF / Word / HTML**), plus
     **🧠 AI Zaključak** (Ollama)
   - **Slučaj / Audit** — verzije analize, hash-chained audit trag,
     provera reproducibilnosti (chain of custody)

---

## Moduli analize (17)

| Modul | Šta izvlači |
|-------|-------------|
| `device_info` | Model, proizvođač, čipset, **serijski broj, SIM (ICCID/IMSI/operater), Android ID**, JWT identitet, **lista svih aplikacija** |
| `sms` / `calllog` / `contacts` | SMS/MMS, pozivi (uklj. nultosekundne), kontakti |
| `app_messaging` | Poruke iz **WhatsApp, Viber, Telegram, Signal, Instagram, Messenger** i dr. (čita plaintext, flaguje enkriptovane) |
| `notes` | Beleške: **Samsung Notes, Google Keep, ColorNote, OmniNotes** |
| `reminders` | Podsetnici, zadaci, alarmi, kalendarski događaji |
| `browser` | Chrome istorija, akreditivi, kolačići |
| `wifi` | WiFi mreže + lozinke (PSK), javne mreže |
| `apk` | Statička DEX analiza, detekcija trojanizovanih aplikacija |
| `exif` | Slike + **video** metapodaci (GPS, vreme) + **steganografija** |
| `crypto` / `blockchain` | QR + kripto adrese, checksum validacija, on-chain provera |
| `mp3_signal` | Audio steganografija |
| `signal_brd` | SQLCipher metapodaci, BRD novčanik |
| `deleted_recovery` | **Oporavak obrisanih**: SQLite freelist/WAL, trash, orphan thumbs |
| `anti_forensics` | Obrisani tragovi, manipulacija vremenom, root, lažni GPS, log wiping |

> IMEI se **ne** nalazi u logičkom dump-u (u modem/EFS je), pa aplikacija to
> pošteno navodi; izvlači serijski broj i SIM identifikatore koji jesu dostupni.

---

## Struktura projekta

```
forensic_dashboard/
├── backend/                  ← FastAPI Python backend
│   ├── main.py               ← API rute, korelator, timeline, izveštaji
│   ├── ai_analyst.py         ← AI zaključak preko Ollama (lokalni model)
│   ├── modules/              ← 13 analitičkih modula
│   ├── correlation/          ← deklarativni registry korelacionih pravila
│   ├── report/               ← deterministički JSON model izveštaja
│   ├── utils/                ← evidence (hash/provenance), case_store,
│   │                            audit_log, dump_resolver, db_reader ...
│   ├── cases/                ← perzistentni slučajevi + audit trag (auto)
│   └── requirements.txt
├── src/                      ← React frontend
│   ├── components/           ← Dashboard, Gallery, Timeline, Report, CaseInfo ...
│   └── utils/                ← api.js, constants.js
├── start.bat / start.sh      ← pokretanje jednim klikom
└── README.md
```

---

## Konfiguracija (promenljive okruženja)

| Promenljiva | Default | Opis |
|-------------|---------|------|
| `AI_MODEL` | `qwen3:32b` | Ollama model za AI zaključak |
| `OLLAMA_HOST` | `http://localhost:11434` | adresa Ollama servera |
| `AFD_CASES_DIR` | `backend/cases` | gde se čuvaju slučajevi i audit |

---

## Napomene

- **AI je opcioni** — cela analiza, korelacije, galerija i izveštaji rade i bez
  Ollama-e. Ako model nije podešen, dugme „AI Zaključak" prikaže tačno uputstvo.
- **Privatnost** — dump i nalazi se obrađuju isključivo lokalno; AI model radi
  na tvojoj mašini, ništa se ne šalje na internet.
- **Blockchain on-chain provera** — jedini korak koji (ako ima interneta)
  proverava balans adrese preko javnog explorer-a; radi i offline (samo lokalna
  validacija checksum-a).
