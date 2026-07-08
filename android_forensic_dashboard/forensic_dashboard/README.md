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

Sve radi **lokalno i offline** — nijedan podatak ne napušta mašinu (bitno za
poverljivost i lanac nadležnosti). Aplikacija **ne menja originalne fajlove** —
sve čitanje je read-only (SQLite baze se otvaraju preko `file:...?mode=ro`, WAL
fajlovi se kopiraju u privremeni fajl pre čitanja).

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

---

## 3. Korišćenje

1. Na početnom ekranu unesi **putanju do dump foldera** (npr.
   `C:\...\evidence\Samsung_S10\Dump`) i ime veštaka, pa klikni **Otvori**.
2. Klikni **Pokreni sve module** (ili pojedinačno u levom meniju).
3. Pregledaj rezultate kroz tabove:
   - **Pregled** — rezime, uređaj, broj artefakata/upozorenja
   - **Korelacije** — ukrštanja između izvora sa skorom i citiranim dokazima
   - **Timeline** — hronologija (glavni događaji / detaljno)
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
