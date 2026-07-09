"""
sim.py — Akvizicija SIM/USIM kartice preko PC/SC (pyscard) APDU komandi
────────────────────────────────────────────────────────────────────────
Čita SIM karticu iz USB PC/SC čitača i izvlači forenzički relevantne
Elementarne Fajlove (EF) preko standardnih GSM/3GPP APDU komandi:

  • EF_ICCID (MF 2FE2)        → serijski broj kartice (BCD, nibble-swap)
  • EF_IMSI  (DF_GSM 6F07)    → IMSI + izvedeni MCC/MNC (operater/država)
  • EF_SPN   (DF_GSM 6F46)    → naziv operatera (Service Provider Name)
  • EF_ADN   (DF_TELECOM 6F3A)→ imenik/kontakti (alpha tag + BCD broj)
  • EF_SMS   (DF_TELECOM 6F3C)→ SMS poruke (best-effort PDU dekodiranje)

Podržane su i USIM (SELECT '00 A4 …') i klasične 2G/GSM (SELECT 'A0 A4 …')
kartice: prvo se pokušava USIM okvir, pa fallback na 2G.

FORENZIČKA PRAVILA (isto kao ostatak acquisition sloja):
  • pyscard je OPCIONA zavisnost — uvoz je zaštićen; bez nje jasna greška.
  • Kartica se SAMO čita (READ BINARY / READ RECORD) — nikad ne piše na SIM.
  • NIŠTA se ne izmišlja: ako EF ne može da se pročita ili dekodira, vrednost
    ostaje null (ili sirovi hex pod 'raw'), greška se loguje — nikad lažni podatak.
  • Izuzetak se baca SAMO ako pyscard nedostaje ili nema čitača/kartice uopšte;
    pojedinačni EF nikad ne obara akviziciju.

Rezultat: folder slučaja sa Evidence/SIM/ (sim_data.json, contacts.json,
sms.json) + manifest (MD5/SHA-1/SHA-256) u Logs/ i Evidence/Metadata.
"""

import json
from pathlib import Path

from . import base, cases_fs


# ═══════════════════════════════════════════════════════════════════════════
# APDU konstante (GSM 11.11 / 3GPP TS 51.011 / 31.102)
# ═══════════════════════════════════════════════════════════════════════════

# SELECT po File ID: dva okvira (USIM: 00 A4 00 04; 2G: A0 A4 00 00)
_SELECT_USIM = [0x00, 0xA4, 0x00, 0x04, 0x02]
_SELECT_2G = [0xA0, 0xA4, 0x00, 0x00, 0x02]

# READ BINARY / READ RECORD zaglavlja (CLA se bira po okviru: 0x00 USIM / 0xA0 2G)
_INS_READ_BINARY = 0xB0
_INS_READ_RECORD = 0xB2
_INS_GET_RESPONSE = 0xC0

# File Identifikatori (dvobajtni)
_MF = [0x3F, 0x00]
_DF_TELECOM = [0x7F, 0x10]
_DF_GSM = [0x7F, 0x20]
_EF_ICCID = [0x2F, 0xE2]        # ispod MF
_EF_IMSI = [0x6F, 0x07]         # ispod DF_GSM
_EF_SPN = [0x6F, 0x46]          # ispod DF_GSM
_EF_ADN = [0x6F, 0x3A]          # ispod DF_TELECOM
_EF_SMS = [0x6F, 0x3C]          # ispod DF_TELECOM

_SW_OK = (0x90, 0x00)


# ═══════════════════════════════════════════════════════════════════════════
# Niski nivo: čitač / konekcija / APDU
# ═══════════════════════════════════════════════════════════════════════════

def _pick_reader(reader_list, reader_name: str):
    """
    Izaberi čitač: po substring podudaranju imena (case-insensitive), inače prvi.
    Vraća objekat čitača ili None ako lista prazna.
    """
    if not reader_list:
        return None
    if reader_name:
        want = reader_name.strip().lower()
        for r in reader_list:
            if want in str(r).lower():
                return r
    return reader_list[0]


def _atr_hex(conn) -> str:
    try:
        return " ".join(f"{b:02X}" for b in conn.getATR())
    except Exception:
        return ""


class _Card:
    """
    Tanak omotač oko pyscard konekcije koji zna da bira USIM ('00 A4') ili
    2G ('A0 A4') okvir i sam se prilagodi (CLA za READ zavisi od okvira).
    Sve metode su read-only nad karticom.
    """

    def __init__(self, conn):
        self.conn = conn
        self.cla = 0x00          # podrazumevano USIM; _detect_frame ga ažurira
        self.usim = True

    def _transmit(self, apdu):
        """Pošalji APDU; vrati (data_bytes, sw1, sw2). Nikad ne baca izuzetak."""
        try:
            data, sw1, sw2 = self.conn.transmit(list(apdu))
            return bytes(data or []), sw1, sw2
        except Exception:
            return b"", 0x6F, 0x00

    def detect_frame(self) -> bool:
        """
        Odredi da li kartica odgovara na USIM ili 2G SELECT (biranjem MF).
        Postavlja self.usim/self.cla. Vraća True ako je bilo koji okvir uspeo.
        """
        # USIM okvir
        apdu = _SELECT_USIM + _MF
        _, sw1, sw2 = self._transmit(apdu)
        if (sw1, sw2) == _SW_OK or sw1 in (0x61, 0x9F):
            self.usim = True
            self.cla = 0x00
            return True
        # 2G okvir
        apdu = _SELECT_2G + _MF
        _, sw1, sw2 = self._transmit(apdu)
        if (sw1, sw2) == _SW_OK or sw1 in (0x61, 0x9F):
            self.usim = False
            self.cla = 0xA0
            return True
        return False

    def select(self, fid) -> tuple:
        """
        SELECT po File ID u tekućem okviru. Vraća (ok, sw1, sw2).
        Neke kartice vraćaju 61xx/9Fxx (ima Response) — tretiramo kao uspeh.
        """
        header = _SELECT_USIM if self.usim else _SELECT_2G
        _, sw1, sw2 = self._transmit(header + list(fid))
        ok = (sw1, sw2) == _SW_OK or sw1 in (0x61, 0x9F)
        return ok, sw1, sw2

    def select_path(self, path) -> bool:
        """
        SELECT niza fajlova (npr. MF → DF_TELECOM → EF_ADN). Uvek kreni od MF
        radi determinizma. Vraća True ako je poslednji SELECT uspeo.
        """
        seq = [_MF] + [p for p in path if p != _MF]
        ok = False
        for fid in seq:
            ok, _, _ = self.select(fid)
            if not ok:
                return False
        return ok

    def read_binary(self, length: int = 0, offset: int = 0) -> bytes:
        """
        READ BINARY (transparentni EF). Ako length==0, pokušava da pročita
        do 256 bajtova (dovoljno za ICCID/IMSI/SPN). Vraća sirove bajtove.
        """
        le = length if 0 < length <= 256 else 0
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        le_byte = 0x00 if le == 0 or le == 256 else le
        apdu = [self.cla, _INS_READ_BINARY, p1, p2, le_byte]
        data, sw1, sw2 = self._transmit(apdu)
        if sw1 == 0x6C:  # pogrešna dužina — kartica javlja tačan Le u sw2
            apdu = [self.cla, _INS_READ_BINARY, p1, p2, sw2]
            data, sw1, sw2 = self._transmit(apdu)
        if (sw1, sw2) == _SW_OK:
            return data
        return b""

    def read_record(self, rec_num: int, length: int) -> bytes:
        """READ RECORD (linearni fiksni EF, npr. ADN/SMS). P2=0x04 = apsolutni broj zapisa."""
        le = 0x00 if length <= 0 or length > 256 else length
        apdu = [self.cla, _INS_READ_RECORD, rec_num & 0xFF, 0x04, le]
        data, sw1, sw2 = self._transmit(apdu)
        if sw1 == 0x6C:
            apdu = [self.cla, _INS_READ_RECORD, rec_num & 0xFF, 0x04, sw2]
            data, sw1, sw2 = self._transmit(apdu)
        if (sw1, sw2) == _SW_OK:
            return data
        return b""

    def record_size(self) -> int:
        """
        Pročitaj veličinu zapisa trenutno selektovanog linearnog EF preko GET RESPONSE
        (SELECT response FCP/FCP-template). Vraća 0 ako se ne može utvrditi.
        """
        # GET RESPONSE (radi kod 2G; USIM često vrati FCP direktno u SELECT-u)
        data, sw1, sw2 = self._transmit([self.cla, _INS_GET_RESPONSE, 0x00, 0x00, 0x0F])
        if (sw1, sw2) != _SW_OK or not data:
            return 0
        # 2G format (GSM 11.11): bajt 14 (indeks 14) = dužina zapisa za linearne fajlove.
        try:
            if len(data) >= 15 and not self.usim:
                return data[14]
        except Exception:
            pass
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# Dekoderi (BCD / nibble-swap / GSM 7-bit) — samo čitanje, bez izmišljanja
# ═══════════════════════════════════════════════════════════════════════════

def _swap_nibbles_bcd(data: bytes) -> str:
    """
    BCD sa zamenjenim nibblima (ICCID/IMSI raspored). Svaki bajt = dve cifre,
    niži nibl prvi. 0xF (i drugi ne-cifreni niblovi) = kraj/paddin — preskače se.
    """
    out = []
    for b in data:
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        for nib in (lo, hi):
            if nib <= 9:
                out.append(str(nib))
            # 0xA–0xF su padding/oznake — ignorišu se
    return "".join(out)


def _decode_iccid(data: bytes) -> str | None:
    s = _swap_nibbles_bcd(data)
    return s or None


def _decode_imsi(data: bytes) -> str | None:
    """
    EF_IMSI: bajt 0 = dužina, zatim se IMSI kodira kao 'parity/first-digit' u
    prvom nizu. Prvi nibl (posle bajta dužine) je oznaka parnosti; realni IMSI
    počinje od visokog nibla prvog bajta. Standardno se prva cifra dobija iz
    gornjeg nibla, ostatak swap-BCD.
    """
    if not data or len(data) < 2:
        return None
    length = data[0]
    body = data[1:1 + length] if 0 < length <= len(data) - 1 else data[1:]
    if not body:
        return None
    # Prva cifra = gornji nibl prvog bajta; ostalo swap-BCD (donji, pa gornji).
    digits = [str((body[0] >> 4) & 0x0F)]
    for b in body[1:]:
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        if lo <= 9:
            digits.append(str(lo))
        if hi <= 9:
            digits.append(str(hi))
    imsi = "".join(digits)
    return imsi or None


def _mcc_mnc(imsi: str | None) -> str | None:
    """
    MCC = prve 3 cifre; MNC = naredne 2 ili 3. Bez baze operatera ne možemo
    pouzdano znati da li je MNC 2 ili 3 cifre za svaki MCC, pa navodimo MCC i
    2-cifreni MNC kao standardni prikaz (ne izmišljamo tačnu dužinu).
    """
    if not imsi or len(imsi) < 5:
        return None
    mcc = imsi[:3]
    mnc = imsi[3:5]
    return f"{mcc}/{mnc}"


def _strip_ff(data: bytes) -> bytes:
    """Ukloni 0xFF padding sa kraja (SIM koristi 0xFF za neiskorišćene bajtove)."""
    return data.rstrip(b"\xff")


def _decode_spn(data: bytes) -> str | None:
    """
    EF_SPN: bajt 0 = prikazni uslovi, zatim GSM alfabet naziv (0xFF padding).
    Best-effort dekodiranje na ASCII/latin-1; ne izmišljamo znakove.
    """
    if not data or len(data) < 2:
        return None
    body = _strip_ff(data[1:])
    if not body:
        return None
    try:
        text = body.decode("latin-1", errors="ignore").strip()
        text = "".join(ch for ch in text if ch.isprintable()).strip()
        return text or None
    except Exception:
        return None


# GSM 7-bit default alfabet (dovoljno za alpha tag i osnovni tekst)
_GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)


def _decode_alpha(data: bytes) -> str:
    """
    Alpha tag kod ADN zapisa. Ako prvi bajt >= 0x80 to je UCS2 kodiranje;
    inače GSM/ASCII. 0xFF su padding. Best-effort, bez izmišljanja.
    """
    body = _strip_ff(data)
    if not body:
        return ""
    # UCS2 varijante (0x80 puni UCS2; 0x81/0x82 skraćene) — pokušaj UTF-16.
    if body[0] == 0x80:
        try:
            return body[1:].decode("utf-16-be", errors="ignore").strip("\x00").strip()
        except Exception:
            pass
    # GSM/latin fallback
    out = []
    for b in body:
        if b == 0xFF:
            break
        if b < len(_GSM7_BASIC):
            out.append(_GSM7_BASIC[b])
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
    return "".join(out).strip()


def _decode_bcd_number(data: bytes) -> str:
    """
    Telefonski broj u BCD (nibble-swap), 0xF = kraj. Vraća string cifara.
    Koristi se za ADN broj (posle TON/NPI bajta).
    """
    out = []
    for b in data:
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        for nib in (lo, hi):
            if nib == 0x0F:
                return "".join(out)
            if nib <= 9:
                out.append(str(nib))
            elif nib == 0x0A:
                out.append("*")
            elif nib == 0x0B:
                out.append("#")
    return "".join(out)


def _decode_adn_record(rec: bytes) -> dict | None:
    """
    ADN zapis (GSM 11.11 §10.5.1):
      [alpha tag (X bajtova)] [1 bajt: dužina BCD broja+1] [1 bajt: TON/NPI]
      [do 10 bajtova BCD broja] [CCP] [Ext].
    Prazan (svi 0xFF) zapis se preskače (vraća None). Ne izmišljamo se ništa.
    """
    if not rec or all(b == 0xFF for b in rec):
        return None
    # Poslednjih 14 bajtova su fiksni deo (dužina + TON/NPI + 10 BCD + CCP + Ext).
    footer = 14
    if len(rec) < footer:
        return None
    alpha_part = rec[:len(rec) - footer]
    fixed = rec[len(rec) - footer:]
    name = _decode_alpha(alpha_part)

    bcd_len = fixed[0]                 # broj bajtova (TON/NPI + broj)
    ton_npi = fixed[1]
    # Broj cifara: (bcd_len - 1) bajtova posle TON/NPI bajta
    num_bytes = fixed[2:2 + max(0, min(10, bcd_len - 1))] if bcd_len and bcd_len != 0xFF else b""
    number = _decode_bcd_number(num_bytes)
    if ton_npi != 0xFF and (ton_npi & 0x70) == 0x10 and number and not number.startswith("+"):
        number = "+" + number         # međunarodni format (TON = international)

    if not name and not number:
        return None
    return {"name": name or None, "number": number or None}


def _decode_sms_record(rec: bytes) -> dict | None:
    """
    EF_SMS zapis: bajt 0 = status, ostatak = SMS TPDU (u SMS-DELIVER/SUBMIT
    formatu, sa SC adresom na početku). Puno PDU dekodiranje je nesigurno
    (7-bit pakovanje, koncatenacija, UDH), pa je pristup best-effort:
      • status se mapira na čitljivu oznaku,
      • pokušaj se izvuče broj pošiljaoca (BCD),
      • tekst se dekodira samo ako je pouzdano 7-bit; inače 'raw' hex.
    NIKAD ne izmišljamo tekst — nesiguran PDU ide pod 'raw'.
    """
    if not rec or all(b == 0xFF for b in rec):
        return None
    status_byte = rec[0]
    status_map = {
        0x00: "slobodno",
        0x01: "primljeno, pročitano",
        0x03: "primljeno, nepročitano",
        0x05: "poslato",
        0x07: "za slanje",
    }
    status = status_map.get(status_byte)
    if status is None:
        # Ako je ceo zapis padding posle statusa, to je prazan slot.
        if all(b == 0xFF for b in rec[1:]):
            return None
        status = f"status 0x{status_byte:02X}"

    pdu = _strip_ff(rec[1:])
    entry = {"status": status, "number": None, "text": None}
    if not pdu:
        return entry

    number = None
    try:
        # SMSC dužina (u bajtovima) je prvi bajt PDU-a.
        smsc_len = pdu[0]
        idx = 1 + smsc_len
        if idx < len(pdu):
            # first octet + (za DELIVER) OA (originating address)
            idx += 1  # preskoči first octet
            if idx < len(pdu):
                oa_len = pdu[idx]        # broj cifara adrese
                ton = pdu[idx + 1] if idx + 1 < len(pdu) else 0
                addr_bytes = (oa_len + 1) // 2
                addr = pdu[idx + 2: idx + 2 + addr_bytes]
                number = _decode_bcd_number(addr)
                if number and (ton & 0x70) == 0x10 and not number.startswith("+"):
                    number = "+" + number
    except Exception:
        number = None
    entry["number"] = number or None

    # Tekst PDU-a je nesiguran za dekodiranje bez punog parsera → uvek 'raw' hex.
    entry["raw"] = pdu.hex().upper()
    return entry


# ═══════════════════════════════════════════════════════════════════════════
# EF čitači (svaki u sopstvenom try/except; log uspeha/greške; bez izmišljanja)
# ═══════════════════════════════════════════════════════════════════════════

def _read_transparent(card: "_Card", path, logs: list, label: str) -> bytes:
    """SELECT putanje do transparentnog EF + READ BINARY. Loguje ishod."""
    try:
        if not card.select_path(path):
            logs.append(f"{label}: SELECT nije uspeo (EF nedostupan).")
            return b""
        data = card.read_binary()
        if data:
            logs.append(f"{label}: pročitano {len(data)} B.")
        else:
            logs.append(f"{label}: READ BINARY prazan/neuspešan.")
        return data
    except Exception as e:
        logs.append(f"{label}: greška — {e}")
        return b""


def _read_records(card: "_Card", path, logs: list, label: str,
                  max_records: int = 255, cancelled=None) -> list:
    """
    SELECT putanje do linearnog EF + iterativni READ RECORD dok ima podataka.
    Vraća listu sirovih zapisa (bajtova). Loguje broj pročitanih zapisa.
    """
    records = []
    try:
        if not card.select_path(path):
            logs.append(f"{label}: SELECT nije uspeo (EF nedostupan).")
            return records
        rec_len = card.record_size()   # može biti 0 (USIM/nepoznato)
        empty_streak = 0
        for n in range(1, max_records + 1):
            if cancelled and cancelled():
                break
            rec = card.read_record(n, rec_len if rec_len else 0)
            if not rec:
                # Prazan odgovor (SW != 9000) obično znači kraj fajla.
                break
            if all(b == 0xFF for b in rec):
                empty_streak += 1
                # SIM često ima retke prazne slotove između zapisa; ne prekidamo
                # odmah, ali posle više uzastopnih praznih verovatno je kraj.
                if empty_streak >= 10:
                    break
                continue
            empty_streak = 0
            records.append(rec)
        logs.append(f"{label}: pročitano {len(records)} zapisa.")
    except Exception as e:
        logs.append(f"{label}: greška — {e}")
    return records


# ═══════════════════════════════════════════════════════════════════════════
# Glavna funkcija akvizicije
# ═══════════════════════════════════════════════════════════════════════════

def acquire_sim(progress, reader_name: str = "", examiner: str = "") -> dict:
    """
    Target funkcija za jobs.start_job. Čita SIM/USIM karticu preko PC/SC i
    pravi folder slučaja sa Evidence/SIM/ (sim_data.json, contacts.json,
    sms.json) + manifest (MD5/SHA-1/SHA-256).

    Baca izuzetak SAMO ako pyscard nije instaliran ili nema čitača/kartice.
    Pojedinačni EF nikad ne obara akviziciju (greška se loguje, vrednost null).

    Vraća dict po ugovoru:
      {case_id, source, evidence_path, case_path, stats, device, report_data, cancelled}
    """
    logs: list = []

    # ── 1) pyscard (opciona zavisnost) ──────────────────────────────────────
    progress.update(1, "Provera PC/SC podrške (pyscard)…")
    try:
        from smartcard.System import readers  # type: ignore
    except ImportError:
        raise RuntimeError(
            "pyscard nije instaliran: pip install pyscard  "
            "(potreban je i USB PC/SC SIM čitač i pokrenut servis 'Smart Card')."
        )

    # ── 2) Izbor čitača i konekcija ─────────────────────────────────────────
    progress.update(3, "Pronalaženje PC/SC čitača…")
    try:
        reader_list = readers()
    except Exception as e:
        raise RuntimeError(
            f"PC/SC greška pri listanju čitača: {e}. "
            "Proveri da je servis 'Smart Card' pokrenut i drajver čitača instaliran."
        )

    reader = _pick_reader(reader_list, reader_name)
    if reader is None:
        raise RuntimeError(
            "Nijedan PC/SC čitač nije pronađen. Poveži USB SIM čitač i osveži."
        )
    logs.append(f"Izabran čitač: {reader}")
    progress.log(f"Čitač: {reader}")

    try:
        conn = reader.createConnection()
        conn.connect()
    except Exception as e:
        raise RuntimeError(
            f"Kartica nije detektovana u čitaču '{reader}': {e}. "
            "Ubaci SIM karticu u čitač i pokušaj ponovo."
        )

    atr = _atr_hex(conn)
    logs.append(f"ATR: {atr}" if atr else "ATR: (nedostupan)")
    progress.log(f"Kartica povezana. ATR: {atr or '?'}")

    # Rezultati (podrazumevano null — popunjava se samo ako se stvarno pročita)
    iccid = None
    imsi = None
    operator = None
    mcc_mnc = None
    contacts: list = []
    sms: list = []

    try:
        card = _Card(conn)

        # ── 3) Detekcija okvira (USIM '00 A4' pa 2G 'A0 A4') ────────────────
        progress.update(8, "Detekcija tipa kartice (USIM/2G)…")
        if not card.detect_frame():
            logs.append("Nijedan SELECT okvir nije prihvaćen (ni USIM ni 2G). "
                        "Nastavljam sa USIM okvirom kao podrazumevanim.")
        else:
            logs.append(f"Okvir kartice: {'USIM (00 A4)' if card.usim else '2G/GSM (A0 A4)'}.")
        progress.log(logs[-1])

        # ── EF_ICCID (transparentni, ispod MF) ──────────────────────────────
        progress.update(15, "Čitanje EF_ICCID…")
        raw = _read_transparent(card, [_MF, _EF_ICCID], logs, "EF_ICCID")
        if raw:
            iccid = _decode_iccid(raw)
        progress.log(logs[-1])

        # ── EF_IMSI (transparentni, ispod DF_GSM) ───────────────────────────
        progress.update(25, "Čitanje EF_IMSI…")
        raw = _read_transparent(card, [_MF, _DF_GSM, _EF_IMSI], logs, "EF_IMSI")
        if raw:
            imsi = _decode_imsi(raw)
            mcc_mnc = _mcc_mnc(imsi)
        progress.log(logs[-1])

        # ── EF_SPN (transparentni, ispod DF_GSM) ────────────────────────────
        progress.update(35, "Čitanje EF_SPN (operater)…")
        raw = _read_transparent(card, [_MF, _DF_GSM, _EF_SPN], logs, "EF_SPN")
        if raw:
            operator = _decode_spn(raw)
        progress.log(logs[-1])

        # ── EF_ADN (kontakti, linearni, ispod DF_TELECOM) ───────────────────
        if not progress.cancelled():
            progress.update(50, "Čitanje EF_ADN (kontakti)…")
            recs = _read_records(card, [_MF, _DF_TELECOM, _EF_ADN], logs, "EF_ADN",
                                 cancelled=progress.cancelled)
            for r in recs:
                dec = None
                try:
                    dec = _decode_adn_record(r)
                except Exception:
                    dec = None
                if dec:
                    contacts.append(dec)
            logs.append(f"EF_ADN: dekodirano {len(contacts)} kontakata.")
            progress.log(logs[-1])

        # ── EF_SMS (poruke, linearni, ispod DF_TELECOM) ─────────────────────
        if not progress.cancelled():
            progress.update(70, "Čitanje EF_SMS (poruke)…")
            recs = _read_records(card, [_MF, _DF_TELECOM, _EF_SMS], logs, "EF_SMS",
                                 cancelled=progress.cancelled)
            for r in recs:
                dec = None
                try:
                    dec = _decode_sms_record(r)
                except Exception:
                    dec = None
                if dec:
                    sms.append(dec)
            logs.append(f"EF_SMS: dekodirano {len(sms)} poruka.")
            progress.log(logs[-1])

    finally:
        try:
            conn.disconnect()
        except Exception:
            pass

    # ── 4) Kreiranje slučaja i upis dokaza ──────────────────────────────────
    progress.update(85, "Kreiranje slučaja i upis dokaza…")
    device_meta = {
        "model": operator or "SIM",
        "iccid": iccid,
        "imsi": imsi,
        "operator": operator,
    }
    case = cases_fs.create_case_folder(
        source="sim", examiner=examiner,
        device_info={"iccid": iccid, "imsi": imsi, "operator": operator,
                     "model": operator or "SIM"},
    )
    cid = case["case_id"]
    evidence_path = case["evidence_path"]
    cases_fs.append_log(
        cid, f"Akvizicija SIM (čitač: {reader}). ICCID: {iccid or '?'}, "
             f"IMSI: {imsi or '?'}, operater: {operator or '?'}, "
             f"kontakata: {len(contacts)}, SMS: {len(sms)}.")
    progress.log(f"Slučaj {cid} kreiran.")

    sim_dir = Path(evidence_path) / "SIM"
    sim_dir.mkdir(parents=True, exist_ok=True)

    sim_data = {
        "acquired_at": base.now_iso(),
        "reader": str(reader),
        "atr": atr or None,
        "card_frame": "USIM" if 'card' in dir() and getattr(card, "usim", True) else "2G",
        "iccid": iccid,
        "imsi": imsi,
        "operator": operator,
        "mcc_mnc": mcc_mnc,
        "msisdn": None,          # MSISDN (EF_MSISDN) često nije upisan na SIM — ne izmišljamo
        "contacts_count": len(contacts),
        "sms_count": len(sms),
        "logs": logs,
    }

    produced = []
    for fname, payload in (
        ("sim_data.json", sim_data),
        ("contacts.json", {"contacts": contacts}),
        ("sms.json", {"sms": sms}),
    ):
        fpath = sim_dir / fname
        try:
            fpath.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                             encoding="utf-8")
            produced.append(fpath)
        except Exception as e:
            cases_fs.append_log(cid, f"Greška pri upisu {fname}: {e}")
            logs.append(f"Upis {fname}: greška — {e}")

    # ── Manifest (integritet) nad proizvedenim JSON fajlovima ───────────────
    progress.update(93, "Sračunavanje heševa (manifest)…")
    manifest = base.EvidenceManifest(case_id=cid, source="sim")
    for fpath in produced:
        try:
            rel = fpath.relative_to(Path(evidence_path))
        except Exception:
            rel = Path("SIM") / fpath.name
        try:
            hashes = base.compute_hashes(fpath)
            if hashes:
                manifest.add(str(rel), fpath, hashes)
            else:
                manifest.add_error(str(rel), "hešovanje nije uspelo")
        except Exception as e:
            manifest.add_error(str(rel), str(e))

    manifest.write(cases_fs.case_dir(cid) / "Logs")
    manifest.write(Path(evidence_path) / "Metadata")
    summary = manifest.summary()
    cases_fs.append_log(
        cid, f"Manifest zapisan: {summary['file_count']} fajlova, "
             f"{summary['error_count']} grešaka.")

    cancelled = progress.cancelled()
    cases_fs.update_case_meta(
        cid,
        status="cancelled" if cancelled else "acquired",
        hashes={"manifest_files": summary["file_count"],
                "total_bytes": summary["total_bytes"],
                "total_size_human": summary["total_size_human"]},
    )

    stats = {
        "contacts": len(contacts),
        "sms": len(sms),
        "files": summary["file_count"],
        "bytes": summary["total_bytes"],
        "bytes_human": summary["total_size_human"],
    }

    # ── 5) report_data po ugovoru (kind='sim') ──────────────────────────────
    report_data = {
        "kind": "sim",
        "case_id": cid,
        "iccid": iccid,
        "imsi": imsi,
        "operator": operator,
        "mcc_mnc": mcc_mnc,
        "msisdn": None,          # nepoznato ako EF_MSISDN nije upisan — null, ne izmišljamo
        "atr": atr or None,
        "contacts": contacts,
        "sms": sms,
        "logs": logs,
    }

    progress.update(100, "SIM akvizicija završena.")
    return {
        "case_id": cid,
        "source": "sim",
        "evidence_path": evidence_path,          # → predaje se POST /api/session
        "case_path": str(cases_fs.case_dir(cid)),
        "stats": stats,
        "device": device_meta,
        "report_data": report_data,
        "cancelled": cancelled,
    }
