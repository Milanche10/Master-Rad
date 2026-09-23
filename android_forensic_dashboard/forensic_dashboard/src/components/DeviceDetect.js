import { useState, useEffect, useCallback } from 'react';
import { C } from '../utils/constants';
import * as api from '../utils/api';

// Konfiguracija po izvoru: koja detekcija, kako se zove lista, kako se gradi
// telo za startAcquisition, i kako se prikazuje jedna detektovana stavka.
const SOURCE_CFG = {
  mobile: {
    title: 'Povezani telefon (USB)',
    hint: 'Poveži telefon USB kablom i uključi „USB debugging" (Developer options).',
    detect: () => api.detectPhone(),
    listKey: 'devices',
    idOf: (d) => d.serial,
    disabled: (d) => d.state !== 'device',
    render: (d) => ({
      title: (`${d.manufacturer || ''} ${d.model || ''}`).trim() || d.serial,
      lines: [
        d.os && `OS: ${d.os}`,
        d.device_serial && `Serijski: ${d.device_serial}`,
        d.storage && d.storage.available_mb != null && `Slobodno: ${(d.storage.available_mb/1024).toFixed(1)} GB`,
        d.state !== 'device' && `Status: ${d.state}${d.note ? ' — ' + d.note : ''}`,
      ].filter(Boolean),
      badge: d.state === 'device' ? 'SPREMAN' : d.state.toUpperCase(),
    }),
    body: (d, examiner) => ({ examiner, serial: d.serial, device_info: d }),
  },
  sim: {
    title: 'SIM čitač (PC/SC)',
    hint: 'Ubaci SIM karticu u kompatibilan USB SIM čitač.',
    detect: () => api.detectSim(),
    listKey: 'readers',
    idOf: (r) => r.name,
    disabled: (r) => !r.card_present,
    render: (r) => ({
      title: r.name,
      lines: [
        r.card_present ? 'Kartica: detektovana' : 'Kartica: nije detektovana',
        r.atr && `ATR: ${r.atr}`,
      ].filter(Boolean),
      badge: r.card_present ? 'SIM PRISUTNA' : 'NEMA SIM',
    }),
    body: (r, examiner) => ({ examiner, reader: r.name }),
  },
  sdcard: {
    title: 'SD kartica',
    hint: 'Ubaci SD karticu u čitač.',
    detect: () => api.detectStorage('sdcard'),
    listKey: 'disks',
    idOf: (d) => d.device_id,
    disabled: () => false,
    render: (d) => ({
      title: `${d.device_id}  ${d.name || ''}`.trim(),
      lines: [
        `Fajl sistem: ${d.filesystem}`,
        `Kapacitet: ${d.size_human} (slobodno ${d.free_human})`,
        d.bus && `Magistrala: ${d.bus}`,
      ].filter(Boolean),
      badge: d.kind === 'usb' ? 'USB' : 'REMOVABLE',
    }),
    body: (d, examiner) => ({ examiner, mount: d.mount, disk_info: d }),
  },
  usb: {
    title: 'USB fleš disk',
    hint: 'Poveži USB fleš disk.',
    detect: () => api.detectStorage('usb'),
    listKey: 'disks',
    idOf: (d) => d.device_id,
    disabled: () => false,
    render: (d) => ({
      title: `${d.device_id}  ${d.name || ''}`.trim(),
      lines: [
        `Fajl sistem: ${d.filesystem}`,
        `Kapacitet: ${d.size_human} (slobodno ${d.free_human})`,
        d.bus && `Magistrala: ${d.bus}`,
      ].filter(Boolean),
      badge: d.kind === 'usb' ? 'USB' : 'REMOVABLE',
    }),
    body: (d, examiner) => ({ examiner, mount: d.mount, disk_info: d }),
  },
};

export default function DeviceDetect({ source, examiner, onStarted, onBack }) {
  const cfg = SOURCE_CFG[source];
  const [state, setState] = useState({ loading: true });
  const [selected, setSelected] = useState(null);
  const [starting, setStarting] = useState(false);
  const [err, setErr] = useState(null);
  const [caps, setCaps] = useState(null);          // sposobnosti + metode (samo za mobile)
  const [methodSel, setMethodSel] = useState('auto');

  const refresh = useCallback(async () => {
    setState({ loading: true });
    setSelected(null);
    try {
      const data = await cfg.detect();
      setState({ loading: false, ...data });
      const items = data[cfg.listKey] || [];
      const firstReady = items.find((it) => !cfg.disabled(it));
      if (firstReady) setSelected(cfg.idOf(firstReady));
    } catch (e) {
      setState({ loading: false, available: false, reason: e.message });
    }
  }, [cfg]);

  useEffect(() => { refresh(); }, [refresh]);

  // Za telefon: po izboru uređaja učitaj sposobnosti (dostupne metode akvizicije).
  useEffect(() => {
    if (source !== 'mobile' || !selected) { setCaps(null); return; }
    let alive = true;
    setCaps({ loading: true });
    api.detectPhoneCapabilities(selected)
      .then((d) => {
        if (!alive) return;
        setCaps(d);
        const methods = d.methods || [];
        const auto = methods.find((m) => m.method === 'auto' && m.available);
        const firstAvail = methods.find((m) => m.available && m.method !== 'auto');
        setMethodSel(auto ? 'auto' : (firstAvail ? firstAvail.method : 'auto'));
      })
      .catch((e) => { if (alive) setCaps({ error: e.message }); });
    return () => { alive = false; };
  }, [source, selected]);

  const items = state[cfg.listKey] || [];
  const methodAvailable = source !== 'mobile'
    || !!(caps && caps.methods && caps.methods.some((m) => m.method === methodSel && m.available));

  // Legitimna `adb root` elevacija na zahtev (emulator/userdebug/rutovan uređaj; bez exploita).
  const attemptRoot = async () => {
    setCaps({ loading: true });
    try {
      const d = await api.detectPhoneCapabilities(selected, true);
      setCaps(d);
      const methods = d.methods || [];
      const auto = methods.find((m) => m.method === 'auto' && m.available);
      const firstAvail = methods.find((m) => m.available && m.method !== 'auto');
      setMethodSel(auto ? 'auto' : (firstAvail ? firstAvail.method : 'auto'));
    } catch (e) { setCaps({ error: e.message }); }
  };

  const start = async () => {
    const item = items.find((it) => cfg.idOf(it) === selected);
    if (!item) return;
    setStarting(true);
    setErr(null);
    try {
      const body = cfg.body(item, examiner);
      if (source === 'mobile') body.method = methodSel;
      const { job_id } = await api.startAcquisition(source, body);
      const label = cfg.render(item).title + (source === 'mobile' ? ` · ${methodSel}` : '');
      onStarted(job_id, label);
    } catch (e) {
      setErr(e.message);
      setStarting(false);
    }
  };

  return (
    <div style={{ maxWidth: 620, width: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <h2 style={{ fontFamily: C.fontMono, fontSize: 18, color: C.textPrimary, margin: 0 }}>
          {cfg.title}
        </h2>
        <button onClick={refresh} style={btn(C.bgCard, C.textSecondary)}>↻ Osveži</button>
      </div>
      <p style={{ color: C.textSecondary, fontSize: 13, marginBottom: 16 }}>{cfg.hint}</p>

      {state.loading && (
        <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 13, padding: 20 }}>
          Detekcija u toku…
        </div>
      )}

      {!state.loading && items.length === 0 && (
        <div style={{
          background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8,
          padding: 16, color: C.textSecondary, fontSize: 13, lineHeight: 1.6,
        }}>
          <div style={{ color: C.yellow, fontFamily: C.fontMono, fontSize: 12, marginBottom: 6 }}>
            ⚠ Ništa nije detektovano
          </div>
          {state.reason || 'Nije pronađen nijedan izvor.'}
        </div>
      )}

      {!state.loading && items.map((it) => {
        const r = cfg.render(it);
        const id = cfg.idOf(it);
        const isDisabled = cfg.disabled(it);
        const isSel = selected === id;
        return (
          <button
            key={id}
            onClick={() => !isDisabled && setSelected(id)}
            disabled={isDisabled}
            style={{
              display: 'block', width: '100%', textAlign: 'left', marginBottom: 8,
              background: isSel ? C.accentDim : C.bgCard,
              border: `1px solid ${isSel ? C.accent : C.border}`,
              borderRadius: 8, padding: '12px 14px',
              cursor: isDisabled ? 'not-allowed' : 'pointer',
              opacity: isDisabled ? 0.55 : 1,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: C.textPrimary, fontFamily: C.fontMono, fontSize: 13, fontWeight: 600 }}>
                {r.title}
              </span>
              <span style={{
                fontFamily: C.fontMono, fontSize: 9, letterSpacing: 1, padding: '2px 6px',
                borderRadius: 3, color: isDisabled ? C.textMuted : C.green,
                background: isDisabled ? C.border : C.greenDim,
              }}>{r.badge}</span>
            </div>
            {r.lines.map((l, i) => (
              <div key={i} style={{ color: C.textSecondary, fontSize: 11, marginTop: 3, fontFamily: C.fontMono }}>
                {l}
              </div>
            ))}
          </button>
        );
      })}

      {/* Izbor metode akvizicije — SAMO za telefon, kad je uređaj izabran (spec §6,§39) */}
      {source === 'mobile' && selected && caps && caps.loading && (
        <div style={{ color: C.textMuted, fontSize: 12, fontFamily: C.fontMono, margin: '10px 0' }}>
          Detekcija sposobnosti uređaja…
        </div>
      )}
      {source === 'mobile' && selected && caps && caps.error && (
        <div style={{ color: C.red, fontSize: 12, fontFamily: C.fontMono, margin: '10px 0' }}>
          ⚠ {caps.error}
        </div>
      )}
      {source === 'mobile' && selected && caps && !caps.loading && !caps.error && (caps.methods || []).length > 0 && (
        <div style={{ marginTop: 6 }}>
          <div style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, letterSpacing: 1, margin: '12px 0 8px' }}>
            METODA AKVIZICIJE
          </div>
          {caps.methods.map((m) => {
            const on = m.available;
            const sel = methodSel === m.method;
            return (
              <button
                key={m.method}
                onClick={() => on && setMethodSel(m.method)}
                disabled={!on}
                style={{
                  display: 'block', width: '100%', textAlign: 'left', marginBottom: 6,
                  background: sel ? C.accentDim : C.bgCard,
                  border: `1px solid ${sel && on ? C.accent : C.border}`,
                  borderRadius: 6, padding: '9px 12px',
                  cursor: on ? 'pointer' : 'not-allowed', opacity: on ? 1 : 0.55,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: on ? C.textPrimary : C.textMuted, fontFamily: C.fontMono, fontSize: 12, fontWeight: 600 }}>
                    {sel && on ? '◉' : '○'} {m.label}
                  </span>
                  <span style={{
                    fontFamily: C.fontMono, fontSize: 9, letterSpacing: 1, padding: '2px 6px', borderRadius: 3,
                    color: on ? C.green : C.textMuted, background: on ? C.greenDim : C.border,
                  }}>{on ? 'DOSTUPNO' : 'NEDOSTUPNO'}</span>
                </div>
                {!on && m.reason && (
                  <div style={{ color: C.textMuted, fontSize: 10, marginTop: 3, lineHeight: 1.4 }}>{m.reason}</div>
                )}
              </button>
            );
          })}

          {/* Legitimna `adb root` elevacija (emulator/userdebug); bez exploita */}
          {!(caps.capabilities && caps.capabilities.root_available) && (
            <div style={{ marginTop: 4 }}>
              <button onClick={attemptRoot} style={{
                background: C.bgCard, color: C.textSecondary, border: `1px solid ${C.border}`,
                borderRadius: 6, padding: '7px 12px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer',
              }}>⚡ Pokušaj `adb root` (emulator / userdebug)</button>
              <div style={{ color: C.textMuted, fontSize: 10, marginTop: 4, lineHeight: 1.4 }}>
                Zvanična `adb root` komanda — radi na emulatoru/userdebug/rutovanom uređaju.
                Ne koristi exploit i ne menja dokaz.
              </div>
            </div>
          )}
          {caps.capabilities && caps.capabilities.adb_root_attempt && (
            <div style={{ color: (caps.capabilities.root_available ? C.green : C.yellow),
              fontSize: 10, fontFamily: C.fontMono, marginTop: 6 }}>
              adb root: {caps.capabilities.adb_root_attempt}
            </div>
          )}
        </div>
      )}

      {err && (
        <div style={{ color: C.red, fontSize: 12, fontFamily: C.fontMono, margin: '10px 0' }}>⚠ {err}</div>
      )}

      <div style={{ display: 'flex', gap: 10, marginTop: 18 }}>
        {onBack && <button onClick={onBack} style={btn(C.bgCard, C.textSecondary)}>← Nazad</button>}
        <button
          onClick={start}
          disabled={!selected || starting || !methodAvailable}
          style={{
            ...btn(selected && !starting && methodAvailable ? C.accent : C.accentDim,
                   selected && !starting && methodAvailable ? C.bg : C.textMuted),
            flex: 1, fontWeight: 600,
            cursor: selected && !starting && methodAvailable ? 'pointer' : 'not-allowed',
          }}
        >
          {starting ? 'Pokretanje…'
            : (source === 'mobile' && !methodAvailable ? 'Izaberi dostupnu metodu'
               : '▶ Započni akviziciju')}
        </button>
      </div>
    </div>
  );
}

function btn(bg, color) {
  return {
    background: bg, color, border: 'none', borderRadius: 6, padding: '10px 16px',
    fontFamily: C.fontMono, fontSize: 12, cursor: 'pointer',
  };
}
