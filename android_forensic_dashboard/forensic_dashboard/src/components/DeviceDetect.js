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

  const items = state[cfg.listKey] || [];

  const start = async () => {
    const item = items.find((it) => cfg.idOf(it) === selected);
    if (!item) return;
    setStarting(true);
    setErr(null);
    try {
      const { job_id } = await api.startAcquisition(source, cfg.body(item, examiner));
      onStarted(job_id, cfg.render(item).title);
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

      {err && (
        <div style={{ color: C.red, fontSize: 12, fontFamily: C.fontMono, margin: '10px 0' }}>⚠ {err}</div>
      )}

      <div style={{ display: 'flex', gap: 10, marginTop: 18 }}>
        {onBack && <button onClick={onBack} style={btn(C.bgCard, C.textSecondary)}>← Nazad</button>}
        <button
          onClick={start}
          disabled={!selected || starting}
          style={{
            ...btn(selected && !starting ? C.accent : C.accentDim, selected && !starting ? C.bg : C.textMuted),
            flex: 1, fontWeight: 600,
            cursor: selected && !starting ? 'pointer' : 'not-allowed',
          }}
        >
          {starting ? 'Pokretanje…' : '▶ Započni akviziciju'}
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
