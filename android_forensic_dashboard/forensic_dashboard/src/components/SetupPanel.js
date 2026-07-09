import { useState, useEffect, useRef, useCallback } from 'react';
import { C } from '../utils/constants';
import * as api from '../utils/api';

// Panel „Zavisnosti / Setup": aplikacija sama preuzme i instalira ono što joj
// treba (adb za telefon, Ollama + AI model za AI zaključak) — bez ručne
// instalacije. Poslovi se prate preko istog job store-a kao akvizicija.
export default function SetupPanel({ embedded }) {
  const [status, setStatus] = useState(null);
  const [job, setJob] = useState(null);      // { kind, id }
  const [prog, setProg] = useState(null);
  const timer = useRef(null);

  const refresh = useCallback(async () => {
    try { setStatus(await api.getSetupStatus()); } catch (e) { setStatus({ error: e.message }); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => () => clearInterval(timer.current), []);

  const runJob = async (kind) => {
    setProg({ progress: 0, message: 'Pokretanje…', logs: [], status: 'running' });
    try {
      const { job_id } = kind === 'adb' ? await api.startSetupAdb() : await api.startSetupOllama();
      setJob({ kind, id: job_id });
      clearInterval(timer.current);
      timer.current = setInterval(async () => {
        try {
          const j = await api.getAcquireJob(job_id);
          setProg(j);
          if (['done', 'error', 'cancelled'].includes(j.status)) {
            clearInterval(timer.current);
            refresh();
          }
        } catch (e) { clearInterval(timer.current); }
      }, 1000);
    } catch (e) {
      setProg({ status: 'error', message: e.message, logs: [] });
    }
  };

  const cancel = async () => { if (job) { try { await api.cancelAcquireJob(job.id); } catch (e) {} } };

  const adb = status?.adb || {};
  const oll = status?.ollama || {};
  const busy = prog && prog.status === 'running';

  return (
    <div style={{ padding: embedded ? 0 : '24px 28px', maxWidth: 760, width: '100%', overflowY: 'auto' }}>
      {!embedded && (
        <>
          <h1 style={{ fontFamily: C.fontMono, fontSize: 20, color: C.textPrimary, margin: '0 0 4px' }}>
            Zavisnosti aplikacije
          </h1>
          <p style={{ color: C.textSecondary, fontSize: 13, marginBottom: 20, lineHeight: 1.6 }}>
            Aplikacija sama preuzima i instalira ono što joj treba — ne moraš ništa ručno da instaliraš.
            SD/USB analiza i izvoz rade i bez ovoga.
          </p>
        </>
      )}

      <DepCard
        icon="📱" title="adb — akvizicija telefona"
        ready={adb.found}
        readyText={adb.bundled ? 'Ugrađen uz aplikaciju' : (adb.path || 'Instalirano')}
        desc="Android platform-tools (mali paket, ~15 MB). Potrebno samo za akviziciju povezanog telefona."
        onInstall={() => runJob('adb')}
        installLabel="Instaliraj adb"
        disabled={busy}
      />

      <DepCard
        icon="🧠" title="AI — Ollama + model"
        ready={oll.model_ready}
        readyText={oll.model_ready ? `Model spreman: ${oll.model}` :
                   (oll.installed ? 'Ollama instaliran, model nije preuzet' : 'Nije instalirano')}
        desc={`AI forenzički zaključak (lokalni model „${oll.model || 'qwen3:32b'}"). ` +
              `⚠ VELIKO preuzimanje (GB) — može dugo trajati. Sve ostalo radi i bez ovoga.`}
        onInstall={() => runJob('ollama')}
        installLabel="Instaliraj AI (Ollama + model)"
        disabled={busy}
        warn
      />

      {/* Napredak instalacije */}
      {prog && (
        <div style={{ marginTop: 18, background: C.bgCard, border: `1px solid ${C.border}`,
          borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ color: C.textSecondary, fontSize: 12 }}>
              {job?.kind === 'ollama' ? 'AI (Ollama + model)' : 'adb'} — {prog.message || prog.status}
            </span>
            <span style={{ color: C.textCode, fontFamily: C.fontMono, fontSize: 12 }}>{prog.progress || 0}%</span>
          </div>
          <div style={{ height: 6, background: C.border, borderRadius: 3, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${prog.progress || 0}%`,
              background: prog.status === 'error' ? C.red : prog.status === 'done' ? C.green : C.accent,
              transition: 'width .4s' }} />
          </div>
          {(prog.logs || []).length > 0 && (
            <div style={{ marginTop: 10, maxHeight: 160, overflowY: 'auto', background: C.bgInput,
              borderRadius: 6, padding: 8, fontFamily: C.fontMono, fontSize: 10, color: C.textSecondary,
              lineHeight: 1.6 }}>
              {prog.logs.slice(-40).map((l, i) => (
                <div key={i} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{l}</div>
              ))}
            </div>
          )}
          {prog.status === 'error' && (
            <div style={{ color: C.red, fontSize: 12, marginTop: 8 }}>⚠ {prog.error || prog.message}</div>
          )}
          {busy && (
            <button onClick={cancel} style={{ marginTop: 10, background: C.redDim, color: C.red,
              border: `1px solid ${C.red}44`, borderRadius: 6, padding: '6px 14px',
              fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer' }}>✕ Otkaži</button>
          )}
        </div>
      )}

      {status?.error && (
        <div style={{ color: C.red, fontSize: 12, marginTop: 12 }}>⚠ {status.error}</div>
      )}
    </div>
  );
}

function DepCard({ icon, title, ready, readyText, desc, onInstall, installLabel, disabled, warn }) {
  return (
    <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', background: C.bgCard,
      border: `1px solid ${ready ? C.green + '44' : C.border}`, borderRadius: 10, padding: 16, marginBottom: 12 }}>
      <span style={{ fontSize: 26 }}>{icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: C.textPrimary, fontFamily: C.fontMono, fontSize: 14, fontWeight: 600 }}>{title}</span>
          <span style={{ fontFamily: C.fontMono, fontSize: 9, letterSpacing: 1, padding: '2px 6px',
            borderRadius: 3, color: ready ? C.green : C.yellow, background: ready ? C.greenDim : C.yellowDim }}>
            {ready ? '● SPREMNO' : '○ NIJE'}
          </span>
        </div>
        <div style={{ color: ready ? C.green : C.textMuted, fontSize: 11, fontFamily: C.fontMono, margin: '4px 0' }}>
          {readyText}
        </div>
        <div style={{ color: C.textSecondary, fontSize: 12, lineHeight: 1.5 }}>{desc}</div>
      </div>
      {!ready && (
        <button onClick={onInstall} disabled={disabled} style={{
          background: disabled ? C.accentDim : (warn ? C.orangeDim : C.accent),
          color: disabled ? C.textMuted : (warn ? C.orange : C.bg),
          border: warn ? `1px solid ${C.orange}55` : 'none', borderRadius: 6, padding: '9px 14px',
          fontFamily: C.fontMono, fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap',
          cursor: disabled ? 'not-allowed' : 'pointer' }}>
          {installLabel}
        </button>
      )}
    </div>
  );
}
