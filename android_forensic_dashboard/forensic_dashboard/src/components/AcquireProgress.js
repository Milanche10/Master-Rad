import { useState, useEffect, useRef } from 'react';
import { C } from '../utils/constants';
import * as api from '../utils/api';

const STATUS_LABEL = {
  running: { text: 'AKVIZICIJA U TOKU', color: C.yellow },
  done: { text: 'ZAVRŠENO', color: C.green },
  cancelled: { text: 'OTKAZANO', color: C.textMuted },
  error: { text: 'GREŠKA', color: C.red },
};

export default function AcquireProgress({ jobId, targetLabel, onDone, onCancelled, onBack }) {
  const [job, setJob] = useState(null);
  const [canceling, setCanceling] = useState(false);
  const logRef = useRef(null);
  const doneRef = useRef(false);

  useEffect(() => {
    if (!jobId) return;
    let alive = true;
    const poll = async () => {
      try {
        const j = await api.getAcquireJob(jobId);
        if (!alive) return;
        setJob(j);
        if (!doneRef.current && j.status === 'done') {
          doneRef.current = true;
          onDone && onDone(j.result || {}, j);
        } else if (!doneRef.current && j.status === 'cancelled') {
          doneRef.current = true;
          onCancelled && onCancelled(j);
        }
      } catch (e) {
        // Posao je in-memory; ako backend restartuje, prekini polling.
        if (alive) setJob((prev) => prev || { status: 'error', message: e.message, logs: [] });
      }
    };
    poll();
    const id = setInterval(() => {
      if (doneRef.current) { clearInterval(id); return; }
      poll();
    }, 1000);
    return () => { alive = false; clearInterval(id); };
  }, [jobId, onDone, onCancelled]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [job]);

  const cancel = async () => {
    setCanceling(true);
    try { await api.cancelAcquireJob(jobId); } catch (e) { /* ignore */ }
  };

  const status = job?.status || 'running';
  const meta = STATUS_LABEL[status] || STATUS_LABEL.running;
  const pct = job?.progress || 0;
  const isTerminal = status === 'done' || status === 'cancelled' || status === 'error';

  return (
    <div style={{ maxWidth: 720, width: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <h2 style={{ fontFamily: C.fontMono, fontSize: 18, color: C.textPrimary, margin: 0 }}>
          Akvizicija dokaza
        </h2>
        <span style={{ fontFamily: C.fontMono, fontSize: 10, letterSpacing: 1, color: meta.color }}>
          ● {meta.text}
        </span>
      </div>
      {targetLabel && (
        <div style={{ color: C.textSecondary, fontSize: 12, fontFamily: C.fontMono, marginBottom: 14 }}>
          Izvor: {targetLabel}
        </div>
      )}

      {/* Progress bar */}
      <div style={{ marginBottom: 6, display: 'flex', justifyContent: 'space-between' }}>
        <span style={{ color: C.textSecondary, fontSize: 12 }}>{job?.message || 'Priprema…'}</span>
        <span style={{ color: C.textCode, fontFamily: C.fontMono, fontSize: 12 }}>{pct}%</span>
      </div>
      <div style={{ height: 8, background: C.border, borderRadius: 4, overflow: 'hidden', marginBottom: 18 }}>
        <div style={{
          height: '100%', width: `${pct}%`,
          background: status === 'error' ? C.red : status === 'done' ? C.green : C.accent,
          transition: 'width 0.4s ease',
        }} />
      </div>

      {/* Live logovi */}
      <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 1, marginBottom: 6 }}>
        LOG AKVIZICIJE {job?.log_count ? `(${job.log_count})` : ''}
      </div>
      <div ref={logRef} style={{
        background: C.bgInput, border: `1px solid ${C.border}`, borderRadius: 8,
        padding: 12, height: 260, overflowY: 'auto',
        fontFamily: C.fontMono, fontSize: 11, lineHeight: 1.6, color: C.textSecondary,
      }}>
        {(job?.logs || []).map((l, i) => (
          <div key={i} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{l}</div>
        ))}
        {!job && <div style={{ color: C.textMuted }}>Povezivanje sa poslom…</div>}
      </div>

      {status === 'error' && (
        <div style={{ color: C.red, fontSize: 12, fontFamily: C.fontMono, marginTop: 12 }}>
          ⚠ {job?.error || job?.message}
        </div>
      )}

      {/* Akcije */}
      <div style={{ display: 'flex', gap: 10, marginTop: 18 }}>
        {!isTerminal && (
          <button onClick={cancel} disabled={canceling} style={{
            background: C.redDim, color: C.red, border: `1px solid ${C.red}44`, borderRadius: 6,
            padding: '10px 18px', fontFamily: C.fontMono, fontSize: 12, cursor: 'pointer',
          }}>{canceling ? 'Otkazivanje…' : '✕ Otkaži'}</button>
        )}
        {isTerminal && onBack && (
          <button onClick={onBack} style={{
            background: C.bgCard, color: C.textSecondary, border: 'none', borderRadius: 6,
            padding: '10px 18px', fontFamily: C.fontMono, fontSize: 12, cursor: 'pointer',
          }}>← Nazad na izbor izvora</button>
        )}
      </div>
    </div>
  );
}
