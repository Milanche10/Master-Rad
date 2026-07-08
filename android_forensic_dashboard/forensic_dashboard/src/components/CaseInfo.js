import { useState, useEffect } from 'react';
import { C } from '../utils/constants';
import { getCaseInfo } from '../utils/api';

function Stat({ label, value, color }) {
  return (
    <div style={{ background: C.bgPanel, border: `1px solid ${C.border}`, borderRadius: 6, padding: '12px 14px' }}>
      <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 1, marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: C.fontMono, fontSize: 18, color: color || C.textPrimary }}>{value}</div>
    </div>
  );
}

export default function CaseInfo({ sessionId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const load = async () => {
    if (!sessionId) return;
    setLoading(true); setError(null);
    try {
      setData(await getCaseInfo(sessionId));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [sessionId]);

  const chain = data?.audit_chain;
  const repro = data?.reproducible;

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            CHAIN OF CUSTODY
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            Slučaj, verzije i audit trag
          </h2>
        </div>
        <button onClick={load} style={{
          background: 'transparent', color: C.textMuted, border: `1px solid ${C.border}`,
          borderRadius: 4, padding: '6px 14px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer',
        }}>↻ Osvježi</button>
      </div>

      {loading && <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 12 }}>⟳ Učitavam...</div>}
      {error && <div style={{ color: C.red, fontSize: 12 }}>Greška: {error}</div>}

      {data && (
        <>
          {/* Integrity strip */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            <Stat label="ID SLUČAJA" value={data.case?.case_id?.slice(0, 12) || '—'} />
            <Stat label="ANALIZA (RUNS)" value={data.runs?.length || 0} color={C.accent} />
            <Stat label="AUDIT LANAC" value={chain?.valid ? '✓ VALIDAN' : '✗ NARUŠEN'} color={chain?.valid ? C.green : C.red} />
            <Stat label="REPRODUCIBILNO"
              value={repro?.verifiable ? (repro.reproducible ? '✓ DA' : '✗ NE') : 'N/A'}
              color={repro?.verifiable ? (repro.reproducible ? C.green : C.red) : C.textMuted} />
          </div>

          {/* Case meta */}
          <div style={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 6, padding: 16, marginBottom: 20 }}>
            <div style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, letterSpacing: 1, marginBottom: 10 }}>DETALJI SLUČAJA</div>
            {[['Veštak', data.case?.examiner], ['Uređaj', data.case?.title], ['Otvoreno', data.case?.created_at], ['Status', data.case?.status]].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', gap: 12, padding: '5px 0', borderBottom: `1px solid ${C.border}` }}>
                <div style={{ width: 120, color: C.textMuted, fontFamily: C.fontMono, fontSize: 11 }}>{k}</div>
                <div style={{ color: C.textPrimary, fontFamily: C.fontMono, fontSize: 12 }}>{v || '—'}</div>
              </div>
            ))}
          </div>

          {/* Runs (versions) */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, letterSpacing: 1, marginBottom: 10 }}>
              VERZIJE ANALIZE (immutable — reproducibilnost preko result_hash)
            </div>
            {(data.runs || []).map((r) => (
              <div key={r.run_id} style={{ background: C.bgPanel, border: `1px solid ${C.border}`, borderRadius: 4, padding: '8px 12px', marginBottom: 5, display: 'flex', gap: 14, alignItems: 'center' }}>
                <span style={{ fontFamily: C.fontMono, fontSize: 11, color: C.accent }}>{r.run_id?.slice(0, 12)}</span>
                <span style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted }}>{r.created_at}</span>
                <span style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textSecondary, marginLeft: 'auto' }}>
                  hash: {r.result_hash?.slice(0, 16)}…
                </span>
              </div>
            ))}
          </div>

          {/* Audit trail */}
          <div>
            <div style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, letterSpacing: 1, marginBottom: 10 }}>
              AUDIT TRAG (hash-chained — {chain?.count || 0} zapisa, tamper-evident)
            </div>
            <div style={{ maxHeight: 300, overflow: 'auto' }}>
              {(data.audit || []).slice().reverse().map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, padding: '5px 10px', borderBottom: `1px solid ${C.border}`, fontFamily: C.fontMono, fontSize: 11 }}>
                  <span style={{ color: C.textMuted, width: 150 }}>{ev.ts}</span>
                  <span style={{ color: C.accent, width: 130 }}>{ev.action}</span>
                  <span style={{ color: C.textSecondary }}>{ev.actor}</span>
                  <span style={{ color: C.textMuted, marginLeft: 'auto' }}>{(ev.hash || '').slice(0, 10)}…</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
