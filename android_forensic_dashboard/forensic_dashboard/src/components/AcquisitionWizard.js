import { useState, useEffect } from 'react';
import { C } from '../utils/constants';
import * as api from '../utils/api';
import DeviceDetect from './DeviceDetect';
import AcquireProgress from './AcquireProgress';

const SOURCES = [
  { id: 'mobile', icon: '📱', label: 'Mobilni telefon', desc: 'USB akvizicija (adb) ili postojeći dump' },
  { id: 'sim', icon: '📶', label: 'SIM kartica', desc: 'ICCID, IMSI, operater, kontakti, SMS' },
  { id: 'sdcard', icon: '💾', label: 'SD kartica', desc: 'Puna akvizicija fajlova + heš (MD5/SHA)' },
  { id: 'usb', icon: '🔌', label: 'USB fleš disk', desc: 'Puna akvizicija fajlova + heš (MD5/SHA)' },
  { id: 'dump', icon: '📁', label: 'Postojeći dump', desc: 'Analiziraj postojeći Evidence/dump folder' },
];

export default function AcquisitionWizard({ onAnalyze, loading, error }) {
  const [step, setStep] = useState('source');   // source|mobile-choice|dump|detect|progress|done
  const [source, setSource] = useState(null);
  const [examiner, setExaminer] = useState('');
  const [dumpPath, setDumpPath] = useState('');
  const [job, setJob] = useState({ id: null, label: '' });
  const [result, setResult] = useState(null);
  const [sources, setSources] = useState(null);
  const [busy, setBusy] = useState('');

  useEffect(() => { api.getSources().then(setSources).catch(() => {}); }, []);

  const pick = (id) => {
    setSource(id);
    if (id === 'dump') setStep('dump');
    else if (id === 'mobile') setStep('mobile-choice');
    else setStep('detect');
  };

  const reset = () => { setStep('source'); setSource(null); setJob({ id: null, label: '' }); setResult(null); };

  const analyzeDump = () => {
    if (dumpPath.trim()) onAnalyze(dumpPath.trim(), { examiner, source: 'dump' });
  };

  const analyzeAcquired = () => {
    if (result?.evidence_path) {
      onAnalyze(result.evidence_path, { examiner, fsCaseId: result.case_id, source });
    }
  };

  const download = async (fn) => {
    setBusy(fn);
    try {
      if (fn === 'report') await api.downloadAcquisitionReport(result.case_id, 'pdf');
      if (fn === 'zip') await api.downloadAcquisitionPackage(result.case_id, 'zip');
    } catch (e) { /* ignore */ }
    setBusy('');
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', background: C.bg, padding: 40, overflowY: 'auto' }}>
      <div style={{ width: '100%', maxWidth: 780 }}>

        {/* Brend */}
        <div style={{ marginBottom: 26, textAlign: 'center' }}>
          <div style={{ fontFamily: C.fontMono, fontSize: 11, color: C.accent, letterSpacing: 4,
            textTransform: 'uppercase', marginBottom: 8 }}>Android Forensic Dashboard</div>
          <h1 style={{ fontFamily: C.fontMono, fontSize: 26, fontWeight: 600, color: C.textPrimary, margin: 0 }}>
            Forenzička akvizicija dokaza
          </h1>
        </div>

        {/* Veštak (chain of custody) — uvek vidljiv */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center',
          marginBottom: 26 }}>
          <label style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, letterSpacing: 1 }}>
            VEŠTAK
          </label>
          <input value={examiner} onChange={(e) => setExaminer(e.target.value)}
            placeholder="ime i prezime (chain of custody)"
            style={{ background: C.bgInput, border: `1px solid ${C.border}`, borderRadius: 6,
              padding: '8px 12px', color: C.textCode, fontFamily: C.fontMono, fontSize: 12,
              width: 320, outline: 'none' }} />
        </div>

        {(error) && (
          <div style={{ background: C.redDim, border: `1px solid ${C.red}44`, borderRadius: 6,
            padding: '10px 14px', color: C.red, fontSize: 12, fontFamily: C.fontMono, marginBottom: 16 }}>
            ⚠ {error}
          </div>
        )}

        {/* KORAK: izbor izvora */}
        {step === 'source' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
            {SOURCES.map((s) => {
              const rdy = sources?.sources?.[s.id];
              return (
                <button key={s.id} onClick={() => pick(s.id)} style={{
                  background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 10,
                  padding: '20px 18px', cursor: 'pointer', textAlign: 'left', transition: 'border-color .15s, background .15s' }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.background = C.bgCardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = C.bgCard; }}>
                  <div style={{ fontSize: 30, marginBottom: 10 }}>{s.icon}</div>
                  <div style={{ color: C.textPrimary, fontFamily: C.fontMono, fontSize: 14, fontWeight: 600, marginBottom: 4 }}>
                    {s.label}
                  </div>
                  <div style={{ color: C.textSecondary, fontSize: 12, lineHeight: 1.5 }}>{s.desc}</div>
                  {rdy && !rdy.ready && s.id !== 'dump' && (
                    <div style={{ color: C.yellow, fontSize: 10, fontFamily: C.fontMono, marginTop: 8 }}>
                      ⚠ {rdy.hint || 'alat nije spreman'}
                    </div>
                  )}
                  {rdy && rdy.ready && s.id !== 'dump' && (
                    <div style={{ color: C.green, fontSize: 10, fontFamily: C.fontMono, marginTop: 8 }}>
                      ● spremno ({rdy.tool})
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {/* KORAK: telefon — dve opcije */}
        {step === 'mobile-choice' && (
          <div style={{ maxWidth: 560, margin: '0 auto' }}>
            <Card onClick={() => { setSource('dump'); setStep('dump'); }}
              icon="📁" title="Analiziraj postojeći dump"
              desc="Izaberi već napravljen Evidence/dump folder — koristi se postojeći analitički engine." />
            <Card onClick={() => setStep('detect')}
              icon="📱" title="Akvizicija sa povezanog telefona"
              desc="Poveži telefon USB-om (USB debugging) — adb logička akvizicija u novi slučaj." />
            <BackBtn onClick={reset} />
          </div>
        )}

        {/* KORAK: unos putanje postojećeg dump-a */}
        {step === 'dump' && (
          <div style={{ maxWidth: 620, margin: '0 auto' }}>
            <h2 style={{ fontFamily: C.fontMono, fontSize: 18, color: C.textPrimary }}>Otvori postojeći dump</h2>
            <p style={{ color: C.textSecondary, fontSize: 13, marginBottom: 14 }}>
              Unesi putanju do Android filesystem dump/Evidence foldera na lokalnom disku.
            </p>
            <div style={{ display: 'flex', gap: 8 }}>
              <input value={dumpPath} onChange={(e) => setDumpPath(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && analyzeDump()}
                placeholder="C:\\Cases\\...\\Evidence"
                style={{ flex: 1, background: C.bgInput, border: `1px solid ${dumpPath ? C.borderFocus : C.border}`,
                  borderRadius: 6, padding: '10px 14px', color: C.textCode, fontFamily: C.fontMono, fontSize: 13, outline: 'none' }} />
              <button onClick={analyzeDump} disabled={!dumpPath.trim() || loading} style={{
                background: dumpPath.trim() && !loading ? C.accent : C.accentDim,
                color: dumpPath.trim() && !loading ? C.bg : C.textMuted, border: 'none', borderRadius: 6,
                padding: '10px 20px', fontFamily: C.fontMono, fontSize: 12, fontWeight: 600,
                cursor: dumpPath.trim() && !loading ? 'pointer' : 'not-allowed' }}>
                {loading ? '...' : 'Analiziraj →'}
              </button>
            </div>
            <BackBtn onClick={reset} />
          </div>
        )}

        {/* KORAK: detekcija uređaja/diska/čitača */}
        {step === 'detect' && (
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <DeviceDetect source={source} examiner={examiner}
              onStarted={(jobId, label) => { setJob({ id: jobId, label }); setStep('progress'); }}
              onBack={reset} />
          </div>
        )}

        {/* KORAK: napredak akvizicije */}
        {step === 'progress' && (
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <AcquireProgress jobId={job.id} targetLabel={job.label}
              onDone={(res) => { setResult(res); setStep('done'); }}
              onCancelled={() => setStep('done')}
              onBack={reset} />
          </div>
        )}

        {/* KORAK: gotovo — analiza + izvoz */}
        {step === 'done' && (
          <div style={{ maxWidth: 620, margin: '0 auto' }}>
            <h2 style={{ fontFamily: C.fontMono, fontSize: 18, color: C.green }}>✓ Akvizicija završena</h2>
            {result && (
              <div style={{ background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 8,
                padding: 16, margin: '12px 0', fontFamily: C.fontMono, fontSize: 12, color: C.textSecondary, lineHeight: 1.9 }}>
                <div>Slučaj: <span style={{ color: C.textCode }}>{result.case_id}</span></div>
                {result.stats && <div>Kopirano fajlova: <span style={{ color: C.textCode }}>{result.stats.copied ?? '—'}</span> ({result.stats.bytes_human || ''})</div>}
                {result.manifest_summary && <div>Manifest: <span style={{ color: C.textCode }}>{result.manifest_summary.file_count}</span> zapisa sa MD5/SHA-1/SHA-256</div>}
                <div style={{ wordBreak: 'break-all' }}>Evidence: <span style={{ color: C.textMuted }}>{result.evidence_path}</span></div>
              </div>
            )}
            <button onClick={analyzeAcquired} disabled={!result?.evidence_path || loading} style={{
              width: '100%', background: C.accent, color: C.bg, border: 'none', borderRadius: 6,
              padding: '12px 20px', fontFamily: C.fontMono, fontSize: 13, fontWeight: 600, cursor: 'pointer', marginBottom: 10 }}>
              {loading ? '...' : 'Analiziraj dokaze →'}
            </button>
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={() => download('report')} disabled={busy === 'report'} style={secBtn()}>
                {busy === 'report' ? '…' : '⤓ Izveštaj (PDF)'}
              </button>
              <button onClick={() => download('zip')} disabled={busy === 'zip'} style={secBtn()}>
                {busy === 'zip' ? '…' : '⤓ Paket (.zip)'}
              </button>
              <button onClick={reset} style={secBtn()}>+ Nova akvizicija</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Card({ onClick, icon, title, desc }) {
  return (
    <button onClick={onClick} style={{ display: 'block', width: '100%', textAlign: 'left', marginBottom: 12,
      background: C.bgCard, border: `1px solid ${C.border}`, borderRadius: 10, padding: '16px 18px', cursor: 'pointer' }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accent; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <span style={{ fontSize: 24 }}>{icon}</span>
        <div>
          <div style={{ color: C.textPrimary, fontFamily: C.fontMono, fontSize: 14, fontWeight: 600 }}>{title}</div>
          <div style={{ color: C.textSecondary, fontSize: 12, marginTop: 3 }}>{desc}</div>
        </div>
      </div>
    </button>
  );
}

function BackBtn({ onClick }) {
  return (
    <button onClick={onClick} style={{ background: 'transparent', color: C.textMuted, border: 'none',
      fontFamily: C.fontMono, fontSize: 12, cursor: 'pointer', marginTop: 16, padding: '6px 0' }}>
      ← Nazad na izbor izvora
    </button>
  );
}

function secBtn() {
  return { flex: 1, background: C.bgCard, color: C.textSecondary, border: `1px solid ${C.border}`,
    borderRadius: 6, padding: '10px 14px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer' };
}
