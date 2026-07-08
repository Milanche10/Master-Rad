import { useState } from 'react';
import { C } from '../utils/constants';

export default function OpenDump({ onOpen, loading, error }) {
  const [path, setPath] = useState('');

  const handleSubmit = () => {
    if (path.trim()) onOpen(path.trim());
  };

  const examples = [
    'C:\\Forensics\\DFRWS\\Samsung_S10_dump',
    '/home/analyst/cases/case001/dump',
    'E:\\Cases\\2024\\S10\\filesystem',
  ];

  return (
    <div style={{
      flex: 1,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: C.bg,
      padding: 40,
    }}>
      <div style={{ width: '100%', maxWidth: 560 }}>

        {/* Header */}
        <div style={{ marginBottom: 40 }}>
          <div style={{
            fontFamily: C.fontMono,
            fontSize: 11,
            color: C.accent,
            letterSpacing: 3,
            textTransform: 'uppercase',
            marginBottom: 12,
          }}>
            Android Forensic Dashboard
          </div>
          <h1 style={{
            fontFamily: C.fontMono,
            fontSize: 28,
            fontWeight: 600,
            color: C.textPrimary,
            lineHeight: 1.2,
            marginBottom: 10,
          }}>
            Otvori dump
          </h1>
          <p style={{
            color: C.textSecondary,
            fontSize: 14,
            lineHeight: 1.6,
          }}>
            Unesi putanju do Android filesystem dump-a na lokalnom disku.
            Dashboard će automatski pronaći sve forenzičke artefakte.
          </p>
        </div>

        {/* Input */}
        <div style={{ marginBottom: 16 }}>
          <label style={{
            display: 'block',
            fontFamily: C.fontMono,
            fontSize: 10,
            color: C.textMuted,
            letterSpacing: 1,
            marginBottom: 8,
          }}>
            PUTANJA DO DUMP FOLDERA
          </label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              value={path}
              onChange={e => setPath(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="/putanja/do/dump"
              style={{
                flex: 1,
                background: C.bgInput,
                border: `1px solid ${path ? C.borderFocus : C.border}`,
                borderRadius: 6,
                padding: '10px 14px',
                color: C.textCode,
                fontFamily: C.fontMono,
                fontSize: 13,
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              onFocus={e => e.target.style.borderColor = C.borderFocus}
              onBlur={e => e.target.style.borderColor = path ? C.borderFocus : C.border}
            />
            <button
              onClick={handleSubmit}
              disabled={!path.trim() || loading}
              style={{
                background: path.trim() && !loading ? C.accent : C.accentDim,
                color: path.trim() && !loading ? C.bg : C.textMuted,
                border: 'none',
                borderRadius: 6,
                padding: '10px 20px',
                fontFamily: C.fontMono,
                fontSize: 12,
                fontWeight: 600,
                cursor: path.trim() && !loading ? 'pointer' : 'not-allowed',
                whiteSpace: 'nowrap',
                transition: 'background 0.2s',
              }}
            >
              {loading ? '...' : 'Otvori →'}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            background: C.redDim,
            border: `1px solid ${C.red}44`,
            borderRadius: 6,
            padding: '10px 14px',
            color: C.red,
            fontSize: 12,
            fontFamily: C.fontMono,
            marginBottom: 16,
          }}>
            ⚠ {error}
          </div>
        )}

        {/* Divider */}
        <div style={{
          height: 1,
          background: C.border,
          margin: '24px 0',
        }} />

        {/* Primeri putanja */}
        <div>
          <div style={{
            fontFamily: C.fontMono,
            fontSize: 9,
            color: C.textMuted,
            letterSpacing: 1,
            marginBottom: 10,
          }}>
            PRIMERI PUTANJA
          </div>
          {examples.map(ex => (
            <button
              key={ex}
              onClick={() => setPath(ex)}
              style={{
                display: 'block',
                width: '100%',
                textAlign: 'left',
                background: 'transparent',
                border: `1px solid ${C.border}`,
                borderRadius: 4,
                padding: '7px 12px',
                color: C.textMuted,
                fontFamily: C.fontMono,
                fontSize: 11,
                cursor: 'pointer',
                marginBottom: 6,
                transition: 'border-color 0.15s, color 0.15s',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = C.borderFocus;
                e.currentTarget.style.color = C.textSecondary;
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = C.border;
                e.currentTarget.style.color = C.textMuted;
              }}
            >
              {ex}
            </button>
          ))}
        </div>

        {/* Info box */}
        <div style={{
          marginTop: 24,
          background: C.bgCard,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: '12px 14px',
        }}>
          <div style={{ color: C.textMuted, fontSize: 11, lineHeight: 1.6 }}>
            <span style={{ color: C.accent, fontFamily: C.fontMono }}>ℹ</span>
            {' '}Dump se otvara u <strong style={{ color: C.textSecondary }}>read-only</strong> režimu.
            Originalni fajlovi se ne menjaju. Svi pristupi se loguju radi Chain of Custody.
          </div>
        </div>
      </div>
    </div>
  );
}
