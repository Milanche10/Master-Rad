import { useState, useRef, useEffect } from 'react';
import { C } from '../utils/constants';
import * as api from '../utils/api';

// Kompaktna horizontalna traka za izvoz — stoji na vrhu bilo kog taba.
// view: 'dashboard'|'timeline'|'correlations'|'evidence'|'report' ili 'module:<id>'
// label: kratak ljudski opis (opcion).
const FORMATS = [
  ['pdf',  'PDF'],
  ['docx', 'Word'],
  ['html', 'HTML'],
  ['txt',  'TXT'],
];

export default function ExportManager({ sessionId, view, label }) {
  const [busy, setBusy] = useState(null);   // format koji se trenutno preuzima, ili 'zip'
  const [failed, setFailed] = useState(false);
  const errTimer = useRef(null);
  const mounted = useRef(true);

  useEffect(() => {
    return () => {
      mounted.current = false;
      if (errTimer.current) clearTimeout(errTimer.current);
    };
  }, []);

  const disabled = !sessionId || busy !== null;

  const flashError = () => {
    if (!mounted.current) return;
    setFailed(true);
    if (errTimer.current) clearTimeout(errTimer.current);
    errTimer.current = setTimeout(() => {
      if (mounted.current) setFailed(false);
    }, 4000);
  };

  const doExport = async (fmt) => {
    if (!sessionId || busy !== null) return;
    setFailed(false);
    setBusy(fmt);
    try {
      await api.downloadExport(sessionId, view, fmt);
    } catch (e) {
      flashError();
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const doZip = async () => {
    if (!sessionId || busy !== null) return;
    setFailed(false);
    setBusy('zip');
    try {
      await api.downloadCaseZip(sessionId);
    } catch (e) {
      flashError();
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      flexWrap: 'wrap',
    }}>
      {/* Pill kontejner sa formatima */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 4,
        background: C.bgCard,
        border: `1px solid ${C.border}`,
        borderRadius: 6,
        padding: '4px 6px',
      }}>
        <span style={{
          fontFamily: C.fontMono,
          fontSize: 9,
          color: C.textMuted,
          letterSpacing: 2,
          padding: '0 4px',
          userSelect: 'none',
        }}>
          IZVOZ{label ? ` · ${label}` : ''}
        </span>

        {FORMATS.map(([fmt, txt]) => {
          const active = busy === fmt;
          return (
            <button
              key={fmt}
              onClick={() => doExport(fmt)}
              disabled={disabled}
              title={`Izvezi u ${txt}`}
              style={{
                background: active ? C.accentDim : 'transparent',
                color: disabled ? C.textMuted : (active ? C.accent : C.textSecondary),
                border: `1px solid ${active ? C.accent + '66' : C.border}`,
                borderRadius: 4,
                padding: '3px 9px',
                fontFamily: C.fontMono,
                fontSize: 10,
                letterSpacing: 1,
                cursor: disabled ? 'default' : 'pointer',
                opacity: disabled && !active ? 0.55 : 1,
                transition: 'color .12s, border-color .12s',
              }}
            >
              {active ? '…' : txt}
            </button>
          );
        })}
      </div>

      {/* Ceo slučaj kao .zip — suptilno */}
      <button
        onClick={doZip}
        disabled={disabled}
        title="Preuzmi ceo slučaj kao .zip arhivu"
        style={{
          background: 'transparent',
          color: disabled ? C.textMuted : C.textSecondary,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: '5px 11px',
          fontFamily: C.fontMono,
          fontSize: 10,
          letterSpacing: 1,
          cursor: disabled ? 'default' : 'pointer',
          opacity: disabled && busy !== 'zip' ? 0.55 : 1,
          transition: 'color .12s, border-color .12s',
        }}
      >
        {busy === 'zip' ? '… ceo slučaj' : '⧉ ceo slučaj (.zip)'}
      </button>

      {/* Poruka o grešci */}
      {failed && (
        <span style={{
          fontFamily: C.fontMono,
          fontSize: 10,
          color: C.red,
          letterSpacing: 1,
        }}>
          izvoz nije uspeo
        </span>
      )}
    </div>
  );
}
