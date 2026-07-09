import { useState, useMemo } from 'react';
import { C, ARTIFACT_COLORS, ARTIFACT_ICONS } from '../utils/constants';
import * as api from '../utils/api';

// Formatiranje vremena — bez fabrikovanja: ako ts ne postoji, prazno
function fmtTs(ts) {
  if (!ts) return '';
  try {
    return String(ts).slice(0, 16).replace('T', ' ');
  } catch {
    return String(ts);
  }
}

// Skraćivanje dugih vrednosti za prikaz u tabeli
function truncate(v, n = 80) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'string' ? v : (() => {
    try { return JSON.stringify(v); } catch { return String(v); }
  })();
  return s.length > n ? s.slice(0, n) + '…' : s;
}

const FORMATS = [
  ['pdf', 'PDF'],
  ['docx', 'Word'],
  ['html', 'HTML'],
  ['txt', 'TXT'],
];

const th = {
  textAlign: 'left',
  fontFamily: C.fontMono,
  fontSize: 9,
  color: C.textMuted,
  letterSpacing: 1,
  fontWeight: 400,
  padding: '8px 10px',
  borderBottom: `1px solid ${C.border}`,
  whiteSpace: 'nowrap',
  position: 'sticky',
  top: 0,
  background: C.bgPanel,
  zIndex: 1,
};

const td = {
  padding: '7px 10px',
  fontSize: 11,
  color: C.textSecondary,
  borderBottom: `1px solid ${C.border}`,
  verticalAlign: 'middle',
};

export default function EvidenceBrowser({ sessionId, results, onOpen }) {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('sve');
  const [moduleFilter, setModuleFilter] = useState('svi');
  const [fmt, setFmt] = useState('pdf');
  const [selected, setSelected] = useState(() => new Set());

  // Spljošti sve artefakte iz svih modula u jedinstvenu listu
  const allArtifacts = useMemo(() => {
    if (!results) return [];
    const out = [];
    Object.entries(results).forEach(([moduleId, mod]) => {
      const arts = (mod && mod.artifacts) || [];
      arts.forEach((a, i) => {
        out.push({
          ...a,
          module: a.module || moduleId,
          _module: moduleId,
          _key: a.id != null ? String(a.id) : `${moduleId}:${i}`,
        });
      });
    });
    return out;
  }, [results]);

  // Jedinstveni tipovi i moduli za <select>
  const types = useMemo(() => {
    const s = new Set();
    allArtifacts.forEach(a => { if (a.type) s.add(a.type); });
    return Array.from(s).sort();
  }, [allArtifacts]);

  const modules = useMemo(() => {
    const s = new Set();
    allArtifacts.forEach(a => { if (a.module) s.add(a.module); });
    return Array.from(s).sort();
  }, [allArtifacts]);

  // Live filtriranje
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allArtifacts.filter(a => {
      if (typeFilter !== 'sve' && a.type !== typeFilter) return false;
      if (moduleFilter !== 'svi' && a.module !== moduleFilter) return false;
      if (q) {
        const hay = [
          a.value != null ? (typeof a.value === 'string' ? a.value : JSON.stringify(a.value)) : '',
          a.source || '',
          a.module || '',
        ].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allArtifacts, search, typeFilter, moduleFilter]);

  const total = allArtifacts.length;
  const filteredKeys = useMemo(() => filtered.map(a => a._key), [filtered]);
  const allSelected = filtered.length > 0 && filteredKeys.every(k => selected.has(k));
  const someSelected = filteredKeys.some(k => selected.has(k));

  const toggleAll = () => {
    setSelected(prev => {
      const next = new Set(prev);
      if (allSelected) {
        filteredKeys.forEach(k => next.delete(k));
      } else {
        filteredKeys.forEach(k => next.add(k));
      }
      return next;
    });
  };

  const toggleOne = (key) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const doExportView = () => {
    api.downloadExport(sessionId, 'evidence', fmt);
  };

  const doExportArtifact = (e, artifact) => {
    e.stopPropagation();
    api.exportArtifact(sessionId, artifact, fmt);
  };

  const doCaseZip = () => {
    api.downloadCaseZip(sessionId);
  };

  // Prazno stanje — nema pokrenutih modula / artefakata
  if (total === 0) {
    return (
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 60,
        color: C.textMuted,
        gap: 16,
      }}>
        <span style={{ fontFamily: C.fontMono, fontSize: 32 }}>▤</span>
        <div style={{ fontSize: 13, textAlign: 'center' }}>
          Pokreni module da bi se popunio evidence pregled
        </div>
      </div>
    );
  }

  const inputStyle = {
    background: C.bgInput,
    color: C.textPrimary,
    border: `1px solid ${C.border}`,
    borderRadius: 4,
    padding: '6px 10px',
    fontFamily: C.fontMono,
    fontSize: 11,
    outline: 'none',
  };

  const selectStyle = {
    ...inputStyle,
    cursor: 'pointer',
  };

  const btnStyle = {
    background: C.accentDim,
    color: C.accent,
    border: `1px solid ${C.accent}44`,
    borderRadius: 4,
    padding: '6px 14px',
    fontFamily: C.fontMono,
    fontSize: 11,
    cursor: 'pointer',
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '24px 28px' }}>
      {/* Zaglavlje */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexShrink: 0 }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            PREGLED DOKAZA
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            {filtered.length} / {total} artefakata
            {selected.size > 0 && (
              <span style={{ color: C.accent, fontSize: 12, marginLeft: 10 }}>· {selected.size} izabrano</span>
            )}
          </h2>
        </div>
        <button onClick={doCaseZip} style={{
          background: 'transparent',
          color: C.textSecondary,
          border: `1px solid ${C.border}`,
          borderRadius: 4,
          padding: '6px 14px',
          fontFamily: C.fontMono,
          fontSize: 11,
          cursor: 'pointer',
        }}>
          ⤓ Preuzmi ceo slučaj (.zip)
        </button>
      </div>

      {/* Toolbar: pretraga + filteri */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center', flexShrink: 0 }}>
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Pretraga (vrednost / izvor / modul)…"
          style={{ ...inputStyle, flex: 1, minWidth: 220 }}
        />
        <span style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>TIP</span>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} style={selectStyle}>
          <option value="sve">sve</option>
          {types.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <span style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>MODUL</span>
        <select value={moduleFilter} onChange={e => setModuleFilter(e.target.value)} style={selectStyle}>
          <option value="svi">svi</option>
          {modules.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>

      {/* Export bar */}
      <div style={{
        display: 'flex',
        gap: 8,
        marginBottom: 12,
        flexWrap: 'wrap',
        alignItems: 'center',
        flexShrink: 0,
        borderTop: `1px solid ${C.border}`,
        borderBottom: `1px solid ${C.border}`,
        padding: '8px 0',
      }}>
        <span style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 1 }}>FORMAT</span>
        <select value={fmt} onChange={e => setFmt(e.target.value)} style={selectStyle}>
          {FORMATS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
        </select>
        <button onClick={doExportView} style={btnStyle}>⤓ Izvezi prikaz (evidence)</button>
      </div>

      {/* Tabela — skrolabilna oblast */}
      <div style={{
        flex: 1,
        overflow: 'auto',
        border: `1px solid ${C.border}`,
        borderRadius: 6,
        background: C.bgPanel,
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: 34 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 120 }} />
            <col />
            <col style={{ width: 180 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 90 }} />
            <col style={{ width: 44 }} />
          </colgroup>
          <thead>
            <tr>
              <th style={th}>
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={el => { if (el) el.indeterminate = !allSelected && someSelected; }}
                  onChange={toggleAll}
                  style={{ cursor: 'pointer', accentColor: C.accent }}
                  title="Izaberi sve (filtrirano)"
                />
              </th>
              <th style={th}>MODUL</th>
              <th style={th}>TIP</th>
              <th style={th}>VREDNOST</th>
              <th style={th}>IZVOR</th>
              <th style={th}>VREME</th>
              <th style={th}>POUZDANOST</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ ...td, textAlign: 'center', color: C.textMuted, padding: 24, fontFamily: C.fontMono }}>
                  Nema artefakata za zadati filter.
                </td>
              </tr>
            ) : filtered.map((a) => {
              const color = ARTIFACT_COLORS[a.type] || C.textSecondary;
              const icon = ARTIFACT_ICONS[a.type] || '◈';
              const isSel = selected.has(a._key);
              const valStr = typeof a.value === 'string' ? a.value
                : (a.value != null ? JSON.stringify(a.value) : '');
              return (
                <tr
                  key={a._key}
                  onClick={() => onOpen(a)}
                  style={{
                    cursor: 'pointer',
                    background: isSel ? C.accentDim : 'transparent',
                  }}
                  onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = C.bgCardHover; }}
                  onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}
                >
                  <td style={td} onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isSel}
                      onChange={() => toggleOne(a._key)}
                      style={{ cursor: 'pointer', accentColor: C.accent }}
                    />
                  </td>
                  <td style={{ ...td, fontFamily: C.fontMono, color: C.textMuted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.module}>
                    {a.module}
                  </td>
                  <td style={td}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color, fontFamily: C.fontMono, fontSize: 12, flexShrink: 0 }}>{icon}</span>
                      <span style={{ color, fontFamily: C.fontMono, fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.type || '—'}
                      </span>
                    </span>
                  </td>
                  <td style={{ ...td, color: C.textPrimary, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={valStr}>
                    {truncate(valStr) || <span style={{ color: C.textMuted }}>—</span>}
                  </td>
                  <td style={{ ...td, fontFamily: C.fontMono, fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.source || ''}>
                    {a.source || <span style={{ color: C.textMuted }}>—</span>}
                  </td>
                  <td style={{ ...td, fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, whiteSpace: 'nowrap' }}>
                    {fmtTs(a.ts) || '—'}
                  </td>
                  <td style={{ ...td, whiteSpace: 'nowrap' }}>
                    {a.confidence != null && a.confidence !== ''
                      ? <span style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textSecondary }}>{a.confidence}</span>
                      : <span style={{ color: C.textMuted }}>—</span>}
                  </td>
                  <td style={td} onClick={e => e.stopPropagation()}>
                    <button
                      onClick={e => doExportArtifact(e, a)}
                      title={`Izvezi artefakt (${fmt.toUpperCase()})`}
                      style={{
                        background: 'transparent',
                        color: C.textMuted,
                        border: `1px solid ${C.border}`,
                        borderRadius: 4,
                        padding: '2px 7px',
                        fontFamily: C.fontMono,
                        fontSize: 12,
                        cursor: 'pointer',
                        lineHeight: 1,
                      }}
                    >
                      ⤓
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
