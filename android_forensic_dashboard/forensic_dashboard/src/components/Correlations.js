import { C, CONFIDENCE_COLORS, ARTIFACT_COLORS, ARTIFACT_ICONS } from '../utils/constants';

function CorrelationCard({ corr }) {
  const confColor = CONFIDENCE_COLORS[corr.confidence] || C.textMuted;

  return (
    <div style={{
      background: C.bgCard,
      border: `1px solid ${C.border}`,
      borderLeft: `3px solid ${confColor}`,
      borderRadius: 6,
      padding: 18,
      marginBottom: 10,
    }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
        marginBottom: 10,
      }}>
        <span style={{
          fontFamily: C.fontMono,
          fontSize: 10,
          color: C.textMuted,
          flexShrink: 0,
          marginTop: 2,
          letterSpacing: 1,
        }}>
          {corr.id}
        </span>
        <h3 style={{
          flex: 1,
          color: C.textPrimary,
          fontSize: 14,
          fontWeight: 500,
          lineHeight: 1.3,
        }}>
          {corr.title}
        </h3>
        <span style={{
          background: confColor + '22',
          color: confColor,
          fontSize: 9,
          fontFamily: C.fontMono,
          padding: '3px 8px',
          borderRadius: 3,
          border: `1px solid ${confColor}44`,
          flexShrink: 0,
          letterSpacing: 1,
        }}>
          {corr.confidence}
        </span>
      </div>

      {/* Detail */}
      <p style={{
        color: C.textSecondary,
        fontSize: 12,
        lineHeight: 1.7,
        marginBottom: 12,
      }}>
        {corr.detail}
      </p>

      {/* Sources */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: corr.linked_artifacts?.length ? 12 : 0 }}>
        <span style={{
          color: C.textMuted,
          fontSize: 10,
          fontFamily: C.fontMono,
          marginRight: 4,
          alignSelf: 'center',
        }}>
          IZVORI:
        </span>
        {(corr.sources || []).map((src, i) => (
          <span key={i} style={{
            background: C.accentDim,
            color: C.accent,
            fontSize: 10,
            fontFamily: C.fontMono,
            padding: '2px 8px',
            borderRadius: 3,
            border: `1px solid ${C.accent}22`,
          }}>
            {src}
          </span>
        ))}
      </div>

      {/* Linked artifacts */}
      {corr.linked_artifacts?.length > 0 && (
        <div style={{
          borderTop: `1px solid ${C.border}`,
          paddingTop: 10,
          marginTop: 10,
        }}>
          <div style={{
            fontFamily: C.fontMono,
            fontSize: 9,
            color: C.textMuted,
            letterSpacing: 1,
            marginBottom: 6,
          }}>
            POVEZANI ARTEFAKTI
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {corr.linked_artifacts.map((a, i) => {
              const color = ARTIFACT_COLORS[a.type] || C.textSecondary;
              const icon = ARTIFACT_ICONS[a.type] || '◈';
              return (
                <div key={i} style={{
                  display: 'flex',
                  gap: 8,
                  alignItems: 'center',
                  background: C.bgPanel,
                  borderRadius: 4,
                  padding: '5px 10px',
                }}>
                  <span style={{ color, fontFamily: C.fontMono, fontSize: 11, flexShrink: 0 }}>{icon}</span>
                  <span style={{ color: C.textSecondary, fontSize: 11, fontFamily: C.fontMono, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.value}
                  </span>
                  {a.ts && (
                    <span style={{ color: C.textMuted, fontSize: 10, fontFamily: C.fontMono, flexShrink: 0 }}>
                      {a.ts.slice(0, 16).replace('T', ' ')}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Correlations({ correlations, onLoad, loading }) {
  if (!correlations?.length && !loading) {
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
        <span style={{ fontFamily: C.fontMono, fontSize: 32 }}>◈</span>
        <div style={{ fontSize: 13, textAlign: 'center' }}>
          Pokreni module analize pa klikni "Učitaj korelacije"
        </div>
        <button
          onClick={onLoad}
          style={{
            background: C.accentDim,
            color: C.accent,
            border: `1px solid ${C.accent}44`,
            borderRadius: 6,
            padding: '8px 20px',
            fontFamily: C.fontMono,
            fontSize: 12,
            cursor: 'pointer',
          }}
        >
          ◈ Učitaj korelacije
        </button>
      </div>
    );
  }

  const byConfidence = {
    VISOKA:  correlations.filter(c => c.confidence === 'VISOKA'),
    SREDNJA: correlations.filter(c => c.confidence === 'SREDNJA'),
    NISKA:   correlations.filter(c => c.confidence === 'NISKA'),
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            CROSS-REFERENTNA ANALIZA
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            {correlations.length} korelacija otkriveno
          </h2>
        </div>
        <button
          onClick={onLoad}
          style={{
            background: 'transparent',
            color: C.textMuted,
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            padding: '6px 14px',
            fontFamily: C.fontMono,
            fontSize: 11,
            cursor: 'pointer',
          }}
        >
          ↻ Osvježi
        </button>
      </div>

      {/* Grupiši po pouzdanosti */}
      {Object.entries(byConfidence).map(([conf, items]) => {
        if (!items.length) return null;
        return (
          <div key={conf} style={{ marginBottom: 28 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: 10,
            }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: CONFIDENCE_COLORS[conf],
              }} />
              <div style={{
                fontFamily: C.fontMono,
                fontSize: 9,
                color: CONFIDENCE_COLORS[conf],
                letterSpacing: 2,
              }}>
                POUZDANOST: {conf} ({items.length})
              </div>
            </div>
            {items.map(c => <CorrelationCard key={c.id} corr={c} />)}
          </div>
        );
      })}
    </div>
  );
}
