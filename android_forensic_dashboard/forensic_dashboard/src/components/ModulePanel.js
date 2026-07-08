import { C, ARTIFACT_COLORS, ARTIFACT_ICONS, MODULES } from '../utils/constants';

function AlertBanner({ alert }) {
  return (
    <div style={{
      display: 'flex',
      gap: 10,
      background: C.redDim,
      border: `1px solid ${C.red}33`,
      borderLeft: `3px solid ${C.red}`,
      borderRadius: 4,
      padding: '8px 12px',
      marginBottom: 6,
    }}>
      <span style={{ color: C.red, flexShrink: 0, fontFamily: C.fontMono }}>⚠</span>
      <span style={{ color: C.textSecondary, fontSize: 12, lineHeight: 1.5 }}>{alert}</span>
    </div>
  );
}

function FindingRow({ k, v }) {
  return (
    <div style={{
      display: 'flex',
      borderBottom: `1px solid ${C.border}`,
      padding: '7px 0',
      gap: 12,
    }}>
      <div style={{
        color: C.textMuted,
        fontSize: 11,
        fontFamily: C.fontMono,
        flexShrink: 0,
        width: 180,
        lineHeight: 1.4,
      }}>
        {k}
      </div>
      <div style={{
        color: C.textPrimary,
        fontSize: 12,
        fontFamily: C.fontMono,
        lineHeight: 1.4,
        wordBreak: 'break-all',
      }}>
        {v}
      </div>
    </div>
  );
}

function ArtifactRow({ artifact, onSelect }) {
  const color = ARTIFACT_COLORS[artifact.type] || C.textSecondary;
  const icon  = ARTIFACT_ICONS[artifact.type]  || '◈';

  return (
    <div
      onClick={onSelect}
      style={{
        background: C.bgPanel,
        border: `1px solid ${C.border}`,
        borderLeft: `3px solid ${color}44`,
        borderRadius: 4,
        padding: '9px 12px',
        marginBottom: 5,
        cursor: onSelect ? 'pointer' : 'default',
      }}
    >
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
        <span style={{
          color,
          fontFamily: C.fontMono,
          fontSize: 13,
          flexShrink: 0,
          marginTop: 1,
        }}>
          {icon}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            color: C.textPrimary,
            fontSize: 12,
            fontFamily: C.fontMono,
            lineHeight: 1.5,
            wordBreak: 'break-all',
          }}>
            {artifact.value}
          </div>
          <div style={{
            display: 'flex',
            gap: 12,
            marginTop: 4,
            flexWrap: 'wrap',
          }}>
            {artifact.ts && (
              <span style={{ color: C.textMuted, fontSize: 10, fontFamily: C.fontMono }}>
                ◷ {artifact.ts.replace('T', ' ').replace('Z', ' UTC')}
              </span>
            )}
            {artifact.source && (
              <span style={{ color: C.textMuted, fontSize: 10, fontFamily: C.fontMono }}>
                ◁ {artifact.source}
              </span>
            )}
          </div>
        </div>
        <span style={{
          background: color + '22',
          color,
          fontSize: 9,
          fontFamily: C.fontMono,
          padding: '2px 6px',
          borderRadius: 3,
          flexShrink: 0,
          letterSpacing: 1,
        }}>
          {artifact.type.toUpperCase()}
        </span>
      </div>
    </div>
  );
}

export default function ModulePanel({ moduleId, data, onRun, status, onSelectArtifact }) {
  const module = MODULES.find(m => m.id === moduleId);
  if (!module) return null;

  const hasData = !!data;
  const isRunning = status === 'running';

  return (
    <div style={{
      flex: 1,
      overflow: 'auto',
      padding: '24px 28px',
    }}>
      {/* Module header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        marginBottom: 24,
        paddingBottom: 20,
        borderBottom: `1px solid ${C.border}`,
      }}>
        <span style={{
          fontFamily: C.fontMono,
          fontSize: 28,
          color: hasData ? C.accent : C.textMuted,
        }}>
          {module.icon}
        </span>
        <div style={{ flex: 1 }}>
          <h2 style={{
            fontFamily: C.fontMono,
            fontSize: 16,
            color: C.textPrimary,
            fontWeight: 600,
            marginBottom: 4,
          }}>
            {module.label}
          </h2>
          <div style={{
            color: C.textMuted,
            fontSize: 11,
            fontFamily: C.fontMono,
          }}>
            {module.desc}
          </div>
        </div>

        {!hasData && !isRunning && (
          <button
            onClick={() => onRun(moduleId)}
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
            ▶ Pokreni analizu
          </button>
        )}
        {isRunning && (
          <div style={{
            color: C.yellow,
            fontFamily: C.fontMono,
            fontSize: 11,
            letterSpacing: 2,
          }}>
            ⟳ ANALIZIRA...
          </div>
        )}
        {hasData && (
          <div style={{
            color: C.green,
            fontFamily: C.fontMono,
            fontSize: 11,
            letterSpacing: 1,
          }}>
            ✓ ZAVRŠENO
          </div>
        )}
      </div>

      {/* Waiting state */}
      {!hasData && !isRunning && (
        <div style={{
          textAlign: 'center',
          padding: '60px 40px',
          color: C.textMuted,
        }}>
          <div style={{
            fontFamily: C.fontMono,
            fontSize: 32,
            marginBottom: 12,
          }}>
            {module.icon}
          </div>
          <div style={{ fontSize: 13 }}>
            Klikni "Pokreni analizu" da počneš
          </div>
        </div>
      )}

      {/* Running state */}
      {isRunning && (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          padding: '60px 40px',
          gap: 16,
        }}>
          <div style={{
            width: 40,
            height: 40,
            border: `2px solid ${C.border}`,
            borderTop: `2px solid ${C.accent}`,
            borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
          }} />
          <div style={{ color: C.textSecondary, fontFamily: C.fontMono, fontSize: 12 }}>
            Analizira dump...
          </div>
        </div>
      )}

      {/* Results */}
      {hasData && (
        <>
          {/* Alerts */}
          {data.alerts?.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <SectionLabel>UPOZORENJA ({data.alerts.length})</SectionLabel>
              {data.alerts.map((a, i) => <AlertBanner key={i} alert={a} />)}
            </div>
          )}

          {/* Findings */}
          {data.findings?.length > 0 && (
            <div style={{ marginBottom: 24 }}>
              <SectionLabel>NALAZI</SectionLabel>
              <div style={{
                background: C.bgCard,
                border: `1px solid ${C.border}`,
                borderRadius: 6,
                padding: '4px 14px',
              }}>
                {data.findings.map((f, i) => (
                  <FindingRow key={i} k={f.key} v={f.value} />
                ))}
              </div>
            </div>
          )}

          {/* Artifacts */}
          {data.artifacts?.length > 0 && (
            <div>
              <SectionLabel>ARTEFAKTI ({data.artifacts.length})</SectionLabel>
              {data.artifacts.map((a, i) => (
                <ArtifactRow
                  key={i}
                  artifact={a}
                  onSelect={onSelectArtifact ? () => onSelectArtifact({ ...a, module: moduleId }) : undefined}
                />
              ))}
            </div>
          )}
        </>
      )}

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div style={{
      fontFamily: C.fontMono,
      fontSize: 9,
      color: C.textMuted,
      letterSpacing: 2,
      textTransform: 'uppercase',
      marginBottom: 8,
    }}>
      {children}
    </div>
  );
}
