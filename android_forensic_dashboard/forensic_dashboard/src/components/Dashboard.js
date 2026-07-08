import { C, MODULES } from '../utils/constants';

const STATUS_STYLES = {
  idle:      { bg: 'transparent',  border: C.border,  label: 'ČEKA',      labelColor: C.textMuted },
  running:   { bg: C.yellowDim,    border: C.yellow,  label: 'POKRETANJE',labelColor: C.yellow },
  completed: { bg: C.greenDim,     border: C.green,   label: 'ZAVRŠENO',  labelColor: C.green },
  not_found: { bg: 'transparent',  border: C.border,  label: 'N/A',       labelColor: C.textMuted },
  error:     { bg: C.redDim,       border: C.red,     label: 'GREŠKA',    labelColor: C.red },
};

function StatPill({ value, label, color }) {
  return (
    <div style={{
      background: C.bgCard,
      border: `1px solid ${C.border}`,
      borderRadius: 6,
      padding: '12px 16px',
      flex: 1,
    }}>
      <div style={{
        fontFamily: C.fontMono,
        fontSize: 24,
        fontWeight: 600,
        color: color || C.textPrimary,
        lineHeight: 1,
        marginBottom: 4,
      }}>
        {value}
      </div>
      <div style={{
        fontFamily: C.fontMono,
        fontSize: 9,
        color: C.textMuted,
        letterSpacing: 1,
        textTransform: 'uppercase',
      }}>
        {label}
      </div>
    </div>
  );
}

function ModuleCard({ module, status, alertCount, onRun, onView }) {
  const s = STATUS_STYLES[status] || STATUS_STYLES.idle;
  const isRunning = status === 'running';
  const isDone = status === 'completed';
  const isNA = status === 'not_found';

  return (
    <div style={{
      background: C.bgCard,
      border: `1px solid ${isDone ? C.border : s.border}`,
      borderTop: isDone ? `2px solid ${C.green}22` : `2px solid ${s.border}`,
      borderRadius: 6,
      padding: '14px 16px',
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
      transition: 'border-color 0.2s',
      opacity: isNA ? 0.5 : 1,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <span style={{
          fontFamily: C.fontMono,
          fontSize: 18,
          color: isDone ? C.accent : C.textMuted,
          lineHeight: 1,
          marginTop: 1,
        }}>
          {module.icon}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            color: C.textPrimary,
            fontSize: 13,
            fontWeight: 500,
            marginBottom: 3,
          }}>
            {module.label}
          </div>
          <div style={{
            color: C.textMuted,
            fontSize: 11,
            fontFamily: C.fontMono,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}>
            {module.desc}
          </div>
        </div>
        {alertCount > 0 && (
          <span style={{
            background: C.redDim,
            color: C.red,
            fontSize: 10,
            fontFamily: C.fontMono,
            padding: '2px 7px',
            borderRadius: 3,
            border: `1px solid ${C.red}44`,
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}>
            ⚠ {alertCount}
          </span>
        )}
      </div>

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: s.border,
            boxShadow: isRunning ? `0 0 8px ${C.yellow}` : 'none',
            animation: isRunning ? 'pulse 1s infinite' : 'none',
          }} />
          <span style={{
            color: s.labelColor,
            fontSize: 10,
            fontFamily: C.fontMono,
            letterSpacing: 1,
          }}>
            {s.label}
          </span>
        </div>

        <div style={{ display: 'flex', gap: 6 }}>
          {!isDone && !isNA && status !== 'running' && (
            <button
              onClick={() => onRun(module.id)}
              style={{
                background: C.accentDim,
                color: C.accent,
                border: `1px solid ${C.accent}44`,
                borderRadius: 4,
                padding: '4px 12px',
                fontSize: 11,
                fontFamily: C.fontMono,
                cursor: 'pointer',
              }}
            >
              ▶ Pokreni
            </button>
          )}
          {isDone && (
            <button
              onClick={() => onView(module.id)}
              style={{
                background: 'transparent',
                color: C.textSecondary,
                border: `1px solid ${C.border}`,
                borderRadius: 4,
                padding: '4px 12px',
                fontSize: 11,
                fontFamily: C.fontMono,
                cursor: 'pointer',
              }}
            >
              Rezultati →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Dashboard({
  sessionInfo,
  statuses,
  results,
  completedCount,
  totalModules,
  alertCount,
  correlationCount,
  onRunModule,
  onViewModule,
  onRunAll,
  onViewCorrelations,
  loading,
}) {
  const progress = completedCount / totalModules;
  const allDone = completedCount === totalModules;

  return (
    <div style={{
      flex: 1,
      overflow: 'auto',
      padding: '24px 28px',
    }}>
      {/* Case header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{
          fontFamily: C.fontMono,
          fontSize: 9,
          color: C.textMuted,
          letterSpacing: 2,
          marginBottom: 8,
          textTransform: 'uppercase',
        }}>
          Aktivan slučaj
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div>
            <h2 style={{
              fontFamily: C.fontMono,
              fontSize: 18,
              color: C.textPrimary,
              fontWeight: 600,
              marginBottom: 6,
            }}>
              {sessionInfo?.device || 'Android uređaj'}
            </h2>
            <div style={{
              display: 'flex',
              gap: 16,
              flexWrap: 'wrap',
            }}>
              {sessionInfo?.android && (
                <span style={{ color: C.textMuted, fontSize: 12, fontFamily: C.fontMono }}>
                  {sessionInfo.android}
                </span>
              )}
              {sessionInfo?.dump_path && (
                <span style={{ color: C.textMuted, fontSize: 12, fontFamily: C.fontMono }}>
                  {sessionInfo.dump_path}
                </span>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button
              onClick={onRunAll}
              disabled={loading || allDone}
              style={{
                background: allDone ? C.greenDim : C.accentDim,
                color: allDone ? C.green : C.accent,
                border: `1px solid ${allDone ? C.green + '44' : C.accent + '44'}`,
                borderRadius: 6,
                padding: '8px 16px',
                fontSize: 12,
                fontFamily: C.fontMono,
                cursor: loading || allDone ? 'default' : 'pointer',
              }}
            >
              {loading ? '⟳ Analiza...' : allDone ? '✓ Završeno' : '▶ Pokreni sve'}
            </button>
          </div>
        </div>

        {/* Progress bar */}
        <div style={{ marginTop: 16 }}>
          <div style={{
            height: 3,
            background: C.border,
            borderRadius: 2,
            overflow: 'hidden',
          }}>
            <div style={{
              height: '100%',
              width: `${progress * 100}%`,
              background: allDone ? C.green : C.accent,
              transition: 'width 0.5s ease',
              boxShadow: !allDone ? `0 0 8px ${C.accent}88` : 'none',
            }} />
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
        <StatPill value={completedCount} label="Moduli završeni" color={C.accent} />
        <StatPill value={alertCount} label="Upozorenja" color={alertCount > 0 ? C.red : C.textMuted} />
        <StatPill value={correlationCount || 0} label="Korelacije" color={correlationCount > 0 ? C.purple : C.textMuted} />
        <StatPill
          value={Object.values(results).flatMap(r => r?.artifacts || []).length}
          label="Artefakti"
          color={C.green}
        />
      </div>

      {/* Alert strip */}
      {alertCount > 0 && (
        <div style={{
          background: C.redDim,
          border: `1px solid ${C.red}33`,
          borderRadius: 6,
          padding: '10px 14px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
        }}>
          <div>
            <span style={{ color: C.red, fontFamily: C.fontMono, fontSize: 11 }}>
              ⚠ {alertCount} upozorenja
            </span>
            <span style={{ color: C.textSecondary, fontSize: 11, marginLeft: 10 }}>
              {Object.entries(results)
                .filter(([, v]) => v?.alerts?.length)
                .map(([k, v]) => `${k}: ${v.alerts.length}`)
                .join(' · ')}
            </span>
          </div>
          {correlationCount > 0 && (
            <button
              onClick={onViewCorrelations}
              style={{
                background: 'transparent',
                color: C.accent,
                border: `1px solid ${C.accent}44`,
                borderRadius: 4,
                padding: '4px 12px',
                fontSize: 11,
                fontFamily: C.fontMono,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Prikaži korelacije →
            </button>
          )}
        </div>
      )}

      {/* Module grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: 10,
      }}>
        {MODULES.map(module => (
          <ModuleCard
            key={module.id}
            module={module}
            status={statuses[module.id]}
            alertCount={results[module.id]?.alerts?.length || 0}
            onRun={onRunModule}
            onView={onViewModule}
          />
        ))}
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.2; }
        }
      `}</style>
    </div>
  );
}
