import { C, MODULES, ARTIFACT_COLORS } from '../utils/constants';

const STATUS_CONFIG = {
  idle:      { color: C.textMuted,    label: 'ČEKA',      dot: C.textMuted },
  running:   { color: C.yellow,       label: 'ANALIZIRA', dot: C.yellow },
  completed: { color: C.green,        label: 'OK',        dot: C.green },
  not_found: { color: C.textMuted,    label: 'N/A',       dot: C.textMuted },
  error:     { color: C.red,          label: 'ERR',       dot: C.red },
};

function ModuleRow({ module, status, alertCount, isActive, onClick }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.idle;
  const isRunning = status === 'running';

  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        width: '100%',
        padding: '8px 12px',
        background: isActive ? C.accentDim : 'transparent',
        border: 'none',
        borderLeft: `2px solid ${isActive ? C.accent : 'transparent'}`,
        borderRadius: '0 4px 4px 0',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'background 0.15s, border-color 0.15s',
      }}
      onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = '#0d1a2e'; }}
      onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
    >
      {/* Status dot */}
      <div style={{
        width: 6, height: 6, borderRadius: '50%',
        background: cfg.dot, flexShrink: 0,
        boxShadow: isRunning ? `0 0 6px ${C.yellow}` : 'none',
        animation: isRunning ? 'pulse 1s infinite' : 'none',
      }} />

      {/* Icon */}
      <span style={{
        fontFamily: C.fontMono,
        fontSize: 14,
        color: isActive ? C.accent : C.textMuted,
        flexShrink: 0,
        width: 16,
        textAlign: 'center',
      }}>
        {module.icon}
      </span>

      {/* Label */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          color: isActive ? C.textPrimary : C.textSecondary,
          fontSize: 12,
          fontWeight: 500,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}>
          {module.label}
        </div>
      </div>

      {/* Alert badge */}
      {alertCount > 0 && (
        <span style={{
          background: C.redDim,
          color: C.red,
          fontSize: 10,
          fontFamily: C.fontMono,
          padding: '1px 5px',
          borderRadius: 3,
          border: `1px solid ${C.red}44`,
          flexShrink: 0,
        }}>
          {alertCount}
        </span>
      )}

      {/* Status label — samo za running */}
      {isRunning && (
        <span style={{
          color: C.yellow,
          fontSize: 9,
          fontFamily: C.fontMono,
          letterSpacing: 1,
          flexShrink: 0,
        }}>
          ···
        </span>
      )}
    </button>
  );
}

export default function Sidebar({
  sessionInfo,
  statuses,
  results,
  activeModule,
  activeTab,
  onSelectModule,
  onSelectTab,
  completedCount,
  totalModules,
  alertCount,
  correlationCount,
  timelineCount,
}) {
  const progress = completedCount / totalModules;

  const navTabs = [
    { id: 'dashboard', icon: '▦', label: 'Pregled' },
    { id: 'correlations', icon: '◈', label: `Korelacije${correlationCount ? ` (${correlationCount})` : ''}` },
    { id: 'timeline', icon: '◫', label: `Timeline${timelineCount ? ` (${timelineCount})` : ''}` },
    { id: 'gallery', icon: '▤', label: 'Galerija' },
    { id: 'report', icon: '◧', label: 'Izveštaj' },
    { id: 'case', icon: '⛓', label: 'Slučaj / Audit' },
  ];

  return (
    <aside style={{
      width: 220,
      flexShrink: 0,
      background: C.bgPanel,
      borderRight: `1px solid ${C.border}`,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{
        padding: '16px 16px 12px',
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{
          fontFamily: C.fontMono,
          fontSize: 11,
          fontWeight: 600,
          color: C.accent,
          letterSpacing: 3,
          textTransform: 'uppercase',
        }}>
          AFD
        </div>
        <div style={{
          fontFamily: C.fontMono,
          fontSize: 9,
          color: C.textMuted,
          letterSpacing: 1,
          marginTop: 2,
        }}>
          Android Forensic Dashboard
        </div>
      </div>

      {/* Session info */}
      {sessionInfo && (
        <div style={{
          padding: '10px 16px',
          borderBottom: `1px solid ${C.border}`,
          fontSize: 11,
        }}>
          <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 9, letterSpacing: 1, marginBottom: 6 }}>
            AKTIVAN SLUČAJ
          </div>
          <div style={{ color: C.textSecondary, marginBottom: 4, lineHeight: 1.4 }}>
            {sessionInfo.device || 'Android uređaj'}
          </div>
          {/* Progress bar */}
          <div style={{ marginTop: 8 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ color: C.textMuted, fontSize: 9, fontFamily: C.fontMono }}>
                {completedCount}/{totalModules} MODULI
              </span>
              {alertCount > 0 && (
                <span style={{ color: C.red, fontSize: 9, fontFamily: C.fontMono }}>
                  ⚠ {alertCount}
                </span>
              )}
            </div>
            <div style={{
              height: 2, background: C.border, borderRadius: 1, overflow: 'hidden',
            }}>
              <div style={{
                height: '100%',
                width: `${progress * 100}%`,
                background: progress === 1 ? C.green : C.accent,
                transition: 'width 0.4s ease',
              }} />
            </div>
          </div>
        </div>
      )}

      {/* Nav tabs */}
      <div style={{
        padding: '8px 0',
        borderBottom: `1px solid ${C.border}`,
      }}>
        {navTabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => onSelectTab(tab.id)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              width: '100%',
              padding: '7px 16px',
              background: activeTab === tab.id ? C.accentDim : 'transparent',
              border: 'none',
              borderLeft: `2px solid ${activeTab === tab.id ? C.accent : 'transparent'}`,
              color: activeTab === tab.id ? C.textPrimary : C.textSecondary,
              fontSize: 12,
              cursor: 'pointer',
              textAlign: 'left',
              fontFamily: C.fontSans,
            }}
          >
            <span style={{ fontFamily: C.fontMono, fontSize: 12 }}>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Module list */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '8px 0',
      }}>
        <div style={{
          padding: '4px 16px 6px',
          fontFamily: C.fontMono,
          fontSize: 9,
          color: C.textMuted,
          letterSpacing: 1,
        }}>
          MODULI ANALIZE
        </div>
        {MODULES.map(module => (
          <ModuleRow
            key={module.id}
            module={module}
            status={statuses[module.id]}
            alertCount={results[module.id]?.alerts?.length || 0}
            isActive={activeModule === module.id && activeTab === 'module'}
            onClick={() => onSelectModule(module.id)}
          />
        ))}
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
      `}</style>
    </aside>
  );
}
