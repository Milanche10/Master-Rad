import { useState } from 'react';
import { C, ARTIFACT_COLORS, ARTIFACT_ICONS } from '../utils/constants';

function groupByDate(events) {
  const groups = {};
  events.forEach(e => {
    const day = e.ts ? e.ts.slice(0, 10) : 'Bez timestamp-a';
    if (!groups[day]) groups[day] = [];
    groups[day].push(e);
  });
  return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
}

function webHost(value) {
  if (!value) return '';
  const head = value.split(' – ')[0].split(' - ')[0].trim();
  return head.split(' ')[0] || '';
}

// Sažmi uzastopne 'web' događaje (browser istorija) u jedan pregledan red —
// isto kao u izveštaju, da detaljni timeline ne bude zatrpan šumom.
const WEB_BURST_MIN = 3;
function collapseWebBursts(events) {
  const out = [];
  let i = 0;
  while (i < events.length) {
    const e = events[i];
    if (e.type === 'web') {
      let j = i;
      const hosts = [];
      while (j < events.length && events[j].type === 'web') {
        const h = webHost(events[j].value);
        if (h && !hosts.includes(h)) hosts.push(h);
        j += 1;
      }
      const run = events.slice(i, j);
      if (run.length >= WEB_BURST_MIN) {
        const top = hosts.slice(0, 4).join(', ') + (hosts.length > 4 ? ` … (+${hosts.length - 4})` : '');
        out.push({
          type: 'web',
          value: `${run.length} web poseta: ${top}`,
          source: 'Chrome/History',
          ts: run[0].ts,
          ts_end: run[run.length - 1].ts,
          module: run[0].module,
          _burst: true,
        });
        i = j;
        continue;
      }
    }
    out.push(e);
    i += 1;
  }
  return out;
}

function TimelineEvent({ event, isLast, onSelect }) {
  const color = ARTIFACT_COLORS[event.type] || C.textSecondary;
  const icon  = ARTIFACT_ICONS[event.type]  || '◈';

  return (
    <div onClick={onSelect} style={{ display: 'flex', gap: 0, cursor: onSelect ? 'pointer' : 'default' }}>
      {/* Left: timestamp */}
      <div style={{
        width: 110,
        flexShrink: 0,
        paddingRight: 16,
        paddingTop: 3,
        textAlign: 'right',
      }}>
        <div style={{
          color: C.textMuted,
          fontFamily: C.fontMono,
          fontSize: 10,
          lineHeight: 1.3,
        }}>
          {event.ts ? event.ts.slice(11, 19) : '--:--:--'}
          {event.ts_end && event.ts_end.slice(11, 19) !== event.ts.slice(11, 19)
            ? `–${event.ts_end.slice(11, 19)}` : ''}
        </div>
        <div style={{
          color: C.textMuted + '88',
          fontFamily: C.fontMono,
          fontSize: 9,
        }}>
          {event.module}
        </div>
      </div>

      {/* Center: dot + line */}
      <div style={{
        width: 16,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
      }}>
        <div style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
          border: `2px solid ${C.bg}`,
          flexShrink: 0,
          marginTop: 4,
          zIndex: 1,
        }} />
        {!isLast && (
          <div style={{
            width: 1,
            flex: 1,
            minHeight: 8,
            background: C.border,
            marginTop: 2,
          }} />
        )}
      </div>

      {/* Right: content */}
      <div style={{
        flex: 1,
        paddingLeft: 14,
        paddingBottom: 14,
      }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
          <span style={{
            fontFamily: C.fontMono,
            fontSize: 12,
            color,
            flexShrink: 0,
          }}>
            {icon}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              color: C.textPrimary,
              fontSize: 12,
              lineHeight: 1.5,
              wordBreak: 'break-all',
            }}>
              {event.value}
            </div>
            {event.source && (
              <div style={{
                color: C.textMuted,
                fontSize: 10,
                fontFamily: C.fontMono,
                marginTop: 2,
              }}>
                ◁ {event.source}
              </div>
            )}
          </div>
          <span style={{
            background: color + '22',
            color,
            fontSize: 9,
            fontFamily: C.fontMono,
            padding: '1px 5px',
            borderRadius: 2,
            flexShrink: 0,
            letterSpacing: 1,
          }}>
            {event.type?.toUpperCase()}
          </span>
        </div>
      </div>
    </div>
  );
}

export default function Timeline({ timeline, headlineTimeline, onLoad, loading, onSelectArtifact }) {
  const [view, setView] = useState('headline'); // 'headline' | 'detailed'

  // Headline = kurirani glavni događaji; Detaljno = sve, ali sa sažimanjem
  // uzastopne browser istorije radi preglednosti.
  const activeData = view === 'headline'
    ? (headlineTimeline || [])
    : collapseWebBursts(timeline || []);

  if (!timeline?.length && !loading) {
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
        <span style={{ fontFamily: C.fontMono, fontSize: 32 }}>◫</span>
        <div style={{ fontSize: 13 }}>
          Pokreni module pa učitaj vremensku liniju
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
          ◫ Učitaj timeline
        </button>
      </div>
    );
  }

  const groups = groupByDate(activeData);

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            REKONSTRUISANA VREMENSKA LINIJA
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            {activeData.length} događaja · {groups.length} dana
          </h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <div style={{
            display: 'flex',
            border: `1px solid ${C.border}`,
            borderRadius: 4,
            overflow: 'hidden',
          }}>
            <button
              onClick={() => setView('headline')}
              style={{
                background: view === 'headline' ? C.accentDim : 'transparent',
                color: view === 'headline' ? C.accent : C.textMuted,
                border: 'none',
                padding: '6px 14px',
                fontFamily: C.fontMono,
                fontSize: 11,
                cursor: 'pointer',
              }}
            >
              ★ Najvažnije
            </button>
            <button
              onClick={() => setView('detailed')}
              style={{
                background: view === 'detailed' ? C.accentDim : 'transparent',
                color: view === 'detailed' ? C.accent : C.textMuted,
                border: 'none',
                borderLeft: `1px solid ${C.border}`,
                padding: '6px 14px',
                fontFamily: C.fontMono,
                fontSize: 11,
                cursor: 'pointer',
              }}
            >
              ☰ Detaljno
            </button>
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
      </div>

      {view === 'headline' && !activeData.length && (
        <div style={{
          color: C.textMuted,
          fontSize: 12,
          fontFamily: C.fontMono,
          padding: '20px 0',
          textAlign: 'center',
        }}>
          Nema "glavnih" događaja (pozivi, lokacije, kripto, šifrovana komunikacija...).
          Pogledaj "Detaljno" za kompletnu listu.
        </div>
      )}

      {/* Timeline grouped by day */}
      {groups.map(([day, events]) => (
        <div key={day} style={{ marginBottom: 8 }}>
          {/* Day separator */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            marginBottom: 12,
            marginLeft: 126,
          }}>
            <div style={{
              background: C.bgCard,
              border: `1px solid ${C.border}`,
              borderRadius: 4,
              padding: '3px 10px',
              fontFamily: C.fontMono,
              fontSize: 10,
              color: C.accent,
              letterSpacing: 1,
            }}>
              {day}
            </div>
            <div style={{ flex: 1, height: 1, background: C.border }} />
            <div style={{
              fontFamily: C.fontMono,
              fontSize: 9,
              color: C.textMuted,
            }}>
              {events.length} događaja
            </div>
          </div>

          {events.map((event, i) => (
            <TimelineEvent
              key={i}
              event={event}
              isLast={i === events.length - 1 && day === groups[groups.length - 1][0]}
              onSelect={onSelectArtifact ? () => onSelectArtifact(event) : undefined}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
