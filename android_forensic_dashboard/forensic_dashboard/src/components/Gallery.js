import { useState, useEffect } from 'react';
import { C } from '../utils/constants';
import { getMedia, getArtifactFileUrl } from '../utils/api';

function Thumb({ item, sessionId, onOpen }) {
  const [err, setErr] = useState(false);
  const url = getArtifactFileUrl(sessionId, item.rel);
  return (
    <button
      onClick={() => onOpen(item)}
      style={{
        position: 'relative', padding: 0, border: `1px solid ${C.border}`,
        borderRadius: 6, overflow: 'hidden', cursor: 'pointer', background: C.bgPanel,
        aspectRatio: '1 / 1',
      }}
      title={`${item.filename}\n${item.ts || ''}`}
    >
      {item.kind === 'video' ? (
        <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#000', color: C.textMuted, fontSize: 26 }}>🎬</div>
      ) : err ? (
        <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.textMuted, fontSize: 20 }}>⛊</div>
      ) : (
        <img src={url} alt={item.filename} loading="lazy" onError={() => setErr(true)}
          style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
      )}
      {/* Badges */}
      <div style={{ position: 'absolute', top: 4, left: 4, display: 'flex', gap: 3 }}>
        {item.lat !== null && item.lat !== undefined && (
          <span style={{ background: C.greenDim, color: C.green, fontSize: 8, fontFamily: C.fontMono, padding: '1px 4px', borderRadius: 2 }}>GPS</span>
        )}
        {item.stego && (
          <span style={{ background: C.redDim, color: C.red, fontSize: 8, fontFamily: C.fontMono, padding: '1px 4px', borderRadius: 2 }}>STEGO</span>
        )}
      </div>
      {/* Filename strip */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0,
        background: '#000000cc', color: C.textSecondary, fontFamily: C.fontMono,
        fontSize: 8, padding: '2px 4px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
      }}>
        {item.filename}
      </div>
    </button>
  );
}

export default function Gallery({ sessionId, onOpen }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all'); // all | gps | images | videos | stego
  const [album, setAlbum] = useState(null);     // naziv albuma ili null = svi

  const load = async (f = filter) => {
    if (!sessionId) return;
    setLoading(true); setError(null);
    try {
      const opts = {};
      if (f === 'gps') opts.only_gps = true;
      if (f === 'images') opts.kind = 'image';
      if (f === 'videos') opts.kind = 'video';
      const res = await getMedia(sessionId, opts);
      if (f === 'stego') res.media = res.media.filter(m => m.stego);
      setData(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load('all'); /* eslint-disable-next-line */ }, [sessionId]);

  const setF = (f) => { setFilter(f); load(f); };

  const FILTERS = [
    ['all', 'Sve'], ['gps', 'Sa GPS'], ['images', 'Slike'], ['videos', 'Video'], ['stego', 'Stego'],
  ];

  const openMedia = (item) => {
    // konstruiši artefakt-oblik za ArtifactModal (pun pregled + detalji)
    onOpen({
      type: item.lat != null ? 'location' : 'media',
      value: item.filename,
      source: item.rel,
      ts: item.ts,
      raw_source: { rel: item.rel, file: item.rel },
      module: 'exif',
      hash_set: item.sha256 ? { sha256: item.sha256 } : undefined,
      extra: {
        filename: item.filename, lat: item.lat, lon: item.lon,
        device: item.device, stego: item.stego, kind: item.kind, 'veličina_kb': item.size_kb,
      },
    });
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            PRONAĐENI MEDIJI
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            {data ? `${data.count} slika/snimaka · ${data.with_gps} sa GPS${data.stego ? ` · ${data.stego} stego` : ''}` : 'Galerija'}
          </h2>
        </div>
        <button onClick={() => load()} style={{
          background: 'transparent', color: C.textMuted, border: `1px solid ${C.border}`,
          borderRadius: 4, padding: '6px 14px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer',
        }}>↻ Osvježi</button>
      </div>

      {/* Filteri po tipu */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
        {FILTERS.map(([id, label]) => (
          <button key={id} onClick={() => { setF(id); setAlbum(null); }} style={{
            background: filter === id ? C.accentDim : 'transparent',
            color: filter === id ? C.accent : C.textMuted,
            border: `1px solid ${filter === id ? C.accent + '66' : C.border}`,
            borderRadius: 4, padding: '5px 12px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer',
          }}>{label}</button>
        ))}
      </div>

      {/* Albumi */}
      {data && data.albums && data.albums.length > 0 && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
          <span style={{ fontFamily: C.fontMono, fontSize: 10, color: C.textMuted, alignSelf: 'center', marginRight: 4 }}>ALBUMI:</span>
          <button onClick={() => setAlbum(null)} style={{
            background: album === null ? C.greenDim : 'transparent',
            color: album === null ? C.green : C.textMuted,
            border: `1px solid ${album === null ? C.green + '66' : C.border}`,
            borderRadius: 12, padding: '3px 10px', fontFamily: C.fontMono, fontSize: 10, cursor: 'pointer',
          }}>Svi ({data.count})</button>
          {data.albums.map((al) => (
            <button key={al.name} onClick={() => setAlbum(al.name)} style={{
              background: album === al.name ? C.greenDim : 'transparent',
              color: album === al.name ? C.green : C.textMuted,
              border: `1px solid ${album === al.name ? C.green + '66' : C.border}`,
              borderRadius: 12, padding: '3px 10px', fontFamily: C.fontMono, fontSize: 10, cursor: 'pointer',
            }}>{al.name} ({al.count})</button>
          ))}
        </div>
      )}

      {loading && <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 12 }}>⟳ Učitavam medije...</div>}
      {error && <div style={{ color: C.red, fontSize: 12 }}>Greška: {error}</div>}

      {data && !loading && (() => {
        const shown = album ? data.media.filter(m => m.album === album) : data.media;
        return shown.length === 0
          ? <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 12 }}>Nema medija za ovaj filter.</div>
          : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))',
              gap: 8,
            }}>
              {shown.map((item) => (
                <Thumb key={item.rel} item={item} sessionId={sessionId} onOpen={openMedia} />
              ))}
            </div>
          );
      })()}
    </div>
  );
}
