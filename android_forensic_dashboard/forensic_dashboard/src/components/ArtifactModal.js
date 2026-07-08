import { useState } from 'react';
import { C, ARTIFACT_COLORS, ARTIFACT_ICONS } from '../utils/constants';
import { getArtifactFileUrl, revealArtifactFile } from '../utils/api';

const IMAGE_EXT = ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.gif'];
const AUDIO_EXT = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac'];
const VIDEO_EXT = ['.mp4', '.mov', '.3gp', '.m4v', '.webm', '.mkv'];

function extOf(path) {
  if (!path) return '';
  const dot = path.lastIndexOf('.');
  return dot === -1 ? '' : path.slice(dot).toLowerCase();
}

function FieldRow({ label, value }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div style={{ display: 'flex', gap: 12, padding: '6px 0', borderBottom: `1px solid ${C.border}` }}>
      <div style={{
        width: 150, flexShrink: 0, color: C.textMuted,
        fontFamily: C.fontMono, fontSize: 11, lineHeight: 1.5,
      }}>
        {label}
      </div>
      <div style={{
        color: C.textPrimary, fontFamily: C.fontMono, fontSize: 12,
        lineHeight: 1.5, wordBreak: 'break-all', flex: 1,
      }}>
        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
      </div>
    </div>
  );
}

export default function ArtifactModal({ artifact, sessionId, onClose }) {
  const [revealStatus, setRevealStatus] = useState(null); // null | 'ok' | 'error'
  const [previewError, setPreviewError] = useState(false);

  if (!artifact) return null;

  const color = ARTIFACT_COLORS[artifact.type] || C.textSecondary;
  const icon = ARTIFACT_ICONS[artifact.type] || '◈';
  const source = artifact.source || '';
  // Preferiraj razrešenu proveniencijsku putanju (raw_source.rel) ako postoji
  const previewPath = (artifact.raw_source && artifact.raw_source.rel) || source;
  const ext = extOf(previewPath);
  const isImage = IMAGE_EXT.includes(ext);
  const isAudio = AUDIO_EXT.includes(ext);
  const isVideo = VIDEO_EXT.includes(ext);
  const fileUrl = sessionId && previewPath ? getArtifactFileUrl(sessionId, previewPath) : null;

  const handleReveal = async () => {
    setRevealStatus(null);
    try {
      await revealArtifactFile(sessionId, source);
      setRevealStatus('ok');
    } catch (e) {
      setRevealStatus('error');
    }
  };

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: '#000000aa',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 100,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: C.bgCard,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          width: 'min(640px, 92vw)',
          maxHeight: '85vh',
          overflow: 'auto',
          padding: 24,
          boxShadow: '0 20px 60px #00000088',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
          <span style={{ color, fontFamily: C.fontMono, fontSize: 22 }}>{icon}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontFamily: C.fontMono, fontSize: 9, color: C.textMuted,
              letterSpacing: 2, marginBottom: 4,
            }}>
              DETALJI ARTEFAKTA
            </div>
            <div style={{
              color: C.textPrimary, fontSize: 14, fontFamily: C.fontMono,
              lineHeight: 1.5, wordBreak: 'break-word',
            }}>
              {artifact.value}
            </div>
          </div>
          <span style={{
            background: color + '22', color, fontSize: 9, fontFamily: C.fontMono,
            padding: '2px 6px', borderRadius: 3, letterSpacing: 1, flexShrink: 0,
          }}>
            {artifact.type?.toUpperCase()}
          </span>
          <button
            onClick={onClose}
            style={{
              background: 'transparent', color: C.textMuted, border: `1px solid ${C.border}`,
              borderRadius: 4, width: 26, height: 26, cursor: 'pointer', fontFamily: C.fontMono,
              flexShrink: 0,
            }}
          >
            ✕
          </button>
        </div>

        {/* Fields */}
        <div style={{ marginBottom: 16 }}>
          <FieldRow label="Tip" value={artifact.type} />
          <FieldRow label="Vreme (ts)" value={artifact.ts} />
          <FieldRow label="Modul" value={artifact.module} />
          <FieldRow label="Izvor (fajl/baza)" value={source} />
          {artifact.extra && Object.entries(artifact.extra).map(([k, v]) => (
            <FieldRow key={k} label={k} value={v} />
          ))}
        </div>

        {/* Preview */}
        {fileUrl && !previewError && (isImage || isAudio || isVideo) && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 8 }}>
              PREGLED
            </div>
            {isImage && (
              <img
                src={fileUrl}
                alt={artifact.value}
                onError={() => setPreviewError(true)}
                style={{ maxWidth: '100%', maxHeight: 360, borderRadius: 6, border: `1px solid ${C.border}` }}
              />
            )}
            {isAudio && (
              <audio
                controls
                src={fileUrl}
                onError={() => setPreviewError(true)}
                style={{ width: '100%' }}
              />
            )}
            {isVideo && (
              <video
                controls
                src={fileUrl}
                onError={() => setPreviewError(true)}
                style={{ maxWidth: '100%', maxHeight: 360, borderRadius: 6, border: `1px solid ${C.border}`, background: '#000' }}
              />
            )}
          </div>
        )}

        {fileUrl && previewError && (
          <div style={{ color: C.textMuted, fontSize: 11, fontFamily: C.fontMono, marginBottom: 16 }}>
            Pregled nije moguć — fajl nije dostupan na ovoj putanji u dump-u.
          </div>
        )}

        {/* Actions */}
        {source && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              onClick={handleReveal}
              style={{
                background: C.accentDim, color: C.accent, border: `1px solid ${C.accent}44`,
                borderRadius: 4, padding: '8px 16px', fontFamily: C.fontMono, fontSize: 11, cursor: 'pointer',
              }}
            >
              ◫ Otvori u Eksploreru
            </button>
            {fileUrl && (
              <a
                href={fileUrl}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  background: C.purpleDim, color: C.purple, border: `1px solid ${C.purple}44`,
                  borderRadius: 4, padding: '8px 16px', fontFamily: C.fontMono, fontSize: 11,
                  textDecoration: 'none', display: 'inline-flex', alignItems: 'center',
                }}
              >
                ↓ Preuzmi / otvori fajl
              </a>
            )}
            {revealStatus === 'ok' && (
              <span style={{ color: C.green, fontFamily: C.fontMono, fontSize: 11, alignSelf: 'center' }}>
                ✓ Otvoreno
              </span>
            )}
            {revealStatus === 'error' && (
              <span style={{ color: C.red, fontFamily: C.fontMono, fontSize: 11, alignSelf: 'center' }}>
                ✗ Fajl nije pronađen u dump-u
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
