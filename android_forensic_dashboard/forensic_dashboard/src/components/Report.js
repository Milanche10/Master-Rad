import { useState } from 'react';
import { C } from '../utils/constants';
import { downloadReportFile, getAiConclusion } from '../utils/api';

export default function Report({ report, onGenerate, loading, sessionId }) {
  const [copied, setCopied] = useState(false);
  const [exporting, setExporting] = useState(null); // 'pdf' | 'docx' | null
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState(null); // { available, conclusion|reason, model, usage }

  const handleAiConclusion = async () => {
    if (!sessionId) return;
    setAiLoading(true);
    setAiResult(null);
    try {
      const res = await getAiConclusion(sessionId);
      setAiResult(res);
    } catch (e) {
      setAiResult({ available: false, reason: e.message });
    } finally {
      setAiLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(report).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleDownload = () => {
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_report_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExport = async (format) => {
    if (!sessionId) return;
    setExporting(format);
    try {
      await downloadReportFile(sessionId, format);
    } catch (e) {
      // eslint-disable-next-line no-alert
      alert(`Greška pri izvozu (${format}): ${e.message}`);
    } finally {
      setExporting(null);
    }
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 20,
        flexShrink: 0,
      }}>
        <div>
          <div style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted, letterSpacing: 2, marginBottom: 6 }}>
            FORENZIČKI IZVEŠTAJ
          </div>
          <h2 style={{ fontFamily: C.fontMono, fontSize: 16, color: C.textPrimary, fontWeight: 600 }}>
            Centralizovani izveštaj
          </h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {report && (
            <>
              <button
                onClick={handleCopy}
                style={{
                  background: copied ? C.greenDim : 'transparent',
                  color: copied ? C.green : C.textMuted,
                  border: `1px solid ${copied ? C.green + '44' : C.border}`,
                  borderRadius: 4,
                  padding: '6px 14px',
                  fontFamily: C.fontMono,
                  fontSize: 11,
                  cursor: 'pointer',
                }}
              >
                {copied ? '✓ Kopirano' : '◈ Kopiraj'}
              </button>
              <button
                onClick={handleDownload}
                style={{
                  background: C.accentDim,
                  color: C.accent,
                  border: `1px solid ${C.accent}44`,
                  borderRadius: 4,
                  padding: '6px 14px',
                  fontFamily: C.fontMono,
                  fontSize: 11,
                  cursor: 'pointer',
                }}
              >
                ↓ .txt
              </button>
              <button
                onClick={() => handleExport('pdf')}
                disabled={exporting === 'pdf'}
                style={{
                  background: C.redDim,
                  color: C.red,
                  border: `1px solid ${C.red}44`,
                  borderRadius: 4,
                  padding: '6px 14px',
                  fontFamily: C.fontMono,
                  fontSize: 11,
                  cursor: exporting === 'pdf' ? 'wait' : 'pointer',
                }}
              >
                {exporting === 'pdf' ? '⟳ ...' : '↓ PDF'}
              </button>
              <button
                onClick={() => handleExport('docx')}
                disabled={exporting === 'docx'}
                style={{
                  background: C.purpleDim,
                  color: C.purple,
                  border: `1px solid ${C.purple}44`,
                  borderRadius: 4,
                  padding: '6px 14px',
                  fontFamily: C.fontMono,
                  fontSize: 11,
                  cursor: exporting === 'docx' ? 'wait' : 'pointer',
                }}
              >
                {exporting === 'docx' ? '⟳ ...' : '↓ Word'}
              </button>
              <button
                onClick={() => handleExport('html')}
                disabled={exporting === 'html'}
                style={{
                  background: C.greenDim,
                  color: C.green,
                  border: `1px solid ${C.green}44`,
                  borderRadius: 4,
                  padding: '6px 14px',
                  fontFamily: C.fontMono,
                  fontSize: 11,
                  cursor: exporting === 'html' ? 'wait' : 'pointer',
                }}
              >
                {exporting === 'html' ? '⟳ ...' : '↓ HTML'}
              </button>
            </>
          )}
          <button
            onClick={handleAiConclusion}
            disabled={aiLoading || !sessionId}
            style={{
              background: C.accentDim,
              color: C.accent,
              border: `1px solid ${C.accent}66`,
              borderRadius: 4,
              padding: '6px 14px',
              fontFamily: C.fontMono,
              fontSize: 11,
              cursor: aiLoading ? 'wait' : 'pointer',
            }}
          >
            {aiLoading ? '⟳ AI analizira...' : '🧠 AI Zaključak'}
          </button>
          <button
            onClick={onGenerate}
            disabled={loading}
            style={{
              background: C.purpleDim,
              color: C.purple,
              border: `1px solid ${C.purple}44`,
              borderRadius: 4,
              padding: '6px 14px',
              fontFamily: C.fontMono,
              fontSize: 11,
              cursor: loading ? 'wait' : 'pointer',
            }}
          >
            {loading ? '⟳ ...' : report ? '↻ Regeneriši' : '◧ Generiši izveštaj'}
          </button>
        </div>
      </div>

      {/* AI zaključak panel */}
      {(aiLoading || aiResult) && (
        <div style={{
          flexShrink: 0,
          marginBottom: 16,
          background: C.bgCard,
          border: `1px solid ${aiResult && !aiResult.available ? C.red + '44' : C.accent + '44'}`,
          borderRadius: 6,
          padding: '16px 20px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 14 }}>🧠</span>
            <span style={{ fontFamily: C.fontMono, fontSize: 11, color: C.accent, letterSpacing: 1 }}>
              AI FORENZIČKI ZAKLJUČAK
            </span>
            {aiResult?.model && (
              <span style={{ fontFamily: C.fontMono, fontSize: 9, color: C.textMuted }}>
                · {aiResult.model}{aiResult.engine ? ` · ${aiResult.engine}` : ''}
                {aiResult.usage ? ` · ${aiResult.usage.output_tokens} tok` : ''}
              </span>
            )}
          </div>
          {aiLoading && (
            <div style={{ color: C.textMuted, fontFamily: C.fontMono, fontSize: 12 }}>
              ⟳ Lokalni AI model analizira sve nalaze i piše zaključak... (može potrajati na CPU-u)
            </div>
          )}
          {aiResult && !aiResult.available && (
            <div style={{ color: C.red, fontSize: 12, lineHeight: 1.6 }}>
              AI nije dostupan: {aiResult.reason}
              <div style={{ color: C.textMuted, fontSize: 11, marginTop: 6 }}>
                Koristi se <b>lokalni</b> open-source model (Ollama) — besplatno i privatno
                (podaci ne napuštaju mašinu). Podešavanje: instaliraj{' '}
                <a href="https://ollama.com" target="_blank" rel="noopener noreferrer" style={{ color: C.accent }}>Ollama</a>,
                pa u terminalu pokreni <code>ollama pull llama3.1</code>.
              </div>
            </div>
          )}
          {aiResult?.available && (
            <div style={{
              color: C.textPrimary,
              fontSize: 13,
              lineHeight: 1.7,
              whiteSpace: 'pre-wrap',
              maxHeight: 420,
              overflow: 'auto',
            }}>
              {aiResult.conclusion}
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!report && !loading && (
        <div style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: C.textMuted,
          gap: 16,
        }}>
          <span style={{ fontFamily: C.fontMono, fontSize: 32 }}>◧</span>
          <div style={{ fontSize: 13, textAlign: 'center', maxWidth: 320, lineHeight: 1.6 }}>
            Pokreni sve module, pa klikni "Generiši izveštaj" da dobiješ
            centralizovani dokument sa svim nalazima i korelacijama.
          </div>
          <button
            onClick={onGenerate}
            style={{
              background: C.purpleDim,
              color: C.purple,
              border: `1px solid ${C.purple}44`,
              borderRadius: 6,
              padding: '8px 20px',
              fontFamily: C.fontMono,
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            ◧ Generiši izveštaj
          </button>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: C.textMuted,
          fontFamily: C.fontMono,
          fontSize: 12,
          letterSpacing: 2,
        }}>
          ⟳ GENERISANJE...
        </div>
      )}

      {/* Report content */}
      {report && (
        <pre style={{
          flex: 1,
          overflow: 'auto',
          background: C.bgPanel,
          border: `1px solid ${C.border}`,
          borderRadius: 6,
          padding: '20px 24px',
          color: C.textSecondary,
          fontFamily: C.fontMono,
          fontSize: 12,
          lineHeight: 1.7,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          margin: 0,
        }}>
          {/* Koloriziraj određene linije */}
          {report.split('\n').map((line, i) => {
            let color = C.textSecondary;
            if (line.startsWith('=') || line.startsWith('─')) color = C.border;
            else if (line.startsWith('[!]') || line.includes('UPOZORENJE')) color = C.red;
            else if (line.startsWith('[') && line.includes(']')) color = C.accent;
            else if (line.startsWith('  ') && line.includes(':')) color = C.textPrimary;
            else if (line.toUpperCase() === line && line.trim().length > 3 && !line.startsWith(' ')) color = C.textPrimary;

            return (
              <span key={i} style={{ color, display: 'block' }}>
                {line || ' '}
              </span>
            );
          })}
        </pre>
      )}
    </div>
  );
}
