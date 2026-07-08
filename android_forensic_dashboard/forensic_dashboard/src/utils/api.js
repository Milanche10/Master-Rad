// api.js — sva komunikacija sa FastAPI backendom

const BASE = '';  // proxy u package.json šalje na localhost:8000

// ── Session management ────────────────────────────────────────────────────

export async function createSession(dumpPath) {
  // dumpPath je string putanja na serveru (forenzičar unosi putanju do dump foldera)
  const res = await fetch(`${BASE}/api/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dump_path: dumpPath }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { session_id, dump_path, summary }
}

export async function getSession(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function deleteSession(sessionId) {
  await fetch(`${BASE}/api/session/${sessionId}`, { method: 'DELETE' });
}

// ── Module analysis ───────────────────────────────────────────────────────

export async function runModule(sessionId, moduleName) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/analyze/${moduleName}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { status, findings, artifacts, alerts }
}

export async function runAllModules(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/analyze/all`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { results: { module_name: {...} } }
}

// ── Correlations ──────────────────────────────────────────────────────────

export async function getCorrelations(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/correlations`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // [ { id, title, confidence, sources, detail, ... } ]
}

// ── Timeline ──────────────────────────────────────────────────────────────

export async function getTimeline(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/timeline`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // [ { type, value, ts, source, module } ]
}

export async function getHeadlineTimeline(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/timeline/headline`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // [ { type, value, ts, source, module } ] — samo glavni događaji
}

// ── Report ────────────────────────────────────────────────────────────────

export async function generateReport(sessionId, format = 'text') {
  const res = await fetch(`${BASE}/api/session/${sessionId}/report?format=${format}`);
  if (!res.ok) throw new Error(await res.text());
  if (format === 'json') return res.json();
  if (format === 'pdf' || format === 'docx' || format === 'html') return res.blob();
  return res.text();
}

// Preuzmi izveštaj kao fajl (PDF/DOCX/HTML) direktno na disk
export async function downloadReportFile(sessionId, format) {
  const blob = await generateReport(sessionId, format);
  const ext = { pdf: 'pdf', docx: 'docx', html: 'html' }[format] || format;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forenzicki_izvestaj_${new Date().toISOString().slice(0, 10)}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Dashboard rezime / graf korelacija ────────────────────────────────────

export async function getDashboard(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/dashboard`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { analyzed_modules, total_artifacts, alerts, correlations, ... }
}

export async function getCorrelationGraph(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/correlations/graph`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { nodes, edges, stats }
}

// Case management: svi slučajevi (multi-case, perzistentni)
export async function getCases() {
  const res = await fetch(`${BASE}/api/cases`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { cases: [...] }
}

// Detalji slučaja: runs (verzije), audit trag (chain-of-custody), reproducibilnost
export async function getCaseInfo(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/case`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { case, runs, audit, audit_chain, reproducible }
}

// Galerija: sve pronađene slike i snimci sa metapodacima
export async function getMedia(sessionId, opts = {}) {
  const params = new URLSearchParams();
  Object.entries(opts).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '' && v !== false) params.set(k, v);
  });
  const qs = params.toString();
  const res = await fetch(`${BASE}/api/session/${sessionId}/media${qs ? '?' + qs : ''}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { count, with_gps, stego, media: [...] }
}

// Popis SVIH baza u dump-u (klasifikovane po imenu i tabelama)
export async function getDatabases(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/databases`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { summary, databases: [...] }
}

// AI forenzički zaključak (Claude) — može da traje (dug odgovor)
export async function getAiConclusion(sessionId) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/ai-conclusion`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { available, conclusion|reason, model, usage }
}

// Filtriran timeline: opts = { type, search, severity, limit, offset }
export async function searchTimeline(sessionId, opts = {}) {
  const params = new URLSearchParams();
  Object.entries(opts).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') params.set(k, v);
  });
  const qs = params.toString();
  const res = await fetch(`${BASE}/api/session/${sessionId}/timeline${qs ? '?' + qs : ''}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// ── Artefakti — pristup originalnim fajlovima ──────────────────────────────

export function getArtifactFileUrl(sessionId, path) {
  return `${BASE}/api/session/${sessionId}/file?path=${encodeURIComponent(path)}`;
}

export async function revealArtifactFile(sessionId, path) {
  const res = await fetch(`${BASE}/api/session/${sessionId}/reveal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
