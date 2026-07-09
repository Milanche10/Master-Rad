// api.js — sva komunikacija sa FastAPI backendom

const BASE = '';  // proxy u package.json šalje na localhost:8000

// ── Session management ────────────────────────────────────────────────────

export async function createSession(dumpPath, opts = {}) {
  // dumpPath je putanja do Evidence/dump foldera na serveru.
  // opts: { examiner, fsCaseId, source } — kada dolazi iz akvizicije, povezuje slučaj.
  const res = await fetch(`${BASE}/api/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dump_path: dumpPath,
      examiner: opts.examiner || '',
      fs_case_id: opts.fsCaseId || '',
      source: opts.source || 'dump',
    }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { session_id, case_id, summary }
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

// ── Acquisition layer: detekcija izvora + akvizicija ──────────────────────

export async function getSources() {
  const res = await fetch(`${BASE}/api/sources`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { platform, sources: { mobile:{ready,hint}, ... } }
}

export async function detectPhone() {
  const res = await fetch(`${BASE}/api/detect/phone`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { available, devices:[...], reason }
}

export async function detectSim() {
  const res = await fetch(`${BASE}/api/detect/sim`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { available, readers:[...], reason }
}

export async function detectStorage(kind = 'sdcard') {
  const res = await fetch(`${BASE}/api/detect/storage?kind=${encodeURIComponent(kind)}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { available, disks:[...], reason }
}

// source: mobile|sim|sdcard|usb ; body zavisi od izvora (mount/disk_info, serial/device_info, reader)
export async function startAcquisition(source, body = {}) {
  const res = await fetch(`${BASE}/api/acquire/${source}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { job_id, source }
}

export async function getAcquireJob(jobId) {
  const res = await fetch(`${BASE}/api/acquire/job/${jobId}`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { status, progress, message, logs, result, case_id, ... }
}

export async function cancelAcquireJob(jobId) {
  const res = await fetch(`${BASE}/api/acquire/job/${jobId}/cancel`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function getAcquisitionCases() {
  const res = await fetch(`${BASE}/api/acquire/cases`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { cases: [...] }
}

// ── Universal export (svaki prikaz → PDF/DOCX/HTML/TXT; ceo slučaj → .zip) ──

function _triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function _extFor(format) {
  return { pdf: 'pdf', docx: 'docx', html: 'html', txt: 'txt', text: 'txt' }[format] || format;
}

// view: dashboard|timeline|correlations|evidence|report|module:<id>
export async function downloadExport(sessionId, view, format) {
  if (!sessionId) return;
  const res = await fetch(
    `${BASE}/api/session/${sessionId}/export?view=${encodeURIComponent(view)}&format=${format}`);
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const safeView = String(view).replace(':', '_');
  _triggerDownload(blob, `${safeView}.${_extFor(format)}`);
}

export async function exportArtifact(sessionId, artifact, format) {
  if (!sessionId) return;
  const res = await fetch(
    `${BASE}/api/session/${sessionId}/export/artifact?format=${format}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifact }),
    });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  _triggerDownload(blob, `artefakt.${_extFor(format)}`);
}

export async function downloadCaseZip(sessionId) {
  if (!sessionId) return;
  const res = await fetch(`${BASE}/api/session/${sessionId}/export/case?format=zip`);
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  _triggerDownload(blob, `slucaj.zip`);
}

// ── Setup / provisioning: aplikacija sama preuzme zavisnosti ──────────────

export async function getSetupStatus() {
  const res = await fetch(`${BASE}/api/setup/status`);
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { adb:{found,path,bundled}, ollama:{installed,running,model_ready,models,model} }
}

export async function startSetupAdb() {
  const res = await fetch(`${BASE}/api/setup/adb`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { job_id }  → prati preko getAcquireJob(job_id)
}

export async function startSetupOllama(model = '') {
  const qs = model ? `?model=${encodeURIComponent(model)}` : '';
  const res = await fetch(`${BASE}/api/setup/ollama${qs}`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json(); // { job_id }
}

// Namenski izveštaj akvizicije (SIM/SD/USB) + preuzimanje paketa slučaja
export async function downloadAcquisitionReport(caseId, format = 'pdf') {
  const res = await fetch(`${BASE}/api/acquire/case/${caseId}/report?format=${format}`);
  if (!res.ok) throw new Error(await res.text());
  _triggerDownload(await res.blob(), `${caseId}_izvestaj.${_extFor(format)}`);
}

export async function downloadAcquisitionPackage(caseId, format = 'zip') {
  const res = await fetch(`${BASE}/api/acquire/case/${caseId}/download?format=${format}`);
  if (!res.ok) throw new Error(await res.text());
  _triggerDownload(await res.blob(), `${caseId}.${format === 'tar' ? 'tar.gz' : 'zip'}`);
}
