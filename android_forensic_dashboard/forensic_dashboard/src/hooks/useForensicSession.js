import { useState, useCallback, useRef } from 'react';
import * as api from '../utils/api';
import { MODULES } from '../utils/constants';

const INITIAL_STATUSES = Object.fromEntries(
  MODULES.map(m => [m.id, 'idle'])
);

export function useForensicSession() {
  const [sessionId, setSessionId]       = useState(null);
  const [sessionInfo, setSessionInfo]   = useState(null);   // dump summary
  const [statuses, setStatuses]         = useState(INITIAL_STATUSES);
  const [results, setResults]           = useState({});
  const [correlations, setCorrelations] = useState([]);
  const [timeline, setTimeline]         = useState([]);
  const [headlineTimeline, setHeadlineTimeline] = useState([]);
  const [report, setReport]             = useState('');
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState(null);

  // Ref za praćenje aktivnog session-a (korisno za cleanup)
  const activeSession = useRef(null);

  // ── Otvori dump (ili Evidence folder iz akvizicije) ───────────────────
  // opts: { examiner, fsCaseId, source } — prosleđuje se kada dolazi iz akvizicije.
  const openDump = useCallback(async (dumpPath, opts = {}) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.createSession(dumpPath, opts);
      setSessionId(data.session_id);
      setSessionInfo(data.summary);
      activeSession.current = data.session_id;
      setStatuses(INITIAL_STATUSES);
      setResults({});
      setCorrelations([]);
      setTimeline([]);
      setHeadlineTimeline([]);
      setReport('');
    } catch (e) {
      setError(`Greška pri otvaranju dump-a: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  // ── Pokreni jedan modul ───────────────────────────────────────────────
  const runModule = useCallback(async (moduleId) => {
    if (!sessionId) return;
    setStatuses(s => ({ ...s, [moduleId]: 'running' }));
    setError(null);
    try {
      const data = await api.runModule(sessionId, moduleId);
      setStatuses(s => ({ ...s, [moduleId]: data.status === 'not_found' ? 'not_found' : 'completed' }));
      setResults(r => ({ ...r, [moduleId]: data }));
    } catch (e) {
      setStatuses(s => ({ ...s, [moduleId]: 'error' }));
      setError(`Modul ${moduleId}: ${e.message}`);
    }
  }, [sessionId]);

  // ── Pokreni sve module sekvencijalno ─────────────────────────────────
  const runAll = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    for (const module of MODULES) {
      if (statuses[module.id] === 'completed') continue;
      setStatuses(s => ({ ...s, [module.id]: 'running' }));
      try {
        const data = await api.runModule(sessionId, module.id);
        setStatuses(s => ({
          ...s,
          [module.id]: data.status === 'not_found' ? 'not_found' : 'completed',
        }));
        setResults(r => ({ ...r, [module.id]: data }));
      } catch (e) {
        setStatuses(s => ({ ...s, [module.id]: 'error' }));
      }
    }
    setLoading(false);
  }, [sessionId, statuses]);

  // ── Učitaj korelacije ─────────────────────────────────────────────────
  const loadCorrelations = useCallback(async () => {
    if (!sessionId) return;
    try {
      const data = await api.getCorrelations(sessionId);
      setCorrelations(data);
    } catch (e) {
      setError(`Korelacije: ${e.message}`);
    }
  }, [sessionId]);

  // ── Učitaj timeline ───────────────────────────────────────────────────
  const loadTimeline = useCallback(async () => {
    if (!sessionId) return;
    try {
      const data = await api.getTimeline(sessionId);
      setTimeline(data);
    } catch (e) {
      setError(`Timeline: ${e.message}`);
    }
  }, [sessionId]);

  // ── Učitaj headline (samo glavni događaji) timeline ──────────────────
  const loadHeadlineTimeline = useCallback(async () => {
    if (!sessionId) return;
    try {
      const data = await api.getHeadlineTimeline(sessionId);
      setHeadlineTimeline(data);
    } catch (e) {
      setError(`Headline timeline: ${e.message}`);
    }
  }, [sessionId]);

  // ── Generiši izveštaj ─────────────────────────────────────────────────
  const generateReport = useCallback(async () => {
    if (!sessionId) return;
    try {
      const text = await api.generateReport(sessionId, 'text');
      setReport(text);
    } catch (e) {
      setError(`Izveštaj: ${e.message}`);
    }
  }, [sessionId]);

  // ── Statistike ────────────────────────────────────────────────────────
  const completedCount = Object.values(statuses).filter(s => s === 'completed').length;
  const totalModules   = MODULES.length;
  const alertCount     = Object.values(results)
    .flatMap(r => r?.alerts || []).length;

  return {
    // State
    sessionId,
    sessionInfo,
    statuses,
    results,
    correlations,
    timeline,
    headlineTimeline,
    report,
    loading,
    error,
    // Computed
    completedCount,
    totalModules,
    alertCount,
    // Actions
    openDump,
    runModule,
    runAll,
    loadCorrelations,
    loadTimeline,
    loadHeadlineTimeline,
    generateReport,
  };
}
