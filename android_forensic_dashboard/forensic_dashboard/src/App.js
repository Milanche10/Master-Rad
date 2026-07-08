import { useState } from 'react';
import { C } from './utils/constants';
import { useForensicSession } from './hooks/useForensicSession';

import Sidebar       from './components/Sidebar';
import OpenDump      from './components/OpenDump';
import Dashboard     from './components/Dashboard';
import ModulePanel   from './components/ModulePanel';
import Correlations  from './components/Correlations';
import Timeline      from './components/Timeline';
import Report        from './components/Report';
import CaseInfo      from './components/CaseInfo';
import Gallery       from './components/Gallery';
import ArtifactModal from './components/ArtifactModal';

export default function App() {
  const session = useForensicSession();
  const [activeTab, setActiveTab]       = useState('dashboard');
  const [activeModule, setActiveModule] = useState(null);
  const [selectedArtifact, setSelectedArtifact] = useState(null);

  // Nema aktivne sesije → prikaži Open Dump ekran
  if (!session.sessionId) {
    return (
      <div style={{ display: 'flex', height: '100%', background: C.bg }}>
        <OpenDump
          onOpen={session.openDump}
          loading={session.loading}
          error={session.error}
        />
      </div>
    );
  }

  const handleSelectModule = (moduleId) => {
    setActiveModule(moduleId);
    setActiveTab('module');
  };

  const handleSelectTab = (tab) => {
    setActiveTab(tab);
    if (tab !== 'module') setActiveModule(null);
  };

  const handleViewModule = (moduleId) => {
    setActiveModule(moduleId);
    setActiveTab('module');
  };

  const handleViewCorrelations = () => {
    setActiveTab('correlations');
    session.loadCorrelations();
  };

  // Kad se prebaci na timeline/correlations tab, automatski učitaj
  const handleTabChange = (tab) => {
    handleSelectTab(tab);
    if (tab === 'correlations') session.loadCorrelations();
    if (tab === 'timeline') {
      session.loadTimeline();
      session.loadHeadlineTimeline();
    }
  };

  return (
    <div style={{
      display: 'flex',
      height: '100%',
      background: C.bg,
      overflow: 'hidden',
    }}>
      {/* Sidebar */}
      <Sidebar
        sessionInfo={session.sessionInfo}
        statuses={session.statuses}
        results={session.results}
        activeModule={activeModule}
        activeTab={activeTab}
        onSelectModule={handleSelectModule}
        onSelectTab={handleTabChange}
        completedCount={session.completedCount}
        totalModules={session.totalModules}
        alertCount={session.alertCount}
        correlationCount={session.correlations?.length || 0}
        timelineCount={session.timeline?.length || 0}
      />

      {/* Main content */}
      <main style={{
        flex: 1,
        display: 'flex',
        overflow: 'hidden',
        position: 'relative',
      }}>
        {/* Error banner */}
        {session.error && (
          <div style={{
            position: 'absolute',
            top: 0, left: 0, right: 0,
            background: C.redDim,
            borderBottom: `1px solid ${C.red}44`,
            padding: '8px 16px',
            color: C.red,
            fontSize: 12,
            fontFamily: C.fontMono,
            zIndex: 20,
          }}>
            ⚠ {session.error}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <Dashboard
            sessionInfo={session.sessionInfo}
            statuses={session.statuses}
            results={session.results}
            completedCount={session.completedCount}
            totalModules={session.totalModules}
            alertCount={session.alertCount}
            correlationCount={session.correlations?.length || 0}
            onRunModule={session.runModule}
            onViewModule={handleViewModule}
            onRunAll={session.runAll}
            onViewCorrelations={handleViewCorrelations}
            loading={session.loading}
          />
        )}

        {activeTab === 'module' && activeModule && (
          <ModulePanel
            moduleId={activeModule}
            data={session.results[activeModule]}
            status={session.statuses[activeModule]}
            onRun={session.runModule}
            onSelectArtifact={setSelectedArtifact}
          />
        )}

        {activeTab === 'correlations' && (
          <Correlations
            correlations={session.correlations}
            onLoad={session.loadCorrelations}
            loading={session.loading}
          />
        )}

        {activeTab === 'timeline' && (
          <Timeline
            timeline={session.timeline}
            headlineTimeline={session.headlineTimeline}
            onLoad={() => {
              session.loadTimeline();
              session.loadHeadlineTimeline();
            }}
            loading={session.loading}
            onSelectArtifact={setSelectedArtifact}
          />
        )}

        {activeTab === 'report' && (
          <Report
            report={session.report}
            onGenerate={session.generateReport}
            loading={session.loading}
            sessionId={session.sessionId}
          />
        )}

        {activeTab === 'gallery' && (
          <Gallery sessionId={session.sessionId} onOpen={setSelectedArtifact} />
        )}

        {activeTab === 'case' && (
          <CaseInfo sessionId={session.sessionId} />
        )}
      </main>

      {selectedArtifact && (
        <ArtifactModal
          artifact={selectedArtifact}
          sessionId={session.sessionId}
          onClose={() => setSelectedArtifact(null)}
        />
      )}
    </div>
  );
}
