import React, { useState, useEffect } from 'react';
import Header from './components/Header.jsx';
import AgentGraphVisualizer from './components/AgentGraphVisualizer.jsx';
import AlertStream from './components/AlertStream.jsx';
import ReasoningTrace from './components/ReasoningTrace.jsx';
import HITLQueue from './components/HITLQueue.jsx';
import IncidentReportModal from './components/IncidentReportModal.jsx';
import EvalModal from './components/EvalModal.jsx';

export default function App() {
  const [status, setStatus] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [showEvalModal, setShowEvalModal] = useState(false);
  const [injecting, setInjecting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [resolving, setResolving] = useState(false);

  // Fetch initial system status & incidents
  const loadData = async () => {
    try {
      setRefreshing(true);
      const [statusRes, incidentsRes] = await Promise.all([
        fetch('/api/status'),
        fetch('/api/incidents')
      ]);
      const statusData = await statusRes.json();
      const incidentsData = await incidentsRes.json();

      setStatus(statusData);
      setIncidents(incidentsData);

      // Auto-select latest incident if none selected or selection was updated
      if (incidentsData.length > 0) {
        setSelectedIncident(prev => {
          if (!prev) return incidentsData[0];
          const found = incidentsData.find(i => i.id === prev.id);
          return found || incidentsData[0];
        });
      }
    } catch (err) {
      console.error('Error fetching SOC data:', err);
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Handle LLM Mode Toggle
  const handleToggleMode = async () => {
    if (!status) return;
    const currentLive = status.llm_engine?.live_llm_enabled;
    try {
      const res = await fetch('/api/settings/toggle-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enable_live_llm: !currentLive })
      });
      const data = await res.json();
      setStatus(prev => ({ ...prev, llm_engine: data.status }));
    } catch (e) {
      console.error('Failed to toggle mode:', e);
    }
  };

  // Inject attack simulation
  const handleInjectScenario = async (scenario) => {
    setInjecting(true);
    try {
      const res = await fetch('/api/simulation/inject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      const result = await res.json();
      await loadData();
      
      // Auto-select newly created incident
      if (result.incident_id) {
        const fullIncRes = await fetch(`/api/incidents/${result.incident_id}`);
        if (fullIncRes.ok) {
          const fullInc = await fullIncRes.json();
          setSelectedIncident(fullInc);
        }
      }
    } catch (e) {
      console.error('Injection error:', e);
    } finally {
      setInjecting(false);
    }
  };

  // Resolve HITL action (Approve or Deny)
  const handleResolveAction = async (incidentId, actionId, decision, analystName, notes) => {
    setResolving(true);
    try {
      const res = await fetch(`/api/hitl/${incidentId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: actionId, decision, analyst_name: analystName, notes })
      });
      if (res.ok) {
        await loadData();
      }
    } catch (e) {
      console.error('Action resolve failed:', e);
    } finally {
      setResolving(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* Top Cyber Command Header */}
      <Header
        status={status}
        onToggleMode={handleToggleMode}
        onOpenEval={() => setShowEvalModal(true)}
        onInjectScenario={handleInjectScenario}
        injecting={injecting}
        refreshing={refreshing}
        onRefresh={loadData}
      />

      {/* Human-in-the-Loop Pending Escalations Drawer */}
      <HITLQueue
        incidents={incidents}
        onResolveAction={handleResolveAction}
        resolving={resolving}
      />

      {/* Interactive LangGraph Orchestration State Machine */}
      <AgentGraphVisualizer
        currentStatus={status}
        activeIncident={selectedIncident}
      />

      {/* Main SOC Command Workspace (2 Columns) */}
      <main style={{
        flex: 1,
        display: 'grid',
        gridTemplateColumns: 'minmax(320px, 380px) minmax(500px, 1fr)',
        gap: '16px',
        padding: '0 16px 16px 16px',
        height: 'calc(100vh - 350px)',
        minHeight: '520px'
      }}>
        {/* Left: Ingestion & Alert Feed */}
        <AlertStream
          incidents={incidents}
          selectedIncident={selectedIncident}
          onSelectIncident={setSelectedIncident}
        />

        {/* Right: Reasoning Trace & Tool Telemetry */}
        <ReasoningTrace
          incident={selectedIncident}
          onOpenReport={() => setShowReportModal(true)}
        />
      </main>

      {/* Dossier Modal */}
      {showReportModal && (
        <IncidentReportModal
          incident={selectedIncident}
          onClose={() => setShowReportModal(false)}
        />
      )}

      {/* Benchmark Evaluation Modal */}
      {showEvalModal && (
        <EvalModal
          onClose={() => setShowEvalModal(false)}
        />
      )}
    </div>
  );
}
