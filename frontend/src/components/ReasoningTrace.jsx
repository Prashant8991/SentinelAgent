import React, { useState } from 'react';
import { Terminal, Shield, Cpu, ExternalLink, ChevronDown, ChevronRight, FileText, CheckCircle2 } from 'lucide-react';

export default function ReasoningTrace({ incident, onOpenReport }) {
  const [expandedSteps, setExpandedSteps] = useState({});

  if (!incident) {
    return (
      <div className="glass-panel" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px', color: 'var(--text-muted)' }}>
        <Terminal size={40} style={{ opacity: 0.4, marginBottom: '16px' }} />
        <p style={{ fontSize: '0.95rem' }}>Select an alert from the feed to inspect agent reasoning trace.</p>
        <span style={{ fontSize: '0.8rem', marginTop: '6px' }}>Or click "Inject Threat" in the header to simulate a live attack.</span>
      </div>
    );
  }

  const toggleStep = (stepNum) => {
    setExpandedSteps(prev => ({ ...prev, [stepNum]: !prev[stepNum] }));
  };

  const steps = incident.investigation_steps || [];
  const mitreTactics = incident.mitre_tactics || [];
  const actions = incident.remediation_actions || [];

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      
      {/* Header bar */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-dim)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="mono-font" style={{ fontSize: '0.78rem', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.12)', padding: '2px 8px', borderRadius: '4px' }}>
              {incident.id}
            </span>
            <h2 className="heading-font" style={{ fontSize: '1.15rem', fontWeight: 700 }}>
              {incident.alert_type}
            </h2>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Source: <span className="mono-font" style={{ color: 'var(--text-primary)' }}>{incident.source_ip}</span> &rarr; Target: <span className="mono-font" style={{ color: 'var(--text-primary)' }}>{incident.destination_ip}:{incident.destination_port}</span>
          </p>
        </div>

        <button onClick={onOpenReport} className="btn-cyber-ghost" style={{ fontSize: '0.82rem' }}>
          <FileText size={15} />
          <span>Full Report</span>
        </button>
      </div>

      {/* Main Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        
        {/* ML Pre-Triage Card */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.02)',
          border: '1px solid var(--border-dim)',
          borderRadius: '10px',
          padding: '14px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <Cpu size={16} color="#818cf8" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Classical ML Pre-Triage (Random Forest Classifier)
            </span>
            <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: '#34d399', fontWeight: 600 }}>
              Latency &lt; 1ms
            </span>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Initial classification scored severity as <strong style={{ color: '#38bdf8' }}>{incident.ml_severity}</strong>. Classical ML model pre-filters high-volume telemetry before engaging tool loops.
          </div>
        </div>

        {/* Autonomous Tool Execution Stream */}
        <div>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Terminal size={14} color="#38bdf8" />
            Autonomous Tool Invocations ({steps.length} tool calls)
          </h4>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {steps.map(s => {
              const isOpen = expandedSteps[s.step_number];
              const tool = s.tool_call;

              return (
                <div
                  key={s.step_number}
                  style={{
                    background: 'rgba(0, 0, 0, 0.25)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: '8px',
                    overflow: 'hidden'
                  }}
                >
                  <div
                    onClick={() => toggleStep(s.step_number)}
                    style={{
                      padding: '10px 14px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                      background: 'rgba(255, 255, 255, 0.02)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="mono-font" style={{ fontSize: '0.72rem', color: '#38bdf8', fontWeight: 700 }}>
                        STEP {s.step_number}
                      </span>
                      <span className="mono-font" style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {tool?.tool_name || 'Tool Call'}
                      </span>
                      <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        ({tool?.latency_ms || 5}ms)
                      </span>
                    </div>
                    {isOpen ? <ChevronDown size={15} color="var(--text-muted)" /> : <ChevronRight size={15} color="var(--text-muted)" />}
                  </div>

                  <div style={{ padding: '10px 14px', borderTop: '1px solid var(--border-dim)', fontSize: '0.8rem' }}>
                    <div style={{ color: 'var(--text-secondary)', marginBottom: '6px' }}>
                      <strong style={{ color: '#94a3b8' }}>Agent Thought: </strong>
                      {s.thought}
                    </div>
                    <div style={{ color: '#34d399', fontWeight: 500 }}>
                      <strong style={{ color: '#94a3b8' }}>Evidence Extracted: </strong>
                      {s.conclusion}
                    </div>

                    {isOpen && tool?.output && (
                      <div style={{ marginTop: '10px' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                          RAW TOOL TELEMETRY (JSON)
                        </div>
                        <pre className="mono-font" style={{
                          background: '#040711',
                          padding: '10px',
                          borderRadius: '6px',
                          fontSize: '0.72rem',
                          color: '#38bdf8',
                          overflowX: 'auto',
                          border: '1px solid rgba(255, 255, 255, 0.05)'
                        }}>
                          {JSON.stringify(tool.output, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* MITRE ATT&CK & Root Cause */}
        <div style={{
          background: 'rgba(56, 189, 248, 0.04)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          borderRadius: '10px',
          padding: '14px'
        }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={16} />
            Root Cause & MITRE ATT&CK Mapping
          </h4>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
            {incident.root_cause || 'Investigation in progress...'}
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {mitreTactics.map((tactic, idx) => (
              <span
                key={idx}
                style={{
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  color: '#7dd3fc',
                  padding: '3px 8px',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontWeight: 600
                }}
              >
                {tactic}
              </span>
            ))}
          </div>
        </div>

        {/* Remediation Status Banner */}
        <div style={{
          background: incident.status === 'ESCALATED_TO_HUMAN' ? 'rgba(244, 63, 94, 0.08)' : 'rgba(16, 185, 129, 0.08)',
          border: `1px solid ${incident.status === 'ESCALATED_TO_HUMAN' ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
          borderRadius: '10px',
          padding: '14px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px'
        }}>
          <div>
            <div style={{
              fontSize: '0.86rem',
              fontWeight: 700,
              color: incident.status === 'ESCALATED_TO_HUMAN' ? '#f43f5e' : '#34d399',
              marginBottom: '2px'
            }}>
              {incident.status === 'ESCALATED_TO_HUMAN' ? 'Human Analyst Escalation Triggered' : 'Containment Executed & Logged'}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Action: <strong className="mono-font" style={{ color: 'var(--text-primary)' }}>{actions[0]?.action_type || 'CREATE_TICKET'}</strong> against <strong className="mono-font">{actions[0]?.target || 'N/A'}</strong>
            </div>
          </div>

          <div className="mono-font" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Audit: {incident.audit_hash ? incident.audit_hash.slice(0, 16) + '...' : 'N/A'}
          </div>
        </div>

      </div>
    </div>
  );
}
