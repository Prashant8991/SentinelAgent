import React from 'react';
import { ArrowRight, CheckCircle2, ShieldCheck, Database, Search, AlertOctagon, Terminal } from 'lucide-react';

const NODES = [
  { id: 'ingest', label: '1. Ingestion Agent', desc: 'Log Normalization & Parsing', icon: Terminal },
  { id: 'triage', label: '2. Triage Agent', desc: 'Random Forest ML Classifier', icon: AlertOctagon },
  { id: 'investigate', label: '3. Investigation Agent', desc: 'Tool Loop (IP, CVE, WHOIS)', icon: Search },
  { id: 'decision', label: '4. Decision Guardrails', desc: 'Deterministic Safety Matrix', icon: ShieldCheck },
  { id: 'remediate', label: '5. Remediation Agent', desc: 'Firewall & Containment', icon: CheckCircle2 },
  { id: 'report', label: '6. Audit & Memory', desc: 'SHA-256 Non-Repudiation', icon: Database }
];

export default function AgentGraphVisualizer({ currentStatus, activeIncident }) {
  const isEscalated = activeIncident?.status === 'ESCALATED_TO_HUMAN';
  const isRemediated = activeIncident?.status?.includes('REMEDIATED');

  return (
    <div className="glass-panel" style={{ padding: '16px 20px', margin: '0 16px 16px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <h3 className="heading-font" style={{ fontSize: '0.95rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: '#38bdf8' }} className="pulse-live"></span>
          LangGraph Multi-Agent Orchestration State Machine
        </h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          {activeIncident ? `Tracking Incident: ${activeIncident.id}` : 'Idle / Ready for Alerts'}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', overflowX: 'auto', paddingBottom: '6px' }}>
        {NODES.map((node, idx) => {
          const IconComponent = node.icon;
          const isNodeActive = activeIncident != null;
          let nodeBorder = 'var(--border-dim)';
          let nodeBg = 'rgba(255, 255, 255, 0.02)';
          let iconColor = 'var(--text-muted)';

          if (node.id === 'decision' && isEscalated) {
            nodeBorder = 'rgba(244, 63, 94, 0.6)';
            nodeBg = 'rgba(244, 63, 94, 0.15)';
            iconColor = '#f43f5e';
          } else if (isNodeActive) {
            nodeBorder = 'rgba(56, 189, 248, 0.35)';
            nodeBg = 'rgba(56, 189, 248, 0.08)';
            iconColor = '#38bdf8';
          }

          return (
            <React.Fragment key={node.id}>
              <div style={{
                flex: '1 1 0',
                minWidth: '150px',
                padding: '12px 14px',
                borderRadius: '10px',
                background: nodeBg,
                border: `1px solid ${nodeBorder}`,
                transition: 'all 0.3s ease',
                position: 'relative'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <IconComponent size={16} color={iconColor} />
                  <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {node.label}
                  </span>
                </div>
                <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  {node.desc}
                </p>
                {node.id === 'decision' && isEscalated && (
                  <span style={{
                    display: 'inline-block',
                    marginTop: '6px',
                    fontSize: '0.68rem',
                    color: '#f43f5e',
                    fontWeight: 700,
                    background: 'rgba(244, 63, 94, 0.2)',
                    padding: '2px 6px',
                    borderRadius: '4px'
                  }}>
                    HITL Intercept
                  </span>
                )}
              </div>
              {idx < NODES.length - 1 && (
                <ArrowRight size={16} color="var(--border-bright)" style={{ opacity: 0.6, flexShrink: 0 }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
