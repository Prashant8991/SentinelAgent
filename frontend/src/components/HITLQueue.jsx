import React, { useState } from 'react';
import { ShieldAlert, Check, X, AlertTriangle, UserCheck } from 'lucide-react';

export default function HITLQueue({ incidents, onResolveAction, resolving }) {
  const pending = incidents.filter(i => i.status === 'ESCALATED_TO_HUMAN');
  const [analystName, setAnalystName] = useState('Analyst-Lead');
  const [notes, setNotes] = useState('');

  if (pending.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '16px 20px', margin: '0 16px 16px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            padding: '6px',
            borderRadius: '8px'
          }}>
            <UserCheck size={18} color="#10b981" />
          </div>
          <div>
            <h3 className="heading-font" style={{ fontSize: '0.92rem', fontWeight: 600 }}>
              Human-in-the-Loop (HITL) Queue Clean
            </h3>
            <p style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
              Zero high-risk actions awaiting manual human analyst authorization.
            </p>
          </div>
        </div>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }} className="mono-font">
          Autonomous Guardrails: ACTIVE
        </span>
      </div>
    );
  }

  return (
    <div className="glass-panel cyber-glow-critical" style={{ padding: '16px 20px', margin: '0 16px 16px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
        <div style={{
          background: 'rgba(244, 63, 94, 0.2)',
          border: '1px solid rgba(244, 63, 94, 0.4)',
          padding: '6px',
          borderRadius: '8px'
        }}>
          <ShieldAlert size={20} color="#f43f5e" />
        </div>
        <div>
          <h3 className="heading-font" style={{ fontSize: '1rem', fontWeight: 700, color: '#f43f5e' }}>
            Action Escalation Queue ({pending.length} Pending Approval)
          </h3>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            Safety Guardrail intercepted high-risk destructive action. Requires explicit human confirmation.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {pending.map(inc => {
          const action = inc.remediation_actions?.[0] || {};

          return (
            <div
              key={inc.id}
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(244, 63, 94, 0.3)',
                borderRadius: '8px',
                padding: '14px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '14px'
              }}
            >
              <div style={{ flex: '1 1 300px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <span className="badge-critical" style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700 }}>
                    {action.action_type || 'CONTAINMENT'}
                  </span>
                  <span className="mono-font" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Target: {action.target || inc.destination_ip}
                  </span>
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                    (Incident: {inc.id})
                  </span>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {action.justification || 'CRITICAL GUARDRAIL: Host isolation requires human sign-off.'}
                </p>
              </div>

              {/* Approval controls */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <button
                  disabled={resolving}
                  onClick={() => onResolveAction(inc.id, action.id, 'APPROVE', analystName, notes)}
                  className="btn-cyber-danger"
                  style={{ fontSize: '0.8rem' }}
                >
                  <Check size={14} />
                  <span>Authorize Containment</span>
                </button>

                <button
                  disabled={resolving}
                  onClick={() => onResolveAction(inc.id, action.id, 'DENY', analystName, notes)}
                  className="btn-cyber-ghost"
                  style={{ fontSize: '0.8rem' }}
                >
                  <X size={14} />
                  <span>Reject</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
