import React from 'react';
import { X, Shield, Clock, Database, Copy, Check } from 'lucide-react';

export default function IncidentReportModal({ incident, onClose }) {
  const [copied, setCopied] = React.useState(false);

  if (!incident) return null;

  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(incident, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const timeline = incident.timeline || [];

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      padding: '20px'
    }}>
      <div className="glass-panel cyber-glow-cyan" style={{
        width: '100%',
        maxWidth: '800px',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: '#090f1d'
      }}>
        {/* Header */}
        <div style={{
          padding: '18px 24px',
          borderBottom: '1px solid var(--border-dim)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield size={20} color="#38bdf8" />
            <h2 className="heading-font" style={{ fontSize: '1.2rem', fontWeight: 700 }}>
              SOC Incident Investigation Dossier
            </h2>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          
          {/* Key Identifiers */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '12px',
            background: 'rgba(255, 255, 255, 0.02)',
            padding: '14px',
            borderRadius: '8px',
            border: '1px solid var(--border-dim)'
          }}>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>INCIDENT ID</div>
              <div className="mono-font" style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8' }}>{incident.id}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>FINAL SEVERITY</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: incident.final_severity === 'CRITICAL' ? '#f43f5e' : '#eab308' }}>
                {incident.final_severity}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>STATUS</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{incident.status}</div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>INGRESS TARGET</div>
              <div className="mono-font" style={{ fontSize: '0.85rem' }}>{incident.source_ip} &rarr; :{incident.destination_port}</div>
            </div>
          </div>

          {/* Root Cause & Synthesis */}
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#38bdf8', marginBottom: '6px' }}>
              Root Cause Determination
            </h3>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {incident.root_cause}
            </p>
          </div>

          {/* MITRE ATT&CK Matrix */}
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px' }}>
              MITRE ATT&CK Adversary Tactics
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {(incident.mitre_tactics || []).map((tac, i) => (
                <span key={i} style={{
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  padding: '4px 10px',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  color: '#7dd3fc'
                }}>
                  {tac}
                </span>
              ))}
            </div>
          </div>

          {/* Forensic Audit Timeline */}
          <div>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={15} /> Forensic Action Timeline
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {timeline.map((event, idx) => (
                <div key={idx} className="mono-font" style={{
                  fontSize: '0.76rem',
                  color: 'var(--text-secondary)',
                  background: 'rgba(0, 0, 0, 0.3)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  borderLeft: '3px solid #38bdf8'
                }}>
                  {event}
                </div>
              ))}
            </div>
          </div>

          {/* Non-Repudiation Cryptographic Hash */}
          <div style={{
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid var(--border-dim)',
            padding: '12px',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}>
            <div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SHA-256 AUDIT LOG FINGERPRINT (NON-REPUDIATION)</div>
              <div className="mono-font" style={{ fontSize: '0.74rem', color: '#34d399', wordBreak: 'break-all' }}>
                {incident.audit_hash}
              </div>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div style={{
          padding: '14px 24px',
          borderTop: '1px solid var(--border-dim)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <button onClick={handleCopyJSON} className="btn-cyber-ghost" style={{ fontSize: '0.8rem' }}>
            {copied ? <Check size={14} color="#34d399" /> : <Copy size={14} />}
            <span>{copied ? 'Copied to Clipboard' : 'Copy Dossier JSON'}</span>
          </button>

          <button onClick={onClose} className="btn-cyber-primary" style={{ fontSize: '0.8rem' }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
