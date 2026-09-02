import React from 'react';
import { Shield, ShieldAlert, Cpu, Database, Activity, CheckCircle, Flame, BarChart2, RefreshCw } from 'lucide-react';

export default function Header({ status, onToggleMode, onOpenEval, onInjectScenario, injecting, refreshing, onRefresh }) {
  const isSmartLocal = status?.llm_engine?.is_smart_local ?? true;
  const metrics = status?.metrics || { total_incidents: 0, audit_entries: 0, patterns_memorized: 0, pending_hitl_actions: 0 };

  return (
    <header className="glass-panel" style={{ padding: '16px 24px', margin: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        
        {/* Left: Branding */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)',
            padding: '10px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={26} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 className="heading-font" style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
                Sentinel<span style={{ color: '#38bdf8' }}>Agent</span>
              </h1>
              <span style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '2px 8px',
                borderRadius: '6px',
                fontSize: '0.72rem',
                fontWeight: 600,
                letterSpacing: '0.05em',
                textTransform: 'uppercase'
              }}>
                Autonomous SOC Tier-1/2
              </span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', marginTop: '2px' }}>
              Multi-Agent Incident Triage, Threat Investigation, & Guardrail Remediation
            </p>
          </div>
        </div>

        {/* Center/Right: Actions & Toggles */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          
          {/* Refresh Button */}
          <button 
            onClick={onRefresh} 
            className="btn-cyber-ghost" 
            title="Refresh Incidents"
            disabled={refreshing}
          >
            <RefreshCw size={15} style={{ animation: refreshing ? 'spin 1s linear infinite' : 'none' }} />
            <span>Sync</span>
          </button>

          {/* Engine Mode Pill */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: isSmartLocal ? 'rgba(16, 185, 129, 0.1)' : 'rgba(139, 92, 246, 0.1)',
            border: `1px solid ${isSmartLocal ? 'rgba(16, 185, 129, 0.3)' : 'rgba(139, 92, 246, 0.3)'}`,
            padding: '6px 12px',
            borderRadius: '8px'
          }}>
            <Cpu size={16} color={isSmartLocal ? '#10b981' : '#a78bfa'} />
            <div style={{ fontSize: '0.78rem' }}>
              <span style={{ color: 'var(--text-muted)' }}>Mode: </span>
              <strong style={{ color: isSmartLocal ? '#34d399' : '#c084fc' }}>
                {isSmartLocal ? 'Smart Dual-Mode (Offline Sandbox)' : `Live API (${status?.llm_engine?.mode})`}
              </strong>
            </div>
            {status?.llm_engine?.has_openai && (
              <button
                onClick={onToggleMode}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#38bdf8',
                  fontSize: '0.75rem',
                  textDecoration: 'underline',
                  cursor: 'pointer',
                  marginLeft: '4px'
                }}
              >
                Switch
              </button>
            )}
          </div>

          {/* Benchmark Eval Button */}
          <button onClick={onOpenEval} className="btn-cyber-primary">
            <BarChart2 size={16} />
            <span>Evaluation Harness</span>
          </button>
        </div>
      </div>

      {/* Metric Telemetry Row & Quick Injectors */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '12px',
        borderTop: '1px solid var(--border-dim)',
        paddingTop: '12px'
      }}>
        {/* Telemetry counters */}
        <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem' }}>
            <Activity size={15} color="#38bdf8" />
            <span style={{ color: 'var(--text-secondary)' }}>Incidents:</span>
            <strong className="mono-font">{metrics.total_incidents}</strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem' }}>
            <ShieldAlert size={15} color={metrics.pending_hitl_actions > 0 ? '#f43f5e' : '#10b981'} />
            <span style={{ color: 'var(--text-secondary)' }}>Pending HITL:</span>
            <strong className="mono-font" style={{ color: metrics.pending_hitl_actions > 0 ? '#f43f5e' : '#10b981' }}>
              {metrics.pending_hitl_actions}
            </strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem' }}>
            <Database size={15} color="#818cf8" />
            <span style={{ color: 'var(--text-secondary)' }}>Pattern Memory:</span>
            <strong className="mono-font">{metrics.patterns_memorized} signatures</strong>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.82rem' }}>
            <CheckCircle size={15} color="#34d399" />
            <span style={{ color: 'var(--text-secondary)' }}>Audit Records:</span>
            <strong className="mono-font">{metrics.audit_entries}</strong>
          </div>
        </div>

        {/* Quick Attack Injectors */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Flame size={13} color="#f43f5e" /> Inject Threat:
          </span>
          <button 
            disabled={injecting} 
            onClick={() => onInjectScenario('log4j')} 
            className="btn-cyber-ghost"
            style={{ fontSize: '0.76rem', padding: '4px 10px' }}
          >
            Log4j RCE
          </button>
          <button 
            disabled={injecting} 
            onClick={() => onInjectScenario('ransomware')} 
            className="btn-cyber-ghost"
            style={{ fontSize: '0.76rem', padding: '4px 10px' }}
          >
            Ransomware / Mimikatz
          </button>
          <button 
            disabled={injecting} 
            onClick={() => onInjectScenario('bruteforce')} 
            className="btn-cyber-ghost"
            style={{ fontSize: '0.76rem', padding: '4px 10px' }}
          >
            SSH Brute Force
          </button>
          <button 
            disabled={injecting} 
            onClick={() => onInjectScenario('sqli')} 
            className="btn-cyber-ghost"
            style={{ fontSize: '0.76rem', padding: '4px 10px' }}
          >
            SQL Injection
          </button>
          <button 
            disabled={injecting} 
            onClick={() => onInjectScenario('benign_scan')} 
            className="btn-cyber-ghost"
            style={{ fontSize: '0.76rem', padding: '4px 10px', borderColor: 'rgba(16, 185, 129, 0.3)' }}
          >
            Benign Port Scan
          </button>
        </div>
      </div>
    </header>
  );
}
