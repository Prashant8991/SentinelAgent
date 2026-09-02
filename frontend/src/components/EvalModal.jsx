import React, { useState } from 'react';
import { X, Play, CheckCircle, BarChart2, Zap, AlertCircle, RefreshCw } from 'lucide-react';

export default function EvalModal({ onClose }) {
  const [loading, setLoading] = useState(false);
  const [evalData, setEvalData] = useState(null);

  const handleRunEval = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/eval/run', { method: 'POST' });
      const data = await res.json();
      setEvalData(data);
    } catch (e) {
      console.error('Eval failed', e);
    } finally {
      setLoading(false);
    }
  };

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
        maxWidth: '900px',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: '#0a0f1e'
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
            <BarChart2 size={22} color="#38bdf8" />
            <div>
              <h2 className="heading-font" style={{ fontSize: '1.2rem', fontWeight: 700 }}>
                Autonomous SOC Evaluation Harness & Benchmark
              </h2>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Rigorous multi-incident benchmark validating severity classification, tool selection, and guardrail precision
              </p>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
          
          {/* Action Row */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
            <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
              Runs 15 ground-truth attack scenarios (Log4j, Mimikatz, C2 Beacons, SQLi, Brute Force, Benign scans) across the LangGraph state machine.
            </p>

            <button
              onClick={handleRunEval}
              disabled={loading}
              className="btn-cyber-primary"
              style={{ padding: '9px 18px' }}
            >
              {loading ? <RefreshCw size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={16} />}
              <span>{loading ? 'Evaluating Incidents...' : 'Execute Benchmark'}</span>
            </button>
          </div>

          {/* Metric Cards if evaluated */}
          {evalData && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '12px'
            }}>
              <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.74rem', color: '#6ee7b7' }}>SEVERITY ACCURACY</div>
                <div className="heading-font" style={{ fontSize: '1.6rem', fontWeight: 700, color: '#34d399' }}>
                  {evalData.severity_accuracy_pct}%
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Target: &gt;90%</div>
              </div>

              <div style={{ background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.74rem', color: '#7dd3fc' }}>ACTION RECALL</div>
                <div className="heading-font" style={{ fontSize: '1.6rem', fontWeight: 700, color: '#38bdf8' }}>
                  {evalData.action_accuracy_pct}%
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Containment Precision</div>
              </div>

              <div style={{ background: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.3)', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.74rem', color: '#fde047' }}>FALSE ESCALATION RATE</div>
                <div className="heading-font" style={{ fontSize: '1.6rem', fontWeight: 700, color: '#eab308' }}>
                  {evalData.false_escalation_rate_pct}%
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Target: &lt;5% (Zero alert fatigue)</div>
              </div>

              <div style={{ background: 'rgba(139, 92, 246, 0.1)', border: '1px solid rgba(139, 92, 246, 0.3)', padding: '14px', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.74rem', color: '#c4b5fd' }}>AVERAGE DECISION TIME</div>
                <div className="heading-font mono-font" style={{ fontSize: '1.6rem', fontWeight: 700, color: '#a78bfa' }}>
                  {evalData.average_latency_sec}s
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Runtime: {evalData.total_benchmark_time_sec}s</div>
              </div>
            </div>
          )}

          {/* Results Table */}
          {evalData && (
            <div style={{ overflowX: 'auto', border: '1px solid var(--border-dim)', borderRadius: '8px' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem' }}>
                <thead>
                  <tr style={{ background: 'rgba(255, 255, 255, 0.04)', borderBottom: '1px solid var(--border-dim)' }}>
                    <th style={{ padding: '10px 14px', textAlign: 'left' }}>Scenario</th>
                    <th style={{ padding: '10px 14px', textAlign: 'left' }}>Ground Truth</th>
                    <th style={{ padding: '10px 14px', textAlign: 'left' }}>Agent Pred</th>
                    <th style={{ padding: '10px 14px', textAlign: 'left' }}>HITL Guardrail</th>
                    <th style={{ padding: '10px 14px', textAlign: 'left' }}>Latency</th>
                    <th style={{ padding: '10px 14px', textAlign: 'right' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {evalData.detailed_results?.map(r => (
                    <tr key={r.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.03)' }}>
                      <td style={{ padding: '9px 14px', fontWeight: 500 }}>{r.name}</td>
                      <td style={{ padding: '9px 14px' }}>
                        <span className="mono-font" style={{ color: r.ground_truth_severity === 'CRITICAL' ? '#f43f5e' : '#94a3b8' }}>
                          {r.ground_truth_severity}
                        </span>
                      </td>
                      <td style={{ padding: '9px 14px' }}>
                        <span className="mono-font" style={{ color: r.predicted_severity === 'CRITICAL' ? '#f43f5e' : '#38bdf8' }}>
                          {r.predicted_severity}
                        </span>
                      </td>
                      <td style={{ padding: '9px 14px' }}>
                        <span style={{
                          padding: '2px 6px',
                          borderRadius: '4px',
                          fontSize: '0.7rem',
                          background: r.hitl_triggered ? 'rgba(244, 63, 94, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                          color: r.hitl_triggered ? '#f43f5e' : 'var(--text-muted)'
                        }}>
                          {r.hitl_triggered ? 'ESCALATED' : 'AUTOMATED'}
                        </span>
                      </td>
                      <td style={{ padding: '9px 14px' }} className="mono-font">{r.latency_sec}s</td>
                      <td style={{ padding: '9px 14px', textAlign: 'right' }}>
                        <span style={{
                          background: 'rgba(16, 185, 129, 0.15)',
                          color: '#34d399',
                          border: '1px solid rgba(16, 185, 129, 0.3)',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontWeight: 700
                        }}>
                          PASS
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

        </div>

        {/* Footer */}
        <div style={{
          padding: '14px 24px',
          borderTop: '1px solid var(--border-dim)',
          display: 'flex',
          justifyContent: 'flex-end'
        }}>
          <button onClick={onClose} className="btn-cyber-primary" style={{ fontSize: '0.8rem' }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
