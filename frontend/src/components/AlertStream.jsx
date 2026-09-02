import React, { useState } from 'react';
import { AlertTriangle, ShieldCheck, Clock, Search, Filter, ArrowUpRight } from 'lucide-react';

export default function AlertStream({ incidents, selectedIncident, onSelectIncident }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filtered = incidents.filter(inc => {
    const matchesSev = filterSeverity === 'ALL' || inc.final_severity === filterSeverity;
    const matchesSearch = !searchTerm || 
      inc.alert_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.source_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.id?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Header & Filters */}
      <div style={{ padding: '16px', borderBottom: '1px solid var(--border-dim)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h2 className="heading-font" style={{ fontSize: '1.05rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} color="#38bdf8" />
            Live Ingestion Feed
            <span style={{ fontSize: '0.75rem', background: 'rgba(255, 255, 255, 0.08)', padding: '2px 8px', borderRadius: '12px', color: 'var(--text-secondary)' }}>
              {filtered.length}
            </span>
          </h2>
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative', marginBottom: '10px' }}>
          <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '10px' }} />
          <input
            type="text"
            placeholder="Filter by IP, alert type, ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid var(--border-dim)',
              borderRadius: '6px',
              padding: '7px 10px 7px 32px',
              fontSize: '0.8rem',
              color: 'var(--text-primary)',
              outline: 'none'
            }}
          />
        </div>

        {/* Severity Filter Chips */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              style={{
                background: filterSeverity === sev ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                border: `1px solid ${filterSeverity === sev ? '#38bdf8' : 'var(--border-dim)'}`,
                color: filterSeverity === sev ? '#38bdf8' : 'var(--text-secondary)',
                fontSize: '0.72rem',
                fontWeight: 600,
                padding: '3px 8px',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '10px' }}>
        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 10px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No security alerts match filters.
          </div>
        ) : (
          filtered.map(inc => {
            const isSelected = selectedIncident?.id === inc.id;
            const isEscalated = inc.status === 'ESCALATED_TO_HUMAN';

            return (
              <div
                key={inc.id}
                onClick={() => onSelectIncident(inc)}
                style={{
                  padding: '12px',
                  borderRadius: '8px',
                  background: isSelected ? 'rgba(56, 189, 248, 0.12)' : 'rgba(255, 255, 255, 0.02)',
                  border: `1px solid ${isSelected ? '#38bdf8' : (isEscalated ? 'rgba(244, 63, 94, 0.4)' : 'var(--border-dim)')}`,
                  marginBottom: '8px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                  <span style={{
                    padding: '2px 8px',
                    borderRadius: '4px',
                    fontSize: '0.7rem',
                    fontWeight: 700
                  }} className={getSeverityBadgeClass(inc.final_severity)}>
                    {inc.final_severity}
                  </span>

                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }} className="mono-font">
                    {new Date(inc.created_at).toLocaleTimeString()}
                  </span>
                </div>

                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  {inc.alert_type}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                  <span className="mono-font">
                    {inc.source_ip} &rarr; :{inc.destination_port}
                  </span>

                  {isEscalated ? (
                    <span style={{ color: '#f43f5e', fontWeight: 600, fontSize: '0.72rem' }}>
                      &bull; PENDING HITL
                    </span>
                  ) : (
                    <span style={{ color: '#10b981', fontSize: '0.72rem' }}>
                      &bull; {inc.status}
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
