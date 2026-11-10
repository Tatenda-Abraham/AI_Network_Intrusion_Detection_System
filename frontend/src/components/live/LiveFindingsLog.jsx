import React from 'react';
import { maskMAC } from '../../api/client';

export default function LiveFindingsLog({ findings }) {
  return (
    <div className="card panel-tall" style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <h3>Wireless Findings Log</h3>
        <span className="count-pill">{findings.length} in view</span>
      </div>
      <div style={{ flex: 1, overflowX: 'auto' }}>
        <table className="cut-table">
          <thead>
            <tr>
              <th>Finding</th>
              <th>Time</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Source / Target</th>
              <th>Confidence</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td colSpan="7" className="table-note">
                  No wireless anomalies in the captured windows.
                </td>
              </tr>
            ) : findings.map((f) => (
              <tr key={f.finding_id || f.id} className={f.severity === 'High' || f.severity === 'Critical' ? 'row-flagged' : undefined}>
                <td style={{ fontWeight: 700 }}>{f.finding_id}</td>
                <td>{f.found_at ? new Date(f.found_at).toLocaleTimeString() : '-'}</td>
                <td>{f.finding_type}</td>
                <td><span className={`badge badge-${String(f.severity || 'low').toLowerCase()}`}>{f.severity}</span></td>
                <td className="mono">
                  {maskMAC(f.source_mac) || '-'}
                  {f.target_mac && <><span className="arrow">→</span>{maskMAC(f.target_mac)}</>}
                </td>
                <td>{((f.confidence_score || 0) * 100).toFixed(0)}%</td>
                <td className="evidence-cell" title={f.evidence}>{f.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
