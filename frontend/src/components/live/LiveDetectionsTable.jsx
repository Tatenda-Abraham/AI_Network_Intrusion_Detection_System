import React from 'react';
import { ShieldAlert } from 'lucide-react';
import Button from '../ui/Button';

function time(value) {
  if (!value) return '-';
  return new Date(value).toLocaleTimeString();
}

export default function LiveDetectionsTable({ detections, flaggedOnly, onToggleFlagged }) {
  return (
    <div className="card panel-tall" style={{ display: 'flex', flexDirection: 'column' }}>
      <div className="card-header">
        <h3>Live Flow Classification</h3>
        <div className="header-tools">
          <span className="count-pill">{detections.length} latest flows</span>
          <Button
            variant={flaggedOnly ? 'primary' : 'secondary'}
            size="sm"
            onClick={onToggleFlagged}
            icon={ShieldAlert}
          >
            {flaggedOnly ? 'Flagged Only' : 'All Flows'}
          </Button>
        </div>
      </div>

      <div style={{ flex: 1, overflowX: 'auto' }}>
        <table className="cut-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Flow</th>
              <th>Protocol</th>
              <th>Packets</th>
              <th>Classification</th>
              <th>Threat</th>
              <th>Severity</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {detections.length === 0 ? (
              <tr>
                <td colSpan="8" className="table-note">
                  The monitor is dissecting traffic; classified flows land here on the next capture window.
                </td>
              </tr>
            ) : detections.map((d) => {
              const flagged = d.ml_class !== 'Normal';
              return (
                <tr key={d.event_id} className={flagged ? 'row-flagged' : undefined}>
                  <td>{time(d.detection_time)}</td>
                  <td className="mono">
                    {d.source_ip}:{d.source_port || 0}
                    <span className="arrow">→</span>
                    {d.destination_ip}:{d.destination_port || 0}
                  </td>
                  <td>{d.protocol}</td>
                  <td>{d.packets ?? '-'}</td>
                  <td>
                    <span className={`class-pill ${flagged ? 'flagged' : 'normal'}`}>{d.ml_class}</span>
                  </td>
                  <td>{d.attack_type}</td>
                  <td><span className={`badge badge-${String(d.severity || 'low').toLowerCase()}`}>{d.severity}</span></td>
                  <td>{((d.confidence_score || 0) * 100).toFixed(1)}%</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
