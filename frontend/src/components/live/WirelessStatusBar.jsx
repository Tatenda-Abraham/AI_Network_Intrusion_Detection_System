import React from 'react';
import { Radio, Activity, Layers, AlertTriangle, Gauge, Database, RefreshCw, Cpu } from 'lucide-react';
import Button from '../ui/Button';

const STATE_STYLES = {
  CAPTURING: { bg: '#DCFCE7', text: '#15803D', border: '#86EFAC' },
  RESTARTING: { bg: '#FEF3C7', text: '#B45309', border: '#FDE68A' },
  STOPPED: { bg: '#F1F5F9', text: '#64748B', border: '#CBD5E1' }
};

function Item({ icon, label, value, color }) {
  return (
    <div className="status-item">
      {icon}
      <span>
        {label}: <b style={{ color: color || '#1E293B' }}>{value}</b>
      </span>
    </div>
  );
}

export default function WirelessStatusBar({ status, countdown, onRefresh, onStart, onStop, busy }) {
  const state = status?.capture_state || 'STOPPED';
  const sc = STATE_STYLES[state] || STATE_STYLES.STOPPED;
  const capturing = state === 'CAPTURING';

  return (
    <div className="wireless-status-bar">
      <span className="state-pill" style={{ background: sc.bg, color: sc.text, border: `1px solid ${sc.border}` }}>
        <span className={`dot ${capturing ? 'on' : 'idle'}`} />
        {state}
      </span>

      <Item icon={<Radio size={15} color="#0288D1" />} label="Adapter" value={status?.adapter || 'selecting'} color="#0288D1" />
      <Item icon={<Activity size={15} color="#16A34A" />} label="Rate" value={`${status?.packets_sec || 0} pkts/s`} color="#16A34A" />
      <Item icon={<Layers size={15} color="#0288D1" />} label="Packets" value={(status?.total_packets || 0).toLocaleString()} />
      <Item icon={<Cpu size={15} color="#7C3AED" />} label="Flows" value={(status?.total_flows || 0).toLocaleString()} color="#7C3AED" />
      <Item icon={<Database size={15} color="#0D47A1" />} label="Stored" value={(status?.total_events || 0).toLocaleString()} color="#0D47A1" />
      <Item
        icon={<AlertTriangle size={15} color="#DC2626" />}
        label="Alerts"
        value={(status?.total_alerts || 0).toLocaleString()}
        color="#DC2626"
      />
      <Item
        icon={<Gauge size={15} color="#B78103" />}
        label="Window"
        value={`${status?.last_window_latency_ms ?? 0} ms / ${status?.window_seconds || 10} s`}
        color="#B78103"
      />

      <div className="status-actions">
        {capturing ? (
          <Button variant="danger" size="sm" onClick={onStop} loading={busy}>Pause Monitoring</Button>
        ) : (
          <Button variant="primary" size="sm" onClick={onStart} loading={busy}>Start Monitoring</Button>
        )}
        <Button variant="secondary" size="sm" onClick={onRefresh} icon={RefreshCw}>
          Refresh ({countdown}s)
        </Button>
      </div>
    </div>
  );
}
