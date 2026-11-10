import React, { useState, useEffect } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line, Doughnut, Bar, Pie } from 'react-chartjs-2';
import {
  ShieldAlert,
  Activity,
  CheckCircle,
  AlertTriangle,
  Flame,
  Radio
} from 'lucide-react';
import KpiCard from '../components/KpiCard';
import { SEVERITY_CHART_COLORS } from '../components/ui/SeverityBadge';
import { api } from '../api/client';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Title, Tooltip, Legend, Filler
);

// Chapter 1 requires the dashboard to refresh at most every 5 seconds.
const REFRESH_MS = 5000;

export default function DashboardPage({ setActiveTab }) {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const data = await api.dashboard.getSummary();
        if (!cancelled) setSummary(data);
      } catch (err) {
        console.error('Error fetching dashboard summary:', err);
      }
    };

    load();
    const interval = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const kpis = summary?.kpis || {};
  const charts = summary?.charts || {};
  const capture = summary?.capture || {};
  const alerts = summary?.recent_alerts || [];

  const baselineStored = kpis.baseline_flows_stored || 0;
  const baselineFlaggedShare = baselineStored
    ? ((kpis.baseline_flagged_count || 0) / baselineStored * 100).toFixed(2)
    : '0.00';

  const timelineData = {
    labels: charts.timeline?.labels || [],
    datasets: [
      {
        label: 'Flagged Flows',
        data: charts.timeline?.attacks || [],
        borderColor: '#D4AF37',
        backgroundColor: 'rgba(212, 175, 55, 0.15)',
        tension: 0.35,
        fill: true,
        pointBackgroundColor: '#FFC72C'
      },
      {
        label: 'Normal Flows',
        data: charts.timeline?.normal || [],
        borderColor: '#0288D1',
        backgroundColor: 'rgba(2, 136, 209, 0.08)',
        tension: 0.35,
        fill: true,
        pointBackgroundColor: '#0288D1'
      }
    ]
  };

  // Ranked by the API: caught threats first, biggest category first, urgent tier first.
  const distribution = charts.threat_type_distribution || charts.attack_type_distribution || {};
  const attackDistData = {
    labels: Object.keys(distribution),
    datasets: [{
      data: Object.values(distribution),
      backgroundColor: ['#0288D1', '#F59E0B', '#EF4444', '#B91C1C', '#D97706', '#64748B', '#8B5CF6']
    }]
  };
  const flaggedTotal = Object.values(distribution).reduce((sum, count) => sum + count, 0);

  const severityCounts = charts.threat_severity_distribution || charts.severity_distribution || {};  const severityTiers = Object.keys(severityCounts);
  const severityData = {
    labels: severityTiers,
    datasets: [{
      label: 'Event Count',
      data: severityTiers.map((tier) => severityCounts[tier]),
      backgroundColor: severityTiers.map((tier) => SEVERITY_CHART_COLORS[tier] || '#94A3B8')
    }]
  };

  const sourceSplit = charts.source_split || {};
  const sourceData = {
    labels: Object.keys(sourceSplit),
    datasets: [{
      data: Object.values(sourceSplit),
      backgroundColor: ['#0288D1', '#10B981', '#64748B']
    }]
  };

  const captureRunning = capture.state === 'CAPTURING';

  return (
    <div className="dashboard-container">
      <div className="page-head">
        <div>
          <h2>Network Traffic Overview</h2>
          <p>
            One events database holding the campus test-data baseline and the flows classified
            live by the Wireshark monitor.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={() => setActiveTab && setActiveTab('live-monitor')}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
        >
          <Radio size={16} />
          Live Monitor
        </button>
      </div>

      <div className="cards-grid">
        <KpiCard
          title="Flows Analysed"
          value={(kpis.campus_devices_monitored || 0).toLocaleString()}
          subtext={`CUT devices monitored, 1 flow each | ${kpis.live_classified_flows || 0} classified by the live monitor`}
          icon={Activity}
          color="#0288D1"
          bg="#E1F5FE"
        />
        <KpiCard
          title="Normal Baseline"
          value={(kpis.baseline_normal_count || 0).toLocaleString()}
          subtext="Benign campus flows"
          icon={CheckCircle}
          color="#16A34A"
          bg="#DCFCE7"
        />
        <KpiCard
          title="Flagged Share"
          value={`${baselineFlaggedShare}%`}
          subtext={`${(kpis.baseline_flagged_count || 0).toLocaleString()} flagged · target below 3%`}
          icon={AlertTriangle}
          color="#D97706"
          bg="#FEF3C7"
        />
        <KpiCard
          title="Critical / High"
          value={(kpis.critical_high_count || 0).toLocaleString()}
          subtext="Urgent severity events"
          icon={Flame}
          color="#B91C1C"
          bg="#FEE2E2"
        />
        <KpiCard
          title="Active Alerts"
          value={(kpis.active_alerts || 0).toLocaleString()}
          subtext="Awaiting analyst response"
          icon={ShieldAlert}
          color="#DC2626"
          bg="#FEE2E2"
        />
      </div>

      <div className="card live-strip" style={{ marginBottom: '20px' }}>
        <div className="live-strip-item">
          <span className={`dot ${captureRunning ? 'on' : 'idle'}`} />
          <div>
            <b>{captureRunning ? 'Monitoring live' : 'Monitor idle'}</b>
            <small>{capture.adapter || 'Starting on the live monitor page'}</small>
          </div>
        </div>
        <div className="live-strip-item">
          <div>
            <b>{(capture.total_packets || 0).toLocaleString()}</b>
            <small>packets captured</small>
          </div>
        </div>
        <div className="live-strip-item">
          <div>
            <b>{(capture.total_flows || 0).toLocaleString()}</b>
            <small>live flows built</small>
          </div>
        </div>
        <div className="live-strip-item">
          <div>
            <b>{(kpis.live_classified_flows || 0).toLocaleString()}</b>
            <small>flows stored in database</small>
          </div>
        </div>
        <div className="live-strip-item">
          <div>
            <b>{capture.packets_per_second || 0}</b>
            <small>packets / second</small>
          </div>
        </div>
      </div>

      <div className="split-2">
        <div className="card chart-card">
          <h3>Detected Activity Over Time</h3>
          <div className="chart-box">
            <Line data={timelineData} options={{ responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>

        <div className="card chart-card">
          <h3>Classification Distribution</h3>
          <p className="chart-note">
            {(flaggedTotal).toLocaleString()} flagged flows of {(kpis.total_events || 0).toLocaleString()} stored
            {` (${kpis.flagged_share_percent || 0}%) · ranked by how often each threat was caught`}
          </p>
          <div className="chart-box">
            <Doughnut data={attackDistData} options={{ responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>
      </div>

      <div className="split-2">
        <div className="card chart-card">
          <h3>Severity Distribution</h3>
          <p className="chart-note">
            Flagged flows only · Critical and High block and push, Medium waits for the analyst, Low is register-only
          </p>
          <div className="chart-box-sm">
            <Bar
              data={severityData}
              options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }}
            />
          </div>
        </div>

        <div className="card chart-card">
          <h3>Traffic Source Split</h3>
          <div className="chart-box-sm">
            <Pie data={sourceData} options={{ responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Latest Alerts</h3>
          <span className="refresh-note">Auto-refreshed every 5 seconds</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="cut-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Threat</th>
                <th>Source</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="5" className="table-note">
                    No alerts raised yet. Live capture writes alerts here as they are classified.
                  </td>
                </tr>
              ) : alerts.map((a) => (
                <tr key={a.id}>
                  <td style={{ fontWeight: 700 }}>{a.alert_id || `AL-${a.id}`}</td>
                  <td><span className={`badge badge-${String(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                  <td>{a.event?.attack_type || a.title || 'Intrusion Attempt'}</td>
                  <td className="mono">{a.event?.source_ip || '-'}</td>
                  <td>{a.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
