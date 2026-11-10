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
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { TrendingUp, AlertTriangle, CheckCircle2, Cpu } from 'lucide-react';
import { api } from '../api/client';
import KpiCard from '../components/KpiCard';
import { SEVERITY_CHART_COLORS } from '../components/ui/SeverityBadge';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Title, Tooltip, Legend, Filler
);

export default function AnalyticsPage() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.dashboard.getSummary()
      .then(setSummary)
      .catch((err) => console.error('Error loading analytics:', err))
      .finally(() => setLoading(false));
  }, []);

  const kpis = summary?.kpis || {};
  const charts = summary?.charts || {};
  const model = summary?.model || {};
  const capture = summary?.capture || {};

  const accuracy = model.accuracy ? model.accuracy * 100 : null;
  const fpr = model.false_positive_rate ? model.false_positive_rate * 100 : null;
  const split = model.validation_split || null;
  const pct = (ratio) => (ratio != null ? `${Math.round(ratio * 100)}%` : '');

  const timeline = charts.timeline || {};
  const trendData = {
    labels: timeline.labels || [],
    datasets: [
      {
        label: 'Flagged Flows',
        data: timeline.attacks || [],
        borderColor: '#D4AF37',
        backgroundColor: 'rgba(212, 175, 55, 0.15)',
        tension: 0.35,
        fill: true
      },
      {
        label: 'Normal Flows',
        data: timeline.normal || [],
        borderColor: '#0288D1',
        backgroundColor: 'rgba(2, 136, 209, 0.1)',
        tension: 0.35,
        fill: true
      }
    ]
  };

  // Ranked by the API: threats by how often they were caught, tiers by urgency.
  const flaggedCategories = charts.threat_type_distribution || charts.attack_type_distribution || {};
  const categoryData = {
    labels: Object.keys(flaggedCategories),
    datasets: [{
      label: 'Flagged Events',
      data: Object.values(flaggedCategories),
      backgroundColor: '#0288D1'
    }]
  };
  const categoryTotal = Object.values(flaggedCategories).reduce((sum, count) => sum + count, 0);

  const severityCounts = charts.threat_severity_distribution || charts.severity_distribution || {};
  const severityTiers = Object.keys(severityCounts);
  const severityData = {
    labels: severityTiers,
    datasets: [{
      label: 'Volume by Severity Tier',
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

  const topSources = charts.top_source_ips || [];
  const topSourceData = {
    labels: topSources.map((s) => s.ip),
    datasets: [{
      label: 'Events',
      data: topSources.map((s) => s.count),
      backgroundColor: '#7C3AED'
    }]
  };

  return (
    <div>
      <div className="page-head">
        <div>
          <h2>Traffic Analytics</h2>
          <p>
            Measured behaviour of the deployed system: {kpis.total_events || 0} flows in the
            events database, covering the campus test-data baseline and live Wireshark capture.
          </p>
        </div>
      </div>

      <div className="kpi-grid">
        <KpiCard
          title="Flagged Share"
          value={`${kpis.flagged_share_percent ?? 0}%`}
          subtext="Chapter 1 target: below 3%"
          icon={CheckCircle2}
          color="#16A34A"
          bg="#DCFCE7"
        />
        <KpiCard
          title="Flows Analysed"
          value={(kpis.campus_devices_monitored || 0).toLocaleString()}
          subtext={`${kpis.live_classified_flows || 0} more classified by the live monitor`}
          icon={TrendingUp}
          color="#0288D1"
          bg="#E1F5FE"
        />
        <KpiCard
          title="Active High Severity Alerts"
          value={(kpis.active_alerts || 0).toLocaleString()}
          subtext="Requiring analyst response"
          icon={AlertTriangle}
          color="#DC2626"
          bg="#FEE2E2"
        />
        <div className="card model-card">
          <div className="model-card-head">
            <Cpu size={18} color="#0D47A1" />
            <b>AI Model Performance</b>
          </div>
          <div className="model-metrics">
            <div>
              <span>Accuracy</span>
              <strong>{accuracy !== null ? `${accuracy.toFixed(2)}%` : 'Measuring'}</strong>
              <small>{accuracy !== null && accuracy >= 95 ? 'Target met (≥ 95%)' : 'Target: ≥ 95%'}</small>
            </div>
            <div>
              <span>False Positives</span>
              <strong>{fpr !== null ? `${fpr.toFixed(2)}%` : 'Measuring'}</strong>
              <small>{fpr !== null && fpr < 3 ? 'Target met (< 3%)' : 'Target: < 3%'}</small>
            </div>
            <div>
              <span>Flow Preprocessing</span>
              <strong>{capture.last_preprocessing_ms_per_flow != null ? `${capture.last_preprocessing_ms_per_flow.toFixed(2)} ms` : 'Measuring'}</strong>
              <small>Per flow &middot; Target: &lt; 50 ms</small>
            </div>
          </div>
          <p className="model-foot">
            {model.algorithm || 'Random Forest'} ({model.version || 'rf_v1'}) &middot; F1 {model.f1_score ? (model.f1_score * 100).toFixed(2) : '—'}%
            {split ? ` · ${pct(split.train_ratio)} train (${split.train_samples?.toLocaleString()}) / ${pct(split.test_ratio)} test (${split.test_samples?.toLocaleString()})` : ''}
          </p>
        </div>
      </div>

      <div className="split-2">
        <div className="chart-card">
          <div className="chart-header"><h3>Detection Trend</h3></div>
          <div className="chart-box">
            <Line data={trendData} options={{ responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-header"><h3>Incident Distribution by Category</h3></div>
          <p className="chart-note">
            {(categoryTotal).toLocaleString()} flagged flows, ranked by how often each threat was caught.
            The benign share sits on the Normal Baseline and Flagged Share cards of the dashboard.
          </p>
          <div className="chart-box">
            <Bar data={categoryData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }} />
          </div>
        </div>
      </div>

      <div className="split-2">
        <div className="chart-card">
          <div className="chart-header"><h3>Severity Tier Proportions</h3></div>
          <p className="chart-note">
            Flagged flows only · Critical and High block and push, Medium waits for the analyst, Low is register-only
          </p>
          <div className="chart-box-sm">
            <Bar data={severityData} options={{ responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }} />
          </div>
        </div>

        <div className="chart-card">
          <div className="chart-header"><h3>Test Data vs Live Capture</h3></div>
          <div className="chart-box-sm">
            <Doughnut data={sourceData} options={{ responsive: true, maintainAspectRatio: false }} />
          </div>
        </div>
      </div>

      <div className="chart-card">
        <div className="chart-header"><h3>Most Frequent Source Endpoints</h3></div>
        <div className="chart-box-sm">
          <Bar
            data={topSourceData}
            options={{
              responsive: true,
              maintainAspectRatio: false,
              indexAxis: 'y',
              plugins: { legend: { display: false } }
            }}
          />
        </div>
      </div>

      {loading && <p className="table-note">Loading analytics…</p>}
    </div>
  );
}
