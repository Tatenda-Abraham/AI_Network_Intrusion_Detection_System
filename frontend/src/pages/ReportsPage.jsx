import React, { useState, useEffect } from 'react';
import { Download, Plus } from 'lucide-react';
import { api } from '../api/client';
import { useToast } from '../contexts/ToastContext';

const SEVERITY_TIERS = ['Critical', 'High', 'Medium', 'Low'];

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [recordedSeverities, setRecordedSeverities] = useState([]);
  const [title, setTitle] = useState('CUT AI-NIDS Comprehensive Incident Report');
  const [reportType, setReportType] = useState('General Incident');
  const [severity, setSeverity] = useState('');
  const [days, setDays] = useState(30);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [notice, setNotice] = useState('');
  const { success, error } = useToast();

  const fetchReports = async () => {
    try {
      const data = await api.reports.list();
      setReports(data.reports || []);
    } catch (err) {
      console.error('Error fetching reports:', err);
    }
  };

  useEffect(() => {
    fetchReports();
    api.dashboard.getSummary()
      .then((summary) => setRecordedSeverities(Object.keys(summary?.charts?.severity_distribution || {})))
      .catch((err) => console.error('Error fetching recorded severities:', err));
  }, []);

  // Only offer the tiers the detectors actually store, so every scope choice yields a report
  const severityOptions = [
    { value: '', label: 'All Severities' },
    ...SEVERITY_TIERS.filter((tier) => recordedSeverities.includes(tier)).map((tier) => ({ value: tier, label: tier }))
  ];

  const handleGenerate = async (e) => {
    e.preventDefault();
    setGenerating(true);
    setNotice('');
    try {
      const res = await api.reports.generate(title, reportType, severity, days);
      setNotice(`Report '${title}' compiled with ${res.event_count} incident events.`);
      await fetchReports();
      success('Report generated and saved successfully');
    } catch (err) {
      error(`Error generating report: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (format) => {
    setDownloading(true);
    try {
      await api.reports.export(format, severity, days, title, reportType);
      success(`Report exported as ${format.toUpperCase()}`);
    } catch (err) {
      error(`Error exporting report: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '800', color: 'var(--cut-blue-dark)' }}>
          Security Telemetry & Formal Incident Reports
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--cut-text-muted)' }}>
          Generate institutional compliance reports and download structured CSV records or CUT-branded PDF dossiers.
        </p>
      </div>

      {notice && (
        <div style={{ background: '#E0F2FE', color: '#0369A1', padding: '12px', borderRadius: '8px', marginBottom: '20px', fontSize: '13px' }}>
          {notice}
        </div>
      )}

      {/* Report Generator Controls */}
      <div style={{ background: 'var(--cut-white)', padding: '24px', borderRadius: 'var(--radius-md)', border: '1px solid var(--cut-border)', marginBottom: '24px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--cut-blue-dark)', marginBottom: '16px' }}>
          Compile New Incident Report
        </h3>
        <form onSubmit={handleGenerate} className="form-grid-4">
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>Report Title:</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="form-input"
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>Report Scope:</label>
            <select value={reportType} onChange={(e) => setReportType(e.target.value)} className="form-select">
              <option value="General Incident">All Detected Traffic</option>
              <option value="Critical Threats Only">Critical & High Threats</option>
              <option value="Live Capture Audit">Live Wireshark Capture</option>
              <option value="Test Data Audit">Campus Test Data Baseline</option>
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>Severity Filter:</label>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="form-select">
              {severityOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>Lookback Range:</label>
            <select value={days} onChange={(e) => setDays(parseInt(e.target.value))} className="form-select">
              <option value="1">Last 24 Hours</option>
              <option value="7">Last 7 Days</option>
              <option value="30">Last 30 Days</option>
              <option value="90">Last 90 Days</option>
            </select>
          </div>

          <div className="span-full stack-mobile" style={{ marginTop: '8px' }}>
            <button type="submit" disabled={generating} className="btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Plus size={16} />
              <span>{generating ? 'Compiling Report...' : 'Save & Record Report'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleDownload('pdf')}
              disabled={downloading}
              className="mode-action-btn btn-gold"
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Download size={14} />
              <span>{downloading ? 'Exporting...' : 'Export Branded PDF'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleDownload('csv')}
              disabled={downloading}
              className="btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Download size={14} />
              <span>{downloading ? 'Exporting...' : 'Export CSV'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Reports History Table */}
      <div className="table-card">
        <div className="table-header-bar">
          <h3>Generated Institutional Reports Archive</h3>
        </div>
        <table className="custom-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Report Title</th>
              <th>Type</th>
              <th>Generated By</th>
              <th>Total Incidents</th>
              <th>Date Created</th>
              <th>Download</th>
            </tr>
          </thead>
          <tbody>
            {reports.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '24px', color: '#8CA0B3' }}>
                  No reports archived yet. Compile one with the form above and it is stored here.
                </td>
              </tr>
            ) : (
              reports.map((rep) => (
                <tr key={rep.id}>
                  <td>#{rep.id}</td>
                  <td style={{ fontWeight: '700', color: 'var(--cut-blue-dark)' }}>{rep.title}</td>
                  <td>{rep.report_type}</td>
                  <td>{rep.generated_by}</td>
                  <td style={{ fontWeight: '600' }}>{rep.total_events}</td>
                  <td style={{ fontSize: '12px' }}>{new Date(rep.created_at).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        type="button"
                        className="btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '11px', minHeight: '32px' }}
                        onClick={() => api.reports.downloadSaved(rep.id, 'pdf').then(() => success('PDF downloaded')).catch((err) => error(err.message))}
                      >
                        PDF
                      </button>
                      <button
                        type="button"
                        className="btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '11px', minHeight: '32px' }}
                        onClick={() => api.reports.downloadSaved(rep.id, 'csv').then(() => success('CSV downloaded')).catch((err) => error(err.message))}
                      >
                        CSV
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
