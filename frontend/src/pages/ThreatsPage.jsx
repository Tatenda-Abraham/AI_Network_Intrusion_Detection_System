import React, { useState, useEffect } from 'react';
import { ShieldAlert, Filter, Search, Eye, AlertCircle, ArrowUpDown, ChevronLeft, ChevronRight, RefreshCw, X } from 'lucide-react';
import { api, maskMAC } from '../api/client';
import { useToast } from '../contexts/ToastContext';
import ThreatDetailModal from '../components/ThreatDetailModal';
import { SeverityBadge, Button, TextInput, SelectInput } from '../components/ui';

export default function ThreatsPage() {
  const [events, setEvents] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, page_size: 20, total_items: 0, total_pages: 1 });
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [recordedAttackTypes, setRecordedAttackTypes] = useState([]);
  const { error } = useToast();

  // Filter States
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [attackType, setAttackType] = useState('');
  const [detectionMethod, setDetectionMethod] = useState('');
  const [responseStatus, setResponseStatus] = useState('');
  const [sortBy, setSortBy] = useState('detection_time');
  const [ascending, setAscending] = useState(false);
  const [mode, setMode] = useState(() => localStorage.getItem('threats_mode') || 'all');

  useEffect(() => {
    localStorage.setItem('threats_mode', mode);
  }, [mode]);

  const fetchEvents = async (page = 1) => {
    setLoading(true);
    try {
      const params = {
        page,
        page_size: pagination.page_size,
        search,
        severity,
        attack_type: attackType,
        detection_method: detectionMethod,
        response_status: responseStatus,
        sort_by: sortBy,
        ascending: ascending ? 'true' : 'false',
        mode
      };
      const res = await api.events.list(params);
      setEvents(res.events || []);
      setPagination(res.pagination || { page: 1, total_pages: 1, total_items: 0 });
    } catch (err) {
      console.error('Error fetching events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents(1);
  }, [severity, attackType, detectionMethod, responseStatus, sortBy, ascending, mode]);

  // The filter only offers classifications the detectors actually produce.
  useEffect(() => {
    api.dashboard.getSummary()
      .then((summary) => setRecordedAttackTypes(Object.keys(summary?.charts?.attack_type_distribution || {})))
      .catch((err) => console.error('Error fetching recorded classifications:', err));
  }, []);

  const handleSearchSubmit = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    fetchEvents(1);
  };

  const handleOpenDetail = async (id) => {
    try {
      const res = await api.events.getDetail(id);
      setSelectedEvent(res.event || res);
    } catch (err) {
      error(`Error loading event detail: ${err.message}`);
    }
  };

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', minWidth: 0 }}>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '800', color: 'var(--cut-blue-dark)', margin: 0 }}>
          Detected Threats & Security Telemetry Log
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--cut-text-muted)', margin: '4px 0 0 0' }}>
          Real-time incident priority queue, heuristic evidence inspection, and analyst response status.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '18px 20px', marginBottom: '20px' }}>
        <form onSubmit={handleSearchSubmit}>
          <div className="filters-grid">
            <div className="span-2">
              <TextInput
                label="Search Incidents:"
                placeholder="Search by Event ID, IP, MAC, attack type..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <div>
              <SelectInput
                label="Traffic Source:"
                value={mode}
                placeholder=""
                onChange={(e) => setMode(e.target.value)}
                options={[
                  { value: 'all', label: 'All Traffic' },
                  { value: 'test', label: 'Campus Test Data' },
                  { value: 'live', label: 'Live Wireshark Capture' }
                ]}
              />
            </div>

            <div>
              <SelectInput
                label="Severity:"
                value={severity}
                placeholder=""
                onChange={(e) => setSeverity(e.target.value)}
                options={[
                  { value: '', label: 'All Severities' },
                  { value: 'Critical', label: 'Critical' },
                  { value: 'High', label: 'High' },
                  { value: 'Medium', label: 'Medium' },
                  { value: 'Low', label: 'Low' }
                ]}
              />
            </div>

            <div>
              <SelectInput
                label="Attack Type:"
                value={attackType}
                placeholder=""
                onChange={(e) => setAttackType(e.target.value)}
                options={[
                  { value: '', label: 'All Threat Types' },
                  ...recordedAttackTypes
                    .filter((t) => t !== 'Normal')
                    .sort()
                    .map((t) => ({ value: t, label: t })),
                  ...(recordedAttackTypes.includes('Normal') ? [{ value: 'Normal', label: 'Normal Traffic' }] : [])
                ]}
              />
            </div>

            <div>
              <SelectInput
                label="Status:"
                value={responseStatus}
                placeholder=""
                onChange={(e) => setResponseStatus(e.target.value)}
                options={[
                  { value: '', label: 'All Statuses' },
                  { value: 'Pending review', label: 'Pending review' },
                  { value: 'Acknowledged', label: 'Acknowledged' },
                  { value: 'Investigating', label: 'Investigating' },
                  { value: 'Resolved', label: 'Resolved' },
                  { value: 'False positive', label: 'False positive' }
                ]}
              />
            </div>

            <div className="stack-mobile">
              <Button type="submit" variant="primary" icon={Search}>
                Filter
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => {
                  setSearch('');
                  setSeverity('');
                  setAttackType('');
                  setDetectionMethod('');
                  setResponseStatus('');
                  setMode('all');
                  fetchEvents(1);
                }}
              >
                Reset
              </Button>
            </div>
          </div>
        </form>
      </div>

      {/* Events Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="custom-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#F8FAFC', borderBottom: '2px solid var(--cut-border)', textAlign: 'left', fontSize: '12px', color: 'var(--cut-text-muted)' }}>
                <th
                  onClick={() => setAscending(!ascending)}
                  style={{ cursor: 'pointer', padding: '12px 14px', whiteSpace: 'nowrap' }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    Event ID <ArrowUpDown size={12} />
                  </span>
                </th>
                <th style={{ padding: '12px 14px' }}>Source Node</th>
                <th style={{ padding: '12px 14px' }}>Destination Node</th>
                <th style={{ padding: '12px 14px' }}>Threat Classification</th>
                <th style={{ padding: '12px 14px' }}>Severity</th>
                <th style={{ padding: '12px 14px' }}>Method</th>
                <th style={{ padding: '12px 14px' }}>Detection Time</th>
                <th style={{ padding: '12px 14px' }}>Status</th>
                <th style={{ padding: '12px 14px', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '36px', color: 'var(--cut-text-muted)' }}>
                    Querying security database telemetry...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '36px', color: 'var(--cut-text-muted)' }}>
                    No security events match the current filter criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => {
                  const timeStr = ev.detection_time ? new Date(ev.detection_time).toLocaleTimeString() : 'N/A';
                  return (
                    <tr key={ev.id} style={{ borderBottom: '1px solid var(--cut-border)', fontSize: '13px' }}>
                      <td style={{ padding: '12px 14px', fontWeight: '700', fontFamily: 'monospace', color: 'var(--cut-blue-dark)' }}>
                        {ev.event_id || `EVT-${ev.id}`}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'monospace' }}>
                        {ev.source_ip || maskMAC(ev.source_mac) || '—'}
                      </td>
                      <td style={{ padding: '12px 14px', fontFamily: 'monospace' }}>
                        {ev.destination_ip || maskMAC(ev.destination_mac) || '—'}
                      </td>
                      <td style={{ padding: '12px 14px', fontWeight: '600' }}>
                        {ev.attack_type}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <SeverityBadge severity={ev.severity} />
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="badge badge-info" style={{ fontSize: '11px' }}>
                          {ev.detection_method || 'Rule'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', fontSize: '12px', color: 'var(--cut-text-muted)' }}>
                        {timeStr}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span style={{ fontSize: '12px', fontWeight: '500', color: ev.response_status === 'Resolved' ? '#16A34A' : 'var(--cut-text-main)' }}>
                          {ev.response_status || 'Pending review'}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', textAlign: 'center' }}>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleOpenDetail(ev.id)}
                          icon={Eye}
                        >
                          View
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderTop: '1px solid var(--cut-border)', background: '#FAFAFA', flexWrap: 'wrap', gap: '10px' }}>
          <span style={{ fontSize: '13px', color: 'var(--cut-text-muted)' }}>
            Showing page {pagination.page} of {pagination.total_pages || 1} ({pagination.total_items || 0} total records)
          </span>

          <div className="stack-mobile">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => fetchEvents(pagination.page - 1)}
              disabled={pagination.page <= 1 || loading}
              icon={ChevronLeft}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => fetchEvents(pagination.page + 1)}
              disabled={pagination.page >= pagination.total_pages || loading}
            >
              <span>Next</span>
              <ChevronRight size={14} style={{ marginLeft: '4px' }} />
            </Button>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedEvent && (
        <ThreatDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onUpdated={() => {
            fetchEvents(pagination.page);
            setSelectedEvent(null);
          }}
        />
      )}
    </div>
  );
}
