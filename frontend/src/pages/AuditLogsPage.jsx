import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  History,
  UserX,
  RefreshCw,
  LogOut
} from 'lucide-react';
import { api, getCurrentUser } from '../api/client';
import { useToast } from '../contexts/ToastContext';

export default function AuditLogsPage() {
  const user = getCurrentUser();
  const isAdmin = user?.role === 'Administrator';
  const [activeTab, setActiveTab] = useState(isAdmin ? 'audit' : 'login-history');
  const [auditLogs, setAuditLogs] = useState([]);
  const [loginHistory, setLoginHistory] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const { success, error } = useToast();

  const fetchAuditLogs = async () => {
    try {
      const res = await api.system.getAuditLogs({ action: actionFilter, limit: 200 });
      setAuditLogs(res.audit_logs || res.logs || []);
    } catch (err) {
      error(err.message || 'Failed to fetch audit logs');
      setAuditLogs([]);
    }
  };

  const fetchLoginHistory = async () => {
    try {
      const data = await api.auth.getLoginHistory(isAdmin);
      setLoginHistory(data.data || data.history || []);
    } catch (err) {
      error(err.message || 'Failed to fetch login history');
      setLoginHistory([]);
    }
  };

  const fetchSessions = async () => {
    try {
      const data = await api.auth.getSessions();
      setSessions(data.data || data.sessions || []);
    } catch (err) {
      error(err.message || 'Failed to fetch active sessions');
      setSessions([]);
    }
  };

  const handleRevokeSession = async (sessionId) => {
    if (!window.confirm('Are you sure you want to revoke this session?')) return;
    try {
      await api.auth.revokeSession(sessionId);
      success('Session revoked');
      fetchSessions();
    } catch (err) {
      error(err.message);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      if (activeTab === 'audit' && isAdmin) await fetchAuditLogs();
      else if (activeTab === 'login-history') await fetchLoginHistory();
      else if (activeTab === 'sessions' && isAdmin) await fetchSessions();
      if (!cancelled) setLoading(false);
    };
    load();
    return () => { cancelled = true; };
  }, [activeTab, actionFilter, isAdmin]);

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '800', color: 'var(--cut-blue-dark)' }}>
          Security Audit & Authentication Logs
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--cut-text-muted)' }}>
          Comprehensive oversight of system mutations, access events, and active user sessions.
        </p>
      </div>

      <div className="tab-bar" style={{ marginBottom: '20px', borderBottom: '1px solid var(--cut-border)', paddingBottom: '4px' }}>
        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('audit')}
            className={`cut-nav-item ${activeTab === 'audit' ? 'active' : ''}`}
            style={{ border: 'none', background: 'none' }}
          >
            <ShieldCheck size={18} /> System Audit Trail
          </button>
        )}
        <button
          type="button"
          onClick={() => setActiveTab('login-history')}
          className={`cut-nav-item ${activeTab === 'login-history' ? 'active' : ''}`}
          style={{ border: 'none', background: 'none' }}
        >
          <History size={18} /> Login History
        </button>
        {isAdmin && (
          <button
            type="button"
            onClick={() => setActiveTab('sessions')}
            className={`cut-nav-item ${activeTab === 'sessions' ? 'active' : ''}`}
            style={{ border: 'none', background: 'none' }}
          >
            <UserX size={18} /> Active Sessions
          </button>
        )}
      </div>

      {loading && (
        <div style={{ padding: '16px', color: 'var(--cut-text-muted)', fontSize: '13px' }}>
          Loading records...
        </div>
      )}

      {activeTab === 'login-history' && !loading && (
        <div className="table-card">
          <div className="table-header-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px' }}>
            <h3>{isAdmin ? 'Global Authentication Events' : 'My Login History'}</h3>
            <button type="button" onClick={fetchLoginHistory} className="btn-icon" title="Refresh">
              <RefreshCw size={14} />
            </button>
          </div>
          <div className="table-container">
            <table className="cut-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Username</th>
                  <th>Event Type</th>
                  <th>Status</th>
                  <th>IP Address</th>
                  <th>Role</th>
                </tr>
              </thead>
              <tbody>
                {loginHistory.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: '#8CA0B3' }}>
                      No login history records found.
                    </td>
                  </tr>
                ) : loginHistory.map((h) => (
                  <tr key={h.id || `${h.username}-${h.event_time}`}>
                    <td>{h.event_time ? new Date(h.event_time).toLocaleString() : '—'}</td>
                    <td style={{ fontWeight: '700' }}>{h.username}</td>
                    <td><span className="badge badge-low">{h.event_type}</span></td>
                    <td>
                      <span className={`badge ${h.success ? 'badge-low' : 'badge-critical'}`}>
                        {h.success ? 'SUCCESS' : 'FAILED'}
                      </span>
                      {!h.success && <div style={{ fontSize: '10px', color: '#EF4444' }}>{h.failure_reason}</div>}
                    </td>
                    <td style={{ fontFamily: 'monospace' }}>{h.ip_address}</td>
                    <td>{h.role || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'sessions' && isAdmin && !loading && (
        <div className="table-card">
          <div className="table-header-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px' }}>
            <h3>Active User Sessions</h3>
            <button type="button" onClick={fetchSessions} className="btn-icon" title="Refresh">
              <RefreshCw size={14} />
            </button>
          </div>
          <div className="table-container">
            <table className="cut-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>Started At</th>
                  <th>Last Activity</th>
                  <th>IP Address</th>
                  <th>Device</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: '#8CA0B3' }}>
                      No active sessions.
                    </td>
                  </tr>
                ) : sessions.map((s) => (
                  <tr key={s.session_id}>
                    <td style={{ fontWeight: '700' }}>{s.username}</td>
                    <td>{s.created_at ? new Date(s.created_at).toLocaleString() : '—'}</td>
                    <td>{s.last_activity ? new Date(s.last_activity).toLocaleString() : '—'}</td>
                    <td style={{ fontFamily: 'monospace' }}>{s.ip_address}</td>
                    <td style={{ fontSize: '11px', color: '#64748B' }}>{s.user_agent || '—'}</td>
                    <td>
                      <button
                        type="button"
                        onClick={() => handleRevokeSession(s.session_id)}
                        className="btn-icon"
                        style={{ color: '#EF4444' }}
                        title="Revoke Session"
                      >
                        <LogOut size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'audit' && isAdmin && !loading && (
        <div className="table-card">
          <div className="table-header-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', padding: '12px 16px', flexWrap: 'wrap' }}>
            <h3>System Mutation Audit</h3>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="form-select"
                style={{ width: 'min(220px, 100%)' }}
              >
                <option value="">All Actions</option>
                <option value="USER">User Management</option>
                <option value="CAPTURE">Capture Events</option>
                <option value="SESSION">Session Events</option>
                <option value="REPORT">Report Events</option>
                <option value="THRESHOLD">Policy Changes</option>
              </select>
              <button type="button" onClick={fetchAuditLogs} className="btn-icon" title="Refresh">
                <RefreshCw size={14} />
              </button>
            </div>
          </div>
          <div className="table-container">
            <table className="cut-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Details</th>
                  <th>Outcome</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: '#8CA0B3' }}>
                      No audit records match the current filter.
                    </td>
                  </tr>
                ) : auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{log.timestamp ? new Date(log.timestamp).toLocaleString() : '—'}</td>
                    <td style={{ fontWeight: '700' }}>{log.username}</td>
                    <td><span className="badge badge-low">{log.action}</span></td>
                    <td style={{ fontSize: '12px', maxWidth: '360px' }}>{log.details}</td>
                    <td>
                      <span className={`badge ${String(log.outcome).toLowerCase() === 'success' ? 'badge-low' : 'badge-critical'}`}>
                        {log.outcome || '—'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace' }}>{log.ip_address || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
