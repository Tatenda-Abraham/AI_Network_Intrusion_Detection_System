/**
 * AI-NIDS Unified API Client
 * Chinhoyi University of Technology - Group 5
 * Handles JWT bearer token lifecycle, HTTP request execution,
 * blob exports, 401 session expiry redirects, and unified error handling.
 */

const API_BASE = '/api';

export function getAuthToken() {
  return localStorage.getItem('ai_nids_token');
}

export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('ai_nids_token', token);
  } else {
    localStorage.removeItem('ai_nids_token');
  }
}

export function getCurrentUser() {
  const userStr = localStorage.getItem('ai_nids_user');
  try {
    return userStr ? JSON.parse(userStr) : null;
  } catch (e) {
    return null;
  }
}

export function setCurrentUser(user) {
  if (user) {
    localStorage.setItem('ai_nids_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('ai_nids_user');
  }
}

export function hasPermission(permission) {
  const user = getCurrentUser();
  if (!user || !user.role) return false;
  if (user.role === 'Administrator') return true;

  const analystPerms = [
    'dashboard:view', 'findings:view', 'findings:edit', 'alerts:view',
    'threat_details:view', 'analytics:view', 'reports:view',
    'reports:create', 'capture:start', 'capture:stop', 'login_history:view_own'
  ];
  return analystPerms.includes(permission);
}

export function maskMAC(mac) {
  if (!mac) return mac;
  const user = getCurrentUser();
  if (user && user.role === 'Administrator') return mac;

  const clean = String(mac).trim().replace(/-/g, ':');
  const parts = clean.split(':');
  if (parts.length === 6) {
    return `${parts[0]}:${parts[1]}:${parts[2]}:xx:xx:xx`;
  }
  return mac;
}

export async function request(endpoint, options = {}) {
  const token = getAuthToken();
  const headers = {
    ...options.headers
  };

  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers
    });

    if (res.status === 401 && !endpoint.includes('/auth/login')) {
      if (endpoint !== '/auth/refresh') {
        try {
          const refreshRes = await fetch(`${API_BASE}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });

          if (refreshRes.ok) {
            const data = await refreshRes.json();
            setAuthToken(data.access_token);
            headers['Authorization'] = `Bearer ${data.access_token}`;
            return request(endpoint, { ...options, headers });
          }
        } catch (refreshErr) {
          console.error("Token refresh failed:", refreshErr);
        }
      }

      setAuthToken(null);
      setCurrentUser(null);
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login?expired=true';
      }
      throw new Error("Session expired. Please log in again.");
    }

    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.message || "Access Forbidden: Insufficient role permissions.");
    }

    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || `Request failed with status ${res.status}`);
      }
      return data;
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `Request failed with status ${res.status}`);
    }

    return res;
  } catch (error) {
    console.error(`[API ERROR] ${endpoint}:`, error);
    throw error;
  }
}

export async function downloadFile(endpoint, filename) {
  const token = getAuthToken();
  const headers = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'GET',
    headers
  });

  if (res.status === 401) {
    setAuthToken(null);
    setCurrentUser(null);
    window.location.href = '/login?expired=true';
    throw new Error("Session expired. Please log in again.");
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "Download error");
    throw new Error(text || `Failed to download file (${res.status})`);
  }

  const blob = await res.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(downloadUrl);
}

export const api = {
  auth: {
    login: (username, password, signInAs) =>
      request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password, sign_in_as: signInAs })
      }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    refresh: () => request('/auth/refresh', { method: 'POST' }),
    me: () => request('/auth/me'),
    getLoginSummary: () => request('/auth/login-history/summary'),
    getLoginHistory: (admin = false, params = {}) => {
      const query = new URLSearchParams(params).toString();
      const path = admin ? '/auth/login-history/admin' : '/auth/login-history/me';
      return request(`${path}?${query}`);
    },
    exportLoginHistory: () => downloadFile('/auth/login-history/export', `CUT_Login_History_${new Date().toISOString().split('T')[0]}.csv`),
    getSessions: () => request('/auth/sessions'),
    revokeSession: (sessionId) => request(`/auth/sessions/${sessionId}/revoke`, { method: 'POST' }),
    revokeAllSessions: () => request('/auth/sessions/revoke-all', { method: 'POST' })
  },

  dashboard: {
    getSummary: () => request('/dashboard/summary')
  },

  capture: {
    getInterfaces: () => request('/capture/interfaces'),
    // Starting without an interface lets the backend pick the active adapter itself.
    start: (options = {}) => request('/capture/start', {
      method: 'POST',
      body: JSON.stringify(options)
    }),
    stop: () => request('/capture/stop', { method: 'POST' }),
    getStatus: () => request('/capture/status')
  },

  live: {
    getStatus: () => request('/live/status'),
    getDetections: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/live/detections?${query}`);
    },
    getPackets: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/live/packets?${query}`);
    },
    getConversations: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/live/conversations?${query}`);
    },
    getFindings: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/live/findings?${query}`);
    },
    getTimeline: () => request('/live/timeline'),
    getWindows: () => request('/live/windows')
  },

  events: {
    list: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/events?${query}`);
    },
    getDetail: (id) => request(`/events/${id}`),
    updateStatus: (id, status, notes = '') => request(`/events/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes })
    }),
    addNote: (id, note) => request(`/events/${id}/note`, {
      method: 'POST',
      body: JSON.stringify({ note })
    }),
    delete: (id) => request(`/events/${id}`, {
      method: 'DELETE'
    }),
    getAlerts: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/events/alerts?${query}`);
    }
  },

  reports: {
    list: () => request('/reports'),
    generate: (title, reportType, severity, days) => request('/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ title, report_type: reportType, severity, days })
    }),
    export: (format, severity, days, title, reportType) => {
      const params = new URLSearchParams({
        format,
        severity: severity || '',
        days: (days || 30).toString(),
        title: title || '',
        report_type: reportType || 'General Incident'
      });
      const ext = format === 'pdf' ? 'pdf' : 'csv';
      const dateStr = new Date().toISOString().split('T')[0];
      return downloadFile(`/reports/export?${params.toString()}`, `CUT_AINIDS_Report_${dateStr}.${ext}`);
    },
    downloadSaved: (reportId, format = 'pdf') => {
      const dateStr = new Date().toISOString().split('T')[0];
      return downloadFile(`/reports/${reportId}/download?format=${format}`, `CUT_AINIDS_Report_${reportId}_${dateStr}.${format}`);
    }
  },

  users: {
    list: () => request('/users'),
    create: (userData) => request('/users', {
      method: 'POST',
      body: JSON.stringify(userData)
    }),
    update: (id, userData) => request(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(userData)
    }),
    delete: (id) => request(`/users/${id}`, {
      method: 'DELETE'
    })
  },

  system: {
    getHealth: () => request('/health'),
    getAuditLogs: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/audit-logs?${query}`);
    }
  }
};
