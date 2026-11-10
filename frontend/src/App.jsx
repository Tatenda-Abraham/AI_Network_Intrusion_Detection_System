import React, { useState, useEffect, useCallback } from 'react';
import { ArrowLeft } from 'lucide-react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import LiveMonitorPage from './pages/LiveMonitorPage';
import ThreatsPage from './pages/ThreatsPage';
import AnalyticsPage from './pages/AnalyticsPage';
import ReportsPage from './pages/ReportsPage';
import UserManagementPage from './pages/UserManagementPage';
import AuditLogsPage from './pages/AuditLogsPage';
import { ToastProvider } from './contexts/ToastContext';
import { ToastContainer } from './components/Toast';
import { useToast } from './contexts/ToastContext';

import { getAuthToken, getCurrentUser, api, setAuthToken, setCurrentUser } from './api/client';

function AppContent() {
  const [user, setInternalUser] = useState(getCurrentUser());
  const [token, setInternalToken] = useState(getAuthToken());
  const [activeTab, setActiveTab] = useState('dashboard');
  const [healthStatus, setHealthStatus] = useState(null);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { toasts, removeToast, warning, info } = useToast();

  const handleLogout = useCallback(async (message = "Logged out successfully") => {
    try {
      await api.auth.logout();
    } catch (e) {}
    setAuthToken(null);
    setCurrentUser(null);
    setInternalUser(null);
    setInternalToken(null);
    info(message);
  }, [info]);

  // The console is a single-page kiosk: pages are switched from the sidebar, never
  // from the URL. Browser Back/Forward must therefore neither leave the system nor
  // walk between pages, so every history step is re-anchored onto the running app.
  useEffect(() => {
    const anchor = () => window.history.pushState({ ainids: 'anchored' }, '', window.location.href);
    anchor();
    window.addEventListener('popstate', anchor);
    return () => window.removeEventListener('popstate', anchor);
  }, []);

  useEffect(() => {
    if (!token) return undefined;

    api.system.getHealth()
      .then(setHealthStatus)
      .catch(() => setHealthStatus({ status: 'reconnecting', database: 'unknown' }));

    // Keep the analyst signed in without interrupting the live view.
    const keepAlive = setInterval(() => {
      api.auth.refresh().catch(() => {});
    }, 10 * 60 * 1000);

    const healthPoll = setInterval(() => {
      api.system.getHealth()
        .then(setHealthStatus)
        .catch(() => setHealthStatus({ status: 'reconnecting', database: 'unknown' }));
    }, 30 * 1000);

    return () => {
      clearInterval(keepAlive);
      clearInterval(healthPoll);
    };
  }, [token]);

  // The mobile navigation drawer is pinned under the header, so keep the
  // header height in sync with whatever the wrapped brand row renders.
  useEffect(() => {
    const header = document.querySelector('.cut-header');
    if (!header) return undefined;

    const applyHeight = () => {
      document.documentElement.style.setProperty('--header-h', `${Math.round(header.offsetHeight)}px`);
    };
    applyHeight();

    const observer = new ResizeObserver(applyHeight);
    observer.observe(header);
    return () => observer.disconnect();
  }, [user, token]);

  useEffect(() => {
    if (!isSidebarOpen) return undefined;
    const onKeyDown = (e) => {
      if (e.key === 'Escape') setIsSidebarOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    document.body.classList.add('drawer-open');
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.classList.remove('drawer-open');
    };
  }, [isSidebarOpen]);

  const handleLoginSuccess = (userData) => {
    setInternalUser(userData);
    setInternalToken(getAuthToken());
    setActiveTab('dashboard');
  };

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard': return <DashboardPage setActiveTab={setActiveTab} />;
      case 'live-monitor': return <LiveMonitorPage />;
      case 'threats': return <ThreatsPage />;
      case 'analytics': return <AnalyticsPage />;
      case 'reports': return <ReportsPage />;
      case 'users': return <UserManagementPage />;
      case 'audit-logs': return <AuditLogsPage />;
      default: return <DashboardPage setActiveTab={setActiveTab} />;
    }
  };

  if (!token || !user) {
    return (
      <>
        <LoginPage onLoginSuccess={handleLoginSuccess} />
        <ToastContainer toasts={toasts} removeToast={removeToast} />
      </>
    );
  }

  return (
    <div className="app-container">
      <Header 
        onLogout={() => handleLogout()} 
        healthStatus={healthStatus} 
        onMenuClick={() => setIsSidebarOpen(!isSidebarOpen)}
      />
      
      <div className="main-body">
        <div className={`sidebar-shell ${isSidebarOpen ? 'open' : ''}`}>
          <Sidebar 
            activeTab={activeTab} 
            setActiveTab={(tab) => {
              setActiveTab(tab);
              setIsSidebarOpen(false);
            }} 
          />
        </div>
        
        {isSidebarOpen && (
          <div 
            className="modal-overlay" 
            style={{ zIndex: 85, background: 'rgba(0,0,0,0.3)' }} 
            onClick={() => setIsSidebarOpen(false)}
          />
        )}

        <main className="content-area">
          {activeTab !== 'dashboard' && (
            <button
              type="button"
              className="btn-secondary back-to-dashboard"
              onClick={() => setActiveTab('dashboard')}
            >
              <ArrowLeft size={15} />
              <span>Back to Dashboard</span>
            </button>
          )}
          {renderActivePage()}
        </main>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
}
