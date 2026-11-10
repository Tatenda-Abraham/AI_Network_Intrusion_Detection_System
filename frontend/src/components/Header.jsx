import React from 'react';
import { ShieldCheck, LogOut, User as UserIcon, Activity, Menu } from 'lucide-react';
import { getCurrentUser, setAuthToken, setCurrentUser } from '../api/client';

export default function Header({ onLogout, healthStatus, onMenuClick }) {
  const user = getCurrentUser();

  return (
    <header className="cut-header">
      <div className="cut-header-content">
        <div className="cut-brand-wrapper">
          <button 
            className="btn-icon mobile-only" 
            onClick={onMenuClick}
            style={{ marginRight: '10px', color: 'white' }}
          >
            <Menu size={24} />
          </button>
          
          <img src="/cut-logo.png" alt="CUT Logo" className="cut-logo" />

          <div className="cut-titles">
            <h1>CHINHOYI UNIVERSITY OF TECHNOLOGY</h1>
            <p>AI-Based Network Intrusion Detection System</p>
          </div>
        </div>

        <div className="cut-header-right">
          {healthStatus && (
            <div className="cut-user-pill desktop-only">
              <Activity size={14} color={healthStatus.status === 'healthy' ? '#69F0AE' : '#FFAB91'} />
              <span style={{ fontSize: '12px' }}>
                {healthStatus.status === 'healthy' ? 'System Online' : 'Reconnecting'}
              </span>
            </div>
          )}

          {user && (
            <div className="cut-user-pill">
              <UserIcon size={14} color="#FFC72C" />
              <span className="desktop-only">{user.username}</span>
              <span className="role-badge">{user.role}</span>
            </div>
          )}

          <button type="button" onClick={onLogout} className="btn-icon" title="Sign out" style={{ color: '#FFCDD2' }}>
            <LogOut size={20} />
          </button>
        </div>
      </div>
    </header>
  );
}
