import React from 'react';
import {
  LayoutDashboard,
  Radio,
  AlertTriangle,
  BarChart3,
  FileText,
  Users,
  ShieldCheck
} from 'lucide-react';
import { getCurrentUser } from '../api/client';

export default function Sidebar({ activeTab, setActiveTab }) {
  const user = getCurrentUser();
  const isAdmin = user?.role === 'Administrator';

  const navItems = [
    { id: 'dashboard', label: 'Main Dashboard', icon: LayoutDashboard },
    { id: 'live-monitor', label: 'Live Monitor (Wireshark)', icon: Radio },
    { id: 'threats', label: 'Detected Threats / Alerts', icon: AlertTriangle },
    { id: 'analytics', label: 'Analytics & Visualizations', icon: BarChart3 },
    { id: 'reports', label: 'Reports & Audit Export', icon: FileText },
    ...(isAdmin ? [
      { id: 'users', label: 'User Management', icon: Users },
      { id: 'audit-logs', label: 'Security Audit Logs', icon: ShieldCheck }
    ] : [])
  ];

  return (
    <aside className="cut-sidebar">
      <ul className="cut-nav-list">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <li
              key={item.id}
              role="button"
              tabIndex={0}
              className={`cut-nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setActiveTab(item.id);
                }
              }}
            >
              <Icon size={18} color={isActive ? '#0D47A1' : '#5A738E'} />
              <span>{item.label}</span>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
