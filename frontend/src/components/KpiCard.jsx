import React from 'react';

export default function KpiCard({ title, value, subtext, icon: Icon, color = '#0288D1', bg = '#E1F5FE' }) {
  return (
    <div className="kpi-card">
      <div className="kpi-info">
        <h3>{title}</h3>
        <div className="kpi-value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
        {subtext && <div className="kpi-sub">{subtext}</div>}
      </div>
      <div className="kpi-icon-box" style={{ background: bg }}>
        <Icon size={22} color={color} />
      </div>
    </div>
  );
}
