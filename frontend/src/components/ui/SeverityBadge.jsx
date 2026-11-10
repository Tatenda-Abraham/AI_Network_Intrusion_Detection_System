import React from 'react';

// Chart fills for the four documented response tiers, so a bar and its badge always match.
export const SEVERITY_CHART_COLORS = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#FBBF24',
  Low: '#38BDF8'
};

export default function SeverityBadge({ severity, style = {} }) {
  const sev = (severity || 'Investigate').trim();

  // Style mapping: Critical red, High orange, Medium gold, Low light blue, Investigate gray outline
  const badgeStyles = {
    'Critical': {
      background: '#FEF2F2',
      color: '#DC2626',
      border: '1px solid #FCA5A5',
      fontWeight: '700'
    },
    'High': {
      background: '#FFF7ED',
      color: '#EA580C',
      border: '1px solid #FDBA74',
      fontWeight: '700'
    },
    'Medium': {
      background: '#FFFBEB',
      color: '#B45309',
      border: '1px solid #FCD34D',
      fontWeight: '600'
    },
    'Low': {
      background: '#F0F9FF',
      color: '#0284C7',
      border: '1px solid #BAE6FD',
      fontWeight: '600'
    },
    'Investigate': {
      background: '#FFFFFF',
      color: '#64748B',
      border: '1px dashed #94A3B8',
      fontWeight: '500'
    }
  };

  const selected = badgeStyles[sev] || badgeStyles['Investigate'];

  return (
    <span
      className={`ui-badge ui-badge-${sev.toLowerCase().replace(/\s+/g, '-')}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 9px',
        borderRadius: '12px',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.3px',
        whiteSpace: 'nowrap',
        ...selected,
        ...style
      }}
    >
      {sev}
    </span>
  );
}
