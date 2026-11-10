import React from 'react';
import { Check } from 'lucide-react';

export default function Checkbox({
  checked,
  onChange,
  label,
  subtext,
  disabled = false,
  error,
  id,
  name,
  style = {}
}) {
  const checkId = id || name || `checkbox-${Math.random().toString(36).substr(2, 9)}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', ...style }}>
      <label
        htmlFor={checkId}
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          cursor: disabled ? 'not-allowed' : 'pointer',
          userSelect: 'none',
          padding: '6px 4px'
        }}
      >
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center', marginTop: '2px' }}>
          <input
            type="checkbox"
            id={checkId}
            name={name}
            checked={!!checked}
            onChange={(e) => {
              if (!onChange) return;
              onChange(e);
            }}
            disabled={disabled}
            style={{
              position: 'absolute',
              opacity: 0,
              width: '20px',
              height: '20px',
              cursor: disabled ? 'not-allowed' : 'pointer'
            }}
          />
          <div
            style={{
              width: '20px',
              height: '20px',
              borderRadius: '5px',
              border: error
                ? '2px solid #EF4444'
                : (checked ? '2px solid var(--cut-gold-accent, #B78103)' : '2px solid #94A3B8'),
              background: checked ? 'var(--cut-gold-accent, #B78103)' : '#FFFFFF',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
              boxShadow: checked ? '0 1px 2px rgba(183, 129, 3, 0.25)' : 'none'
            }}
          >
            {checked && <Check size={14} color="#FFFFFF" strokeWidth={3} />}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          {label && (
            <span
              style={{
                fontSize: '13.5px',
                fontWeight: '600',
                color: disabled ? '#94A3B8' : 'var(--cut-text-main, #1E293B)',
                lineHeight: '1.4'
              }}
            >
              {label}
            </span>
          )}
          {subtext && (
            <span style={{ fontSize: '12px', color: '#64748B', marginTop: '2px', lineHeight: '1.4' }}>
              {subtext}
            </span>
          )}
        </div>
      </label>

      {error && (
        <span style={{ fontSize: '12px', color: '#DC2626', marginLeft: '32px', fontWeight: '500' }}>
          {error}
        </span>
      )}
    </div>
  );
}
