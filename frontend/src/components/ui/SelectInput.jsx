import React from 'react';
import { ChevronDown } from 'lucide-react';

export default function SelectInput({
  label,
  value,
  onChange,
  options = [],
  groups = null,
  placeholder = 'Select option...',
  helperText,
  error,
  disabled = false,
  required = false,
  id,
  name,
  style = {},
  className = ''
}) {
  const selectId = id || name || `select-${Math.random().toString(36).substr(2, 9)}`;

  return (
    <div className={`ui-form-group ${className}`} style={{ display: 'flex', flexDirection: 'column', gap: '6px', ...style }}>
      {label && (
        <label
          htmlFor={selectId}
          style={{
            fontSize: '13px',
            fontWeight: '600',
            color: 'var(--cut-text-main, #1E293B)',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}
        >
          {label}
          {required && <span style={{ color: '#DC2626' }}>*</span>}
        </label>
      )}

      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        <select
          id={selectId}
          name={name}
          value={value ?? ''}
          onChange={onChange}
          disabled={disabled}
          required={required}
          className={`ui-select ${error ? 'ui-input-error' : ''}`}
          style={{
            width: '100%',
            height: '44px',
            borderRadius: '8px',
            border: error ? '1.5px solid #EF4444' : '1px solid var(--cut-border, #CBD5E1)',
            background: disabled ? '#F1F5F9' : '#FFFFFF',
            paddingLeft: '14px',
            paddingRight: '36px',
            fontSize: '14px',
            color: disabled ? '#94A3B8' : '#0F172A',
            outline: 'none',
            appearance: 'none',
            WebkitAppearance: 'none',
            MozAppearance: 'none',
            cursor: disabled ? 'not-allowed' : 'pointer',
            transition: 'border-color 0.15s ease, box-shadow 0.15s ease'
          }}
        >
          {placeholder && !options.some((opt) => (opt.value ?? opt) === '') && (
            <option value="" disabled>{placeholder}</option>
          )}

          {groups ? (
            Object.entries(groups).map(([groupLabel, groupOpts]) => (
              <optgroup key={groupLabel} label={groupLabel}>
                {groupOpts.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </optgroup>
            ))
          ) : (
            options.map((opt) => (
              <option key={opt.value ?? opt} value={opt.value ?? opt}>
                {opt.label ?? opt}
              </option>
            ))
          )}
        </select>

        <span
          style={{
            position: 'absolute',
            right: '12px',
            pointerEvents: 'none',
            color: '#64748B',
            display: 'flex',
            alignItems: 'center'
          }}
        >
          <ChevronDown size={16} />
        </span>
      </div>

      {error ? (
        <span style={{ fontSize: '12px', color: '#DC2626', marginTop: '2px', fontWeight: '500' }}>
          {error}
        </span>
      ) : helperText ? (
        <span style={{ fontSize: '12px', color: '#64748B', marginTop: '2px' }}>
          {helperText}
        </span>
      ) : null}
    </div>
  );
}
