import React, { useState } from 'react';
import { Eye, EyeOff, X } from 'lucide-react';

export default function TextInput({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  helperText,
  error,
  leftIcon: LeftIcon,
  disabled = false,
  required = false,
  id,
  name,
  onClear,
  style = {},
  className = '',
  autoComplete,
  min,
  max
}) {
  const [showPassword, setShowPassword] = useState(false);
  const inputId = id || name || `input-${Math.random().toString(36).substr(2, 9)}`;
  const isPassword = type === 'password';
  const effectiveType = isPassword ? (showPassword ? 'text' : 'password') : type;

  return (
    <div className={`ui-form-group ${className}`} style={{ display: 'flex', flexDirection: 'column', gap: '6px', ...style }}>
      {label && (
        <label
          htmlFor={inputId}
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
        {LeftIcon && (
          <span style={{ position: 'absolute', left: '12px', color: '#8CA0B3', display: 'flex', alignItems: 'center', pointerEvents: 'none' }}>
            <LeftIcon size={18} />
          </span>
        )}

        <input
          id={inputId}
          name={name}
          type={effectiveType}
          value={value ?? ''}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          required={required}
          autoComplete={autoComplete}
          min={min}
          max={max}
          className={`ui-input ${error ? 'ui-input-error' : ''}`}
          style={{
            width: '100%',
            height: '44px',
            borderRadius: '8px',
            border: error ? '1.5px solid #EF4444' : '1px solid var(--cut-border, #CBD5E1)',
            background: disabled ? '#F1F5F9' : '#FFFFFF',
            paddingLeft: LeftIcon ? '38px' : '14px',
            paddingRight: (isPassword || onClear) ? '40px' : '14px',
            fontSize: '14px',
            color: disabled ? '#94A3B8' : '#0F172A',
            outline: 'none',
            transition: 'border-color 0.15s ease, box-shadow 0.15s ease'
          }}
        />

        {isPassword && !disabled && (
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            tabIndex={-1}
            style={{
              position: 'absolute',
              right: '10px',
              background: 'none',
              border: 'none',
              padding: '6px',
              cursor: 'pointer',
              color: '#64748B',
              display: 'flex',
              alignItems: 'center'
            }}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        )}

        {!isPassword && onClear && value && !disabled && (
          <button
            type="button"
            onClick={onClear}
            tabIndex={-1}
            style={{
              position: 'absolute',
              right: '10px',
              background: 'none',
              border: 'none',
              padding: '6px',
              cursor: 'pointer',
              color: '#94A3B8',
              display: 'flex',
              alignItems: 'center'
            }}
            aria-label="Clear field"
          >
            <X size={14} />
          </button>
        )}
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
