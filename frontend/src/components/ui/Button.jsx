import React from 'react';
import { Loader2 } from 'lucide-react';

export default function Button({
  children,
  onClick,
  type = 'button',
  variant = 'primary', // 'primary' (gold), 'secondary' (white + blue border), 'danger' (red), 'icon', 'ghost'
  size = 'md', // 'sm', 'md', 'lg'
  disabled = false,
  loading = false,
  icon: Icon,
  iconRight: IconRight,
  style = {},
  className = '',
  title,
  ariaLabel
}) {
  // Size metrics
  const sizeStyles = {
    sm: { height: '34px', padding: '0 12px', fontSize: '12px', gap: '6px' },
    md: { height: '42px', padding: '0 18px', fontSize: '13.5px', gap: '8px' },
    lg: { height: '48px', padding: '0 24px', fontSize: '15px', gap: '10px' }
  };

  // Base variant palettes
  const variantStyles = {
    primary: {
      background: 'linear-gradient(135deg, #E6B800 0%, #D4AF37 100%)',
      color: '#0F172A',
      border: '1px solid #C49B28',
      fontWeight: '700',
      boxShadow: '0 1px 3px rgba(212, 175, 55, 0.3)'
    },
    secondary: {
      background: '#FFFFFF',
      color: '#0288D1',
      border: '1px solid #BAE6FD',
      fontWeight: '600',
      boxShadow: '0 1px 2px rgba(0,0,0,0.03)'
    },
    danger: {
      background: '#EF4444',
      color: '#FFFFFF',
      border: '1px solid #DC2626',
      fontWeight: '600',
      boxShadow: '0 1px 2px rgba(239, 68, 68, 0.2)'
    },
    ghost: {
      background: 'transparent',
      color: '#475569',
      border: '1px solid transparent',
      fontWeight: '500'
    },
    icon: {
      background: '#FFFFFF',
      color: '#0288D1',
      border: '1px solid #E2E8F0',
      padding: '0',
      width: size === 'sm' ? '32px' : size === 'lg' ? '46px' : '38px',
      height: size === 'sm' ? '32px' : size === 'lg' ? '46px' : '38px',
      justifyContent: 'center',
      borderRadius: '8px'
    }
  };

  const selectedSize = variant === 'icon' ? {} : sizeStyles[size];
  const selectedVariant = variantStyles[variant] || variantStyles.primary;

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      title={title}
      aria-label={ariaLabel || title}
      className={`ui-btn ui-btn-${variant} ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: '8px',
        cursor: (disabled || loading) ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.55 : 1,
        transition: 'all 0.15s ease',
        userSelect: 'none',
        whiteSpace: 'nowrap',
        ...selectedSize,
        ...selectedVariant,
        ...style
      }}
    >
      {loading ? (
        <>
          <Loader2 size={16} className="ui-spinner" style={{ animation: 'spin 1s linear infinite' }} />
          {variant !== 'icon' && <span>Processing...</span>}
        </>
      ) : (
        <>
          {Icon && <Icon size={size === 'sm' ? 14 : size === 'lg' ? 18 : 16} />}
          {children}
          {IconRight && <IconRight size={size === 'sm' ? 14 : size === 'lg' ? 18 : 16} />}
        </>
      )}
    </button>
  );
}
