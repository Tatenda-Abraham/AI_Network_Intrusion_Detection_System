import React, { useEffect, useState } from 'react';
import { CheckCircle, AlertTriangle, Info, XCircle, X } from 'lucide-react';

export default function Toast({ type = 'info', message, duration = 5000, onClose }) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(onClose, 300);
    }, duration);
    return () => clearTimeout(timer);
  }, [duration, onClose]);

  const styles = {
    success: { bg: '#DCFCE7', border: '#86EFAC', icon: <CheckCircle size={20} color="#16A34A" /> },
    error: { bg: '#FEE2E2', border: '#FCA5A5', icon: <XCircle size={20} color="#DC2626" /> },
    warning: { bg: '#FEF3C7', border: '#FDE68A', icon: <AlertTriangle size={20} color="#F59E0B" /> },
    info: { bg: '#E0F2FE', border: '#BAE6FD', icon: <Info size={20} color="#0288D1" /> }
  };

  const style = styles[type] || styles.info;

  return (
    <div
      style={{
        background: style.bg,
        border: `1px solid ${style.border}`,
        borderRadius: '8px',
        padding: '12px 16px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        
        maxWidth: '100%',
        boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
        transition: 'opacity 0.3s, transform 0.3s',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateX(0)' : 'translateX(100%)'
      }}
    >
      {style.icon}
      <span style={{ flex: 1, fontSize: '13px', color: 'var(--cut-text-main)' }}>{message}</span>
      <button
        onClick={() => {
          setVisible(false);
          setTimeout(onClose, 300);
        }}
        style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '2px' }}
      >
        <X size={16} color="#64748B" />
      </button>
    </div>
  );
}

// Toast Container
export function ToastContainer({ toasts, removeToast }) {
  return (
    <div
      className="toast-stack"
      style={{
        position: 'fixed',
        top: '20px',
        zIndex: 3000,
        display: 'flex',
        flexDirection: 'column',
        gap: '10px'
      }}
    >
      {toasts.map((toast) => (
        <Toast
          key={toast.id}
          type={toast.type}
          message={toast.message}
          duration={toast.duration}
          onClose={() => removeToast(toast.id)}
        />
      ))}
    </div>
  );
}
