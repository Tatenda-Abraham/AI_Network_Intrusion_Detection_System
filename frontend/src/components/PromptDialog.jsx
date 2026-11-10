import React, { useEffect, useRef, useState } from 'react';
import { Edit3, X } from 'lucide-react';

export default function PromptDialog({
  isOpen,
  onClose,
  onSubmit,
  title,
  placeholder = '',
  defaultValue = '',
  multiline = false,
  maxLength = 500,
  confirmText = 'Submit',
  cancelText = 'Cancel'
}) {
  const [value, setValue] = useState(defaultValue);
  const dialogRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    setValue(defaultValue);
  }, [defaultValue, isOpen]);

  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (value.trim()) {
      onSubmit(value.trim());
      setValue('');
    }
  };

  const charCount = value.length;
  const isNearLimit = charCount > maxLength * 0.9;
  const isAtLimit = charCount >= maxLength;

  return (
    <div className="modal-overlay" style={{ zIndex: 2000 }}>
      <div
        ref={dialogRef}
        className="modal-content"
        style={{ maxWidth: '500px', padding: '24px' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
          <div style={{ background: '#E0F2FE', padding: '10px', borderRadius: '50%' }}>
            <Edit3 size={24} color="#0288D1" />
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: '800', color: 'var(--cut-blue-dark)', flex: 1 }}>
            {title}
          </h3>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}
          >
            <X size={20} color="#64748B" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {multiline ? (
            <textarea
              ref={inputRef}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              maxLength={maxLength}
              rows={4}
              className="form-input"
              style={{
                width: '100%',
                resize: 'vertical',
                marginBottom: '8px',
                border: isAtLimit ? '2px solid #DC2626' : '1px solid var(--cut-border)'
              }}
            />
          ) : (
            <input
              ref={inputRef}
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={placeholder}
              maxLength={maxLength}
              className="form-input"
              style={{
                width: '100%',
                marginBottom: '8px',
                border: isAtLimit ? '2px solid #DC2626' : '1px solid var(--cut-border)'
              }}
            />
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <span
              style={{
                fontSize: '11px',
                color: isAtLimit ? '#DC2626' : isNearLimit ? '#F59E0B' : '#94A3B8'
              }}
            >
              {charCount} / {maxLength} characters
            </span>
            {isAtLimit && (
              <span style={{ fontSize: '11px', color: '#DC2626', fontWeight: '600' }}>
                Character limit reached
              </span>
            )}
          </div>

          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary"
              style={{ padding: '10px 20px' }}
            >
              {cancelText}
            </button>
            <button
              type="submit"
              disabled={!value.trim()}
              className="mode-action-btn btn-gold"
              style={{ padding: '10px 20px' }}
            >
              {confirmText}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
