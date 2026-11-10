import React, { useState } from 'react';
import { Shield, Lock, User, AlertCircle, ShieldCheck, UserCheck } from 'lucide-react';
import { api, setAuthToken, setCurrentUser } from '../api/client';

const SIGN_IN_ROLES = [
  { value: 'Administrator', hint: 'Full console control, accounts and capture', Icon: ShieldCheck },
  { value: 'Cybersecurity Analyst', hint: 'Monitoring, threats, analytics and reports', Icon: UserCheck }
];

export default function LoginPage({ onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [signInAs, setSignInAs] = useState('Administrator');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);

    try {
      const res = await api.auth.login(username, password, signInAs);
      const token = res?.access_token || res?.token;
      const user = res?.user;

      if (!token || !user) {
        setErrorMsg('Login succeeded but the session could not be started. Please try again.');
        return;
      }

      setAuthToken(token);
      setCurrentUser(user);
      if (onLoginSuccess) {
        onLoginSuccess(user);
      }
    } catch (err) {
      setErrorMsg(err.message || 'Invalid username or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-shell">
      {/* CUT Banner Header */}
      <header className="cut-header">
        <div className="cut-header-content" style={{ justifyContent: 'center' }}>
          <div className="cut-brand-wrapper" style={{ flex: '0 1 auto' }}>
            <img src="/cut-logo.png" alt="Chinhoyi University of Technology Logo" className="cut-logo" />
            <div className="cut-titles" style={{ textAlign: 'center' }}>
              <h1>CHINHOYI UNIVERSITY OF TECHNOLOGY</h1>
              <p>AI-Based Network Intrusion Detection and Monitoring System</p>
            </div>
          </div>
        </div>
      </header>

      {/* Login Card Container */}
      <div className="login-shell-body">
        <div
          className="login-card"
          style={{
            background: 'var(--cut-white)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-lg)',
            border: '1px solid var(--cut-border)',
            overflow: 'hidden'
          }}
        >
          {/* Top Decorative Header */}
          <div
            style={{
              background: 'linear-gradient(135deg, #0288D1 0%, #0D47A1 100%)',
              padding: 'clamp(18px, 4vw, 24px)',
              textAlign: 'center',
              color: 'var(--cut-white)'
            }}
          >
            <div
              style={{
                width: '56px',
                height: '56px',
                borderRadius: '50%',
                background: 'rgba(255, 255, 255, 0.15)',
                border: '2px solid var(--cut-gold-bright)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 12px'
              }}
            >
              <Shield size={28} color="#FFC72C" />
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: '800' }}>Security Console Login</h2>
            <p style={{ fontSize: '12px', color: '#B3E5FC', marginTop: '4px' }}>
              School of Engineering Sciences & Technology (Group 5)
            </p>
          </div>

          {/* Form Area */}
          <form onSubmit={handleSubmit}>
            {errorMsg && (
              <div
                style={{
                  background: '#FFEBEE',
                  color: '#C62828',
                  border: '1px solid #EF9A9A',
                  padding: '10px 12px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginBottom: '18px'
                }}
              >
                <AlertCircle size={16} />
                <span>{errorMsg}</span>
              </div>
            )}

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: 'var(--cut-text-main)', marginBottom: '6px' }}>
                Sign in as
              </label>
              <div className="role-choice">
                {SIGN_IN_ROLES.map(({ value, hint, Icon }) => (
                  <button
                    type="button"
                    key={value}
                    onClick={() => setSignInAs(value)}
                    className={`role-choice-btn ${signInAs === value ? 'selected' : ''}`}
                    aria-pressed={signInAs === value}
                  >
                    <Icon size={18} />
                    <span className="role-choice-text">
                      <strong>{value}</strong>
                      <small>{hint}</small>
                    </span>
                  </button>
                ))}
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: 'var(--cut-text-main)', marginBottom: '6px' }}>
                Username / Security ID
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="form-input"
                  style={{ paddingLeft: '36px' }}
                  placeholder="Enter system username"
                />
                <User size={16} color="#8CA0B3" style={{ position: 'absolute', left: '12px', top: '12px' }} />
              </div>
            </div>

            <div style={{ marginBottom: '22px' }}>
              <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: 'var(--cut-text-main)', marginBottom: '6px' }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="form-input"
                  style={{ paddingLeft: '36px' }}
                  placeholder="••••••••••••"
                />
                <Lock size={16} color="#8CA0B3" style={{ position: 'absolute', left: '12px', top: '12px' }} />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-green"
              style={{ width: '100%', justifyContent: 'center', padding: '12px', fontSize: '14px' }}
            >
              {loading ? 'Authenticating...' : 'Sign In to AI-NIDS'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
