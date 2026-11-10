import React, { useState, useEffect } from 'react';
import { Users, UserPlus, ShieldCheck, Check, X } from 'lucide-react';
import { api, getCurrentUser } from '../api/client';
import { useToast } from '../contexts/ToastContext';

export default function UserManagementPage() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('Cybersecurity Analyst');
  const [statusMsg, setStatusMsg] = useState('');

  const user = getCurrentUser();
  const isAdmin = user?.role === 'Administrator';
  const { success, error } = useToast();

  const fetchUsers = async () => {
    try {
      const data = await api.users.list();
      setUsers(data.users || []);
    } catch (err) {
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword) return;

    try {
      await api.users.create({
        username: newUsername.trim(),
        password: newPassword,
        role: newRole
      });
      setStatusMsg(`User '${newUsername}' created successfully.`);
      setNewUsername('');
      setNewPassword('');
      await fetchUsers();
      success('User created successfully');
    } catch (err) {
      error(`Error creating user: ${err.message}`);
    }
  };

  const handleToggleActive = async (targetUser) => {
    try {
      await api.users.update(targetUser.id, { active: !targetUser.active });
      await fetchUsers();
      success(`User ${targetUser.active ? 'disabled' : 'activated'}`);
    } catch (err) {
      error(`Error updating user status: ${err.message}`);
    }
  };

  if (!isAdmin) {
    return (
      <div style={{ background: '#FFEBEE', padding: '24px', borderRadius: '8px', color: '#C62828' }}>
        <h3>Access Denied</h3>
        <p>User Management is restricted strictly to users with the Administrator role.</p>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: '800', color: 'var(--cut-blue-dark)' }}>
          User Management
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--cut-text-muted)' }}>
          Configure staff accounts and manage role permissions.
        </p>
      </div>

      {statusMsg && (
        <div style={{ background: '#E0F2FE', color: '#0369A1', padding: '12px', borderRadius: '8px', marginBottom: '20px', fontSize: '13px' }}>
          {statusMsg}
        </div>
      )}

      {/* Create User Card */}
      <div style={{ background: 'var(--cut-white)', padding: '24px', borderRadius: 'var(--radius-md)', border: '1px solid var(--cut-border)', marginBottom: '24px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: '700', color: 'var(--cut-blue-dark)', marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <UserPlus size={18} color="#0288D1" />
          <span>Create Security Console User</span>
        </h3>

        <form onSubmit={handleCreateUser}>
          <div style={{ marginBottom: '12px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>Username:</label>
            <input
              type="text"
              required
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              className="form-input"
              placeholder="e.g. analyst_tawanda"
            />
          </div>

          <div style={{ marginBottom: '12px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>Password:</label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="form-input"
              placeholder="At least 8 characters"
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>Security Role:</label>
            <select value={newRole} onChange={(e) => setNewRole(e.target.value)} className="form-select">
              <option value="Cybersecurity Analyst">Cybersecurity Analyst</option>
              <option value="Administrator">Administrator</option>
            </select>
          </div>

          <button type="submit" className="btn-green" style={{ width: '100%', justifyContent: 'center' }}>
            Create Account
          </button>
        </form>
      </div>

      {/* Users Table */}
      <div className="table-card">
        <div className="table-header-bar">
          <h3>Registered System Users</h3>
        </div>
        <table className="custom-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created Date</th>
              <th>Last Login</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>#{u.id}</td>
                <td style={{ fontWeight: '700' }}>{u.username}</td>
                <td>
                  <span className="role-badge">{u.role}</span>
                </td>
                <td>
                  <span style={{ color: u.active ? '#16A34A' : '#DC2626', fontWeight: '600' }}>
                    {u.active ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td style={{ fontSize: '12px' }}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : 'N/A'}</td>
                <td style={{ fontSize: '12px' }}>{u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}</td>
                <td>
                  <button
                    onClick={() => handleToggleActive(u)}
                    className="btn-secondary"
                    style={{ padding: '3px 8px', fontSize: '11px' }}
                  >
                    {u.active ? 'Deactivate' : 'Activate'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
