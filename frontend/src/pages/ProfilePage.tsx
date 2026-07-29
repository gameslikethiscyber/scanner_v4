import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import api from '../api/client';

const ProfilePage: React.FC = () => {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage('');
    try {
      await api.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword });
      setMessage('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
    } catch (err: any) {
      setMessage(err.response?.data?.detail || 'Failed to change password');
    }
  };

  if (!user) return null;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Profile</h1>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px'}}>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Account Info</h3></div>
          <div style={{textAlign:'center',padding:'20px 0'}}>
            <div className="user-avatar" style={{width:'64px',height:'64px',fontSize:'24px',margin:'0 auto 12px'}}>
              {user.username?.[0]?.toUpperCase()}
            </div>
            <h2 style={{fontSize:'20px',marginBottom:'4px'}}>{user.full_name || user.username}</h2>
            <p style={{color:'var(--text-muted)',fontSize:'14px'}}>@{user.username}</p>
          </div>
          <div style={{display:'grid',gap:'8px',fontSize:'14px'}}>
            <div><span style={{color:'var(--text-muted)'}}>Email:</span> {user.email}</div>
            <div><span style={{color:'var(--text-muted)'}}>Role:</span> <span className="badge badge-info">{user.role}</span></div>
            <div><span style={{color:'var(--text-muted)'}}>Status:</span> <span className={`badge ${user.is_active ? 'badge-pass' : 'badge-skipped'}`}>{user.is_active ? 'Active' : 'Inactive'}</span></div>
            <div><span style={{color:'var(--text-muted)'}}>Verified:</span> {user.is_verified ? 'Yes' : 'No'}</div>
            <div><span style={{color:'var(--text-muted)'}}>Member Since:</span> {new Date(user.created_at).toLocaleDateString()}</div>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h3 className="card-title">Change Password</h3></div>
          {message && (
            <div className="card" style={{background: message.includes('success') ? 'rgba(76,175,80,0.1)' : 'rgba(244,67,54,0.1)',borderColor: message.includes('success') ? 'var(--success)' : 'var(--danger)',padding:'12px',marginBottom:'16px',fontSize:'13px',color: message.includes('success') ? 'var(--success)' : 'var(--danger)'}}>
              {message}
            </div>
          )}
          <form onSubmit={handleChangePassword}>
            <div className="form-group">
              <label>Current Password</label>
              <input type="password" className="form-input" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required />
            </div>
            <div className="form-group">
              <label>New Password</label>
              <input type="password" className="form-input" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={8} />
            </div>
            <button type="submit" className="btn btn-primary">Update Password</button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;
