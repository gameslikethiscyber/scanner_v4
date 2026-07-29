import React, { useState, useEffect } from 'react';
import api from '../api/client';
import { useAuth } from '../contexts/AuthContext';

const UsersPage: React.FC = () => {
  const { user } = useAuth();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/users?page_size=100').then((res) => {
      setUsers(res.data.items || []);
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  const handleRoleChange = async (userId: number, role: string) => {
    try {
      await api.put(`/users/${userId}/role`, { role });
      setUsers(users.map((u) => u.id === userId ? { ...u, role } : u));
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to update role');
    }
  };

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Users</h1>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Verified</th><th>Last Login</th><th>Created</th></tr></thead>
            <tbody>
              {users.map((u: any) => (
                <tr key={u.id}>
                  <td>
                    <div style={{display:'flex',alignItems:'center',gap:'8px'}}>
                      <div className="user-avatar" style={{width:'32px',height:'32px',fontSize:'12px'}}>{u.username?.[0]?.toUpperCase()}</div>
                      <div>
                        <div style={{fontWeight:600,fontSize:'14px'}}>{u.full_name || u.username}</div>
                        <div style={{fontSize:'11px',color:'var(--text-muted)'}}>@{u.username}</div>
                      </div>
                    </div>
                  </td>
                  <td style={{fontSize:'13px'}}>{u.email}</td>
                  <td>
                    <select
                      className="form-input"
                      style={{padding:'4px 8px',fontSize:'12px',width:'auto'}}
                      value={u.role}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      disabled={user?.role !== 'admin'}
                    >
                      <option value="admin">Admin</option>
                      <option value="manager">Manager</option>
                      <option value="user">User</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                  <td><span className={`badge ${u.is_active ? 'badge-pass' : 'badge-skipped'}`}>{u.is_active ? 'Active' : 'Inactive'}</span></td>
                  <td><span className={`badge ${u.is_verified ? 'badge-pass' : 'badge-warning'}`}>{u.is_verified ? 'Yes' : 'No'}</span></td>
                  <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never'}</td>
                  <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{new Date(u.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UsersPage;
