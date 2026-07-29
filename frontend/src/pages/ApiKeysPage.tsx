import React, { useState, useEffect } from 'react';
import api from '../api/client';

const ApiKeysPage: React.FC = () => {
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState<any>(null);
  const [form, setForm] = useState({ name: '', permissions: 'read' });

  const fetchKeys = async () => {
    try {
      const res = await api.get('/api-keys?page_size=50');
      setKeys(res.data.items || []);
    } catch (err) {
      console.error('Failed to load API keys:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchKeys(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.post('/api-keys', form);
      setNewKey(res.data);
      setShowCreate(false);
      fetchKeys();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create key');
    }
  };

  const handleDelete = async (keyId: number) => {
    if (!confirm('Deactivate this API key?')) return;
    try {
      await api.delete(`/api-keys/${keyId}`);
      fetchKeys();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to delete key');
    }
  };

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">API Keys</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New API Key</button>
      </div>

      {newKey && (
        <div className="card" style={{borderColor:'var(--accent)',marginBottom:'20px'}}>
          <div className="card-header"><h3 className="card-title">API Key Created</h3></div>
          <p style={{fontSize:'13px',color:'var(--text-muted)',marginBottom:'12px'}}>Copy this key now. You won't be able to see it again.</p>
          <div style={{display:'flex',gap:'8px',alignItems:'center'}}>
            <code style={{flex:1,padding:'10px',background:'var(--bg-input)',borderRadius:'var(--radius)',fontSize:'13px',wordBreak:'break-all'}}>{newKey.full_key}</code>
            <button className="btn btn-primary btn-sm" onClick={() => { navigator.clipboard.writeText(newKey.full_key); alert('Copied!'); }}>Copy</button>
          </div>
          <button className="btn btn-sm btn-secondary" style={{marginTop:'12px'}} onClick={() => setNewKey(null)}>Dismiss</button>
        </div>
      )}

      <div className="card">
        {keys.length === 0 ? (
          <div className="empty-state" style={{padding:'40px'}}>
            <div className="empty-icon">🔑</div>
            <h3>No API Keys</h3>
            <p>Create an API key to integrate with external tools.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead><tr><th>Name</th><th>Key</th><th>Permissions</th><th>Created</th><th>Last Used</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {keys.map((k: any) => (
                  <tr key={k.id}>
                    <td style={{fontWeight:600}}>{k.name}</td>
                    <td><code style={{fontSize:'12px',color:'var(--text-muted)'}}>{k.key_prefix}...</code></td>
                    <td><span className="badge badge-info">{k.permissions}</span></td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{new Date(k.created_at).toLocaleDateString()}</td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}</td>
                    <td><span className={`badge ${k.is_active ? 'badge-pass' : 'badge-skipped'}`}>{k.is_active ? 'Active' : 'Inactive'}</span></td>
                    <td>
                      <button className="btn btn-sm btn-danger" onClick={() => handleDelete(k.id)}>Revoke</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <div className="modal-overlay" onClick={() => setShowCreate(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>New API Key</h3>
              <button className="btn-icon" onClick={() => setShowCreate(false)}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="modal-body">
                <div className="form-group">
                  <label>Key Name</label>
                  <input type="text" className="form-input" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} required placeholder="CI/CD Integration" />
                </div>
                <div className="form-group">
                  <label>Permissions</label>
                  <select className="form-input" value={form.permissions} onChange={(e) => setForm({...form, permissions: e.target.value})}>
                    <option value="read">Read Only</option>
                    <option value="read,write">Read & Write</option>
                    <option value="read,write,admin">Full Access</option>
                  </select>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create Key</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApiKeysPage;
