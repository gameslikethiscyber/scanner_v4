import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../api/client';

interface Project {
  id: number;
  name: string;
  description: string;
  target_url: string;
  tags: string[];
  security_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_scan_date: string | null;
  scan_count: number;
  created_at: string;
}

const ProjectsPage: React.FC = () => {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', target_url: '', description: '', tags: '' });
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  const fetchProjects = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/projects?page=${page}&page_size=20&search=${search}`);
      setProjects(res.data.items || []);
      setTotalPages(res.data.total_pages || 1);
    } catch (err) {
      console.error('Failed to fetch projects:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchProjects(); }, [page, search]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/projects', form);
      setShowCreate(false);
      setForm({ name: '', target_url: '', description: '', tags: '' });
      fetchProjects();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to create project');
    }
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Projects</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ New Project</button>
      </div>

      <div className="search-bar">
        <span className="search-icon">🔍</span>
        <input type="text" placeholder="Search projects..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
      </div>

      {loading ? (
        <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>
      ) : projects.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📁</div>
          <h3>No Projects Yet</h3>
          <p>Create your first project to start scanning.</p>
        </div>
      ) : (
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(350px,1fr))',gap:'16px'}}>
          {projects.map((p) => (
            <div
              key={p.id}
              className="card"
              style={{cursor:'pointer'}}
              onClick={() => navigate(`/projects/${p.id}`)}
            >
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:'12px'}}>
                <div>
                  <h3 style={{fontSize:'16px',fontWeight:600,marginBottom:'4px'}}>{p.name}</h3>
                  <p style={{fontSize:'12px',color:'var(--text-muted)',maxWidth:'250px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{p.target_url}</p>
                </div>
                <div className={`badge badge-${p.security_score > 80 ? 'low' : p.security_score > 50 ? 'medium' : 'high'}`}>
                  {p.security_score}%
                </div>
              </div>
              {p.tags.length > 0 && (
                <div style={{display:'flex',gap:'4px',flexWrap:'wrap',marginBottom:'12px'}}>
                  {p.tags.map((t, i) => <span key={i} className="badge badge-info">{t}</span>)}
                </div>
              )}
              <div style={{display:'flex',gap:'16px',fontSize:'12px',color:'var(--text-muted)'}}>
                <span>{p.scan_count} scans</span>
                <span style={{color:'var(--critical)'}}>{p.critical_count} critical</span>
                <span style={{color:'var(--high)'}}>{p.high_count} high</span>
                {p.last_scan_date && <span>Last scan: {new Date(p.last_scan_date).toLocaleDateString()}</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
          <span style={{color:'var(--text-muted)',fontSize:'13px'}}>Page {page} of {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}

      {showCreate && (
        <div className="modal-overlay" onClick={() => setShowCreate(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>New Project</h3>
              <button className="btn-icon" onClick={() => setShowCreate(false)}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="modal-body">
                <div className="form-group">
                  <label>Project Name</label>
                  <input type="text" className="form-input" value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} required placeholder="My Project" />
                </div>
                <div className="form-group">
                  <label>Target URL</label>
                  <input type="url" className="form-input" value={form.target_url} onChange={(e) => setForm({...form, target_url: e.target.value})} required placeholder="https://example.com" />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <textarea className="form-input" value={form.description} onChange={(e) => setForm({...form, description: e.target.value})} placeholder="Optional description" />
                </div>
                <div className="form-group">
                  <label>Tags (comma-separated)</label>
                  <input type="text" className="form-input" value={form.tags} onChange={(e) => setForm({...form, tags: e.target.value})} placeholder="production, critical" />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setShowCreate(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create Project</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default ProjectsPage;
