import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import api from '../api/client';

const ProjectDetailPage: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showScanModal, setShowScanModal] = useState(false);

  const fetchData = async () => {
    try {
      const [projRes, scansRes] = await Promise.all([
        api.get(`/projects/${id}`),
        api.get(`/scans?project_id=${id}&page_size=50`),
      ]);
      setProject(projRes.data);
      setScans(scansRes.data.items || []);
    } catch (err) {
      console.error('Failed to load project:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, [id]);

  const startScan = async () => {
    try {
      const res = await api.post('/scans', { project_id: parseInt(id!) });
      navigate(`/scans/${res.data.id}`);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Failed to start scan');
    }
  };

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;
  if (!project) return <div className="empty-state"><h3>Project not found</h3></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <Link to="/projects" style={{fontSize:'13px',color:'var(--text-muted)'}}>← Back to Projects</Link>
          <h1 className="page-title" style={{marginTop:'4px'}}>{project.name}</h1>
        </div>
        <div className="page-actions">
          <button className="btn btn-primary" onClick={startScan}>Run Scan</button>
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'2fr 1fr',gap:'20px',marginBottom:'24px'}}>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Project Info</h3></div>
          <div style={{display:'grid',gap:'12px'}}>
            <div><label style={{fontSize:'12px',color:'var(--text-muted)'}}>Target URL</label><div style={{fontSize:'14px'}}>{project.target_url}</div></div>
            {project.description && <div><label style={{fontSize:'12px',color:'var(--text-muted)'}}>Description</label><div style={{fontSize:'14px'}}>{project.description}</div></div>}
            {project.tags?.length > 0 && (
              <div><label style={{fontSize:'12px',color:'var(--text-muted)'}}>Tags</label>
                <div style={{display:'flex',gap:'4px',marginTop:'4px'}}>{project.tags.map((t: string,i: number) => <span key={i} className="badge badge-info">{t}</span>)}</div>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h3 className="card-title">Security Score</h3></div>
          <div style={{textAlign:'center',padding:'20px'}}>
            <div style={{fontSize:'48px',fontWeight:700,color: project.security_score > 80 ? 'var(--success)' : project.security_score > 50 ? 'var(--warning)' : 'var(--danger)'}}>
              {project.security_score}%
            </div>
            <div className="progress-bar" style={{margin:'12px 0',height:'8px'}}>
              <div className="progress-fill" style={{width:`${project.security_score}%`,background: project.security_score > 80 ? 'var(--success)' : project.security_score > 50 ? 'var(--warning)' : 'var(--danger)'}} />
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'8px',fontSize:'12px',marginTop:'12px'}}>
              <span style={{color:'var(--critical)'}}>Critical: {project.critical_count}</span>
              <span style={{color:'var(--high)'}}>High: {project.high_count}</span>
              <span style={{color:'var(--medium)'}}>Medium: {project.medium_count}</span>
              <span style={{color:'var(--low)'}}>Low: {project.low_count}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Scan History ({scans.length})</h3>
          <button className="btn btn-primary btn-sm" onClick={() => setShowScanModal(true)}>New Scan</button>
        </div>
        {scans.length === 0 ? (
          <div className="empty-state" style={{padding:'40px'}}>
            <div className="empty-icon">🔍</div>
            <h3>No scans yet</h3>
            <p>Run your first scan to see results here.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr><th>ID</th><th>Status</th><th>Vulnerabilities</th><th>Risk Score</th><th>Duration</th><th>Date</th></tr>
              </thead>
              <tbody>
                {scans.map((scan: any) => (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} style={{cursor:'pointer'}}>
                    <td>#{scan.id}</td>
                    <td><span className={`status-dot ${scan.status}`} />{scan.status}</td>
                    <td>{scan.vulnerabilities_count || 0} (C:{scan.critical_count} H:{scan.high_count} M:{scan.medium_count} L:{scan.low_count})</td>
                    <td><span className={`badge badge-${scan.risk_score > 60 ? 'high' : scan.risk_score > 30 ? 'medium' : 'low'}`}>{scan.risk_score || 0}%</span></td>
                    <td>{scan.duration_seconds ? `${scan.duration_seconds.toFixed(1)}s` : '-'}</td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{new Date(scan.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default ProjectDetailPage;
