import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';

const ScansPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');

  const fetchScans = async () => {
    setLoading(true);
    try {
      const params = `page=${page}&page_size=20${statusFilter ? `&status=${statusFilter}` : ''}`;
      const res = await api.get(`/scans?${params}`);
      setScans(res.data.items || []);
      setTotalPages(res.data.total_pages || 1);
    } catch (err) {
      console.error('Failed to fetch scans:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchScans(); }, [page, statusFilter]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Scans</h1>
      </div>

      <div className="filter-bar">
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
          <option value="">All Status</option>
          <option value="pending">Pending</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
      </div>

      {loading ? (
        <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h3>No Scans Found</h3>
          <p>Create a project and run a scan to get started.</p>
        </div>
      ) : (
        <div className="card">
          <div className="table-container">
            <table>
              <thead>
                <tr><th>ID</th><th>Target</th><th>Status</th><th>Progress</th><th>Vulns</th><th>Risk</th><th>Duration</th><th>Date</th></tr>
              </thead>
              <tbody>
                {scans.map((scan: any) => (
                  <tr key={scan.id} onClick={() => navigate(`/scans/${scan.id}`)} style={{cursor:'pointer'}}>
                    <td>#{scan.id}</td>
                    <td style={{maxWidth:'250px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{scan.target_url}</td>
                    <td><span className={`status-dot ${scan.status}`} /><span className={`badge badge-${scan.status}`}>{scan.status}</span></td>
                    <td>
                      <div className="progress-bar" style={{width:'80px',display:'inline-block'}}>
                        <div className="progress-fill" style={{width:`${scan.progress || 0}%`}} />
                      </div>
                      <span style={{fontSize:'11px',color:'var(--text-muted)',marginLeft:'4px'}}>{scan.progress || 0}%</span>
                    </td>
                    <td>
                      <span style={{color:'var(--critical)'}}>{scan.critical_count}</span>
                      <span style={{color:'var(--text-muted)'}}> / </span>
                      <span style={{color:'var(--high)'}}>{scan.high_count}</span>
                      <span style={{color:'var(--text-muted)'}}> / </span>
                      <span style={{color:'var(--medium)'}}>{scan.medium_count}</span>
                    </td>
                    <td><span className={`badge badge-${scan.risk_score > 60 ? 'high' : scan.risk_score > 30 ? 'medium' : 'low'}`}>{scan.risk_score || 0}%</span></td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{scan.duration_seconds ? `${scan.duration_seconds.toFixed(1)}s` : '-'}</td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{new Date(scan.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {totalPages > 1 && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
          <span style={{color:'var(--text-muted)',fontSize:'13px'}}>Page {page} of {totalPages}</span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </div>
  );
};

export default ScansPage;
