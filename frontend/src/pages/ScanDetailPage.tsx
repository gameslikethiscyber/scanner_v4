import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client';

const ScanDetailPage: React.FC = () => {
  const { id } = useParams();
  const [scan, setScan] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'reports'>('overview');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [scanRes, findingsRes] = await Promise.all([
          api.get(`/scans/${id}`),
          api.get(`/findings?scan_id=${id}&page_size=200`),
        ]);
        setScan(scanRes.data);
        setFindings(findingsRes.data.items || []);
      } catch (err) {
        console.error('Failed to load scan:', err);
      } finally {
        setLoading(false);
      }
    };
    if (id) fetchData();
  }, [id]);

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;
  if (!scan) return <div className="empty-state"><h3>Scan not found</h3></div>;

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sortedFindings = [...findings].sort((a, b) => {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });

  return (
    <div>
      <div className="page-header">
        <div>
          <Link to="/scans" style={{fontSize:'13px',color:'var(--text-muted)'}}>← Back to Scans</Link>
          <h1 className="page-title" style={{marginTop:'4px'}}>Scan #{scan.id}</h1>
        </div>
        <div className="page-actions">
          {scan.status === 'completed' && (
            <Link to={`/reports?scan_id=${scan.id}`} className="btn btn-primary">View Reports</Link>
          )}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div><span className={`status-dot ${scan.status}`} />{scan.status.toUpperCase()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Target</div>
          <div style={{fontSize:'14px',wordBreak:'break-all'}}>{scan.target_url}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Risk Score</div>
          <div className="stat-value" style={{color: (scan.risk_score || 0) > 60 ? 'var(--danger)' : (scan.risk_score || 0) > 30 ? 'var(--warning)' : 'var(--success)'}}>
            {scan.risk_score || 0}%
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value" style={{fontSize:'20px'}}>{scan.duration_seconds ? `${scan.duration_seconds.toFixed(1)}s` : '-'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Vulnerabilities</div>
          <div className="stat-value" style={{color: (scan.vulnerabilities_count || 0) > 0 ? 'var(--danger)' : 'var(--success)'}}>{scan.vulnerabilities_count || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Coverage</div>
          <div className="stat-value" style={{fontSize:'20px'}}>{scan.coverage_percentage || 0}%</div>
        </div>
      </div>

      <div className="tabs">
        <button className={`tab ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>Overview</button>
        <button className={`tab ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>Findings ({findings.length})</button>
        <button className={`tab ${activeTab === 'reports' ? 'active' : ''}`} onClick={() => setActiveTab('reports')}>Reports</button>
      </div>

      {activeTab === 'overview' && (
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px'}}>
          <div className="card">
            <div className="card-header"><h3 className="card-title">Severity Breakdown</h3></div>
            {['critical','high','medium','low'].map((sev) => (
              <div key={sev} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 0',borderBottom:'1px solid var(--border)'}}>
                <span style={{color:`var(--${sev})`,fontWeight:600,textTransform:'capitalize'}}>{sev}</span>
                <span style={{fontWeight:700,fontSize:'18px'}}>{(scan as any)[`${sev}_count`] || 0}</span>
              </div>
            ))}
          </div>
          <div className="card">
            <div className="card-header"><h3 className="card-title">Scan Details</h3></div>
            <div style={{display:'grid',gap:'8px',fontSize:'14px'}}>
              <div><span style={{color:'var(--text-muted)'}}>Status:</span> {scan.status}</div>
              <div><span style={{color:'var(--text-muted)'}}>Progress:</span> {scan.progress}%</div>
              <div><span style={{color:'var(--text-muted)'}}>Started:</span> {scan.started_at ? new Date(scan.started_at).toLocaleString() : '-'}</div>
              <div><span style={{color:'var(--text-muted)'}}>Completed:</span> {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '-'}</div>
              <div><span style={{color:'var(--text-muted)'}}>Retry Count:</span> {scan.retry_count}</div>
              <div><span style={{color:'var(--text-muted)'}}>Warnings:</span> {scan.warning_count || 0}</div>
              <div><span style={{color:'var(--text-muted)'}}>Info:</span> {scan.info_count || 0}</div>
              <div><span style={{color:'var(--text-muted)'}}>Passed:</span> {scan.passed_count || 0}</div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'findings' && (
        <div className="card">
          {sortedFindings.length === 0 ? (
            <div className="empty-state" style={{padding:'40px'}}>
              <h3>No Findings</h3>
              <p>No vulnerabilities detected in this scan.</p>
            </div>
          ) : (
            <div className="table-container">
              <table>
                <thead>
                  <tr><th>Severity</th><th>Module</th><th>Title</th><th>Confidence</th><th>Verification</th><th>CVSS</th><th>URL</th></tr>
                </thead>
                <tbody>
                  {sortedFindings.map((f: any) => (
                    <tr key={f.id}>
                      <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                      <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{f.module}</td>
                      <td style={{maxWidth:'250px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.title || f.description || f.module}</td>
                      <td>{f.confidence}%</td>
                      <td><span className={`badge badge-${f.verification_status === 'verified' ? 'pass' : 'warning'}`}>{f.verification_status}</span></td>
                      <td>{f.cvss_score || '-'}</td>
                      <td style={{fontSize:'12px',maxWidth:'150px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{f.affected_url}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'reports' && (
        <ReportsPage scanId={scan.id} embedded />
      )}
    </div>
  );
};

const ReportsPage: React.FC<{ scanId?: number; embedded?: boolean }> = ({ scanId, embedded }) => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const params = scanId ? `?scan_id=${scanId}` : '?page_size=50';
        const res = await api.get(`/reports${params}`);
        setReports(res.data.items || []);
      } catch (err) {
        console.error('Failed to fetch reports:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, [scanId]);

  if (loading) return <div style={{textAlign:'center',padding:'40px'}}><div className="spinner" /></div>;

  return (
    <div className="card">
      <div className="card-header"><h3 className="card-title">Generated Reports</h3></div>
      {reports.length === 0 ? (
        <div className="empty-state" style={{padding:'40px'}}>
          <div className="empty-icon">📄</div>
          <h3>No Reports</h3>
          <p>Reports are generated automatically when a scan completes.</p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead><tr><th>Format</th><th>Size</th><th>Date</th><th>Download</th></tr></thead>
            <tbody>
              {reports.map((r: any) => (
                <tr key={r.id}>
                  <td><span className="badge badge-info">{r.format.toUpperCase()}</span></td>
                  <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{r.file_size ? `${(r.file_size / 1024).toFixed(1)} KB` : '-'}</td>
                  <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{new Date(r.created_at).toLocaleString()}</td>
                  <td>
                    <a href={`/api/reports/${r.id}/download`} className="btn btn-sm btn-primary" download>Download</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ScanDetailPage;
