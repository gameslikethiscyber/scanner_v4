import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client';
import { useAuth } from '../contexts/AuthContext';

interface DashboardData {
  projects_count: number;
  scans_count: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  average_risk_score: number;
  recent_scans: any[];
  recent_findings: any[];
  security_trend: { date: string; score: number }[];
}

const DashboardPage: React.FC = () => {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const [projRes, scansRes] = await Promise.all([
          api.get('/projects?page_size=100'),
          api.get('/scans?page_size=10'),
        ]);
        const projects = projRes.data.items || [];
        const scans = scansRes.data.items || [];

        const totalVulns = scans.reduce((sum: number, s: any) => sum + (s.vulnerabilities_count || 0), 0);
        const critical = scans.reduce((sum: number, s: any) => sum + (s.critical_count || 0), 0);
        const high = scans.reduce((sum: number, s: any) => sum + (s.high_count || 0), 0);
        const medium = scans.reduce((sum: number, s: any) => sum + (s.medium_count || 0), 0);
        const low = scans.reduce((sum: number, s: any) => sum + (s.low_count || 0), 0);
        const scores = scans.filter((s: any) => s.risk_score != null).map((s: any) => s.risk_score);
        const avgScore = scores.length > 0 ? scores.reduce((a: number, b: number) => a + b, 0) / scores.length : 0;

        setData({
          projects_count: projects.length,
          scans_count: scans.length,
          total_vulnerabilities: totalVulns,
          critical_count: critical,
          high_count: high,
          medium_count: medium,
          low_count: low,
          average_risk_score: Math.round(avgScore),
          recent_scans: scans.slice(0, 5),
          recent_findings: [],
          security_trend: [],
        });
      } catch (err) {
        console.error('Dashboard fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchDashboard();
  }, []);

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;

  const stats = [
    { label: 'Projects', value: data?.projects_count || 0, icon: '📁', color: 'var(--accent)' },
    { label: 'Total Scans', value: data?.scans_count || 0, icon: '🔍', color: 'var(--info)' },
    { label: 'Vulnerabilities', value: data?.total_vulnerabilities || 0, icon: '⚠️', color: data && data.total_vulnerabilities > 0 ? 'var(--danger)' : 'var(--success)' },
    { label: 'Risk Score', value: `${data?.average_risk_score || 0}%`, icon: '🎯', color: (data?.average_risk_score || 0) > 50 ? 'var(--danger)' : (data?.average_risk_score || 0) > 20 ? 'var(--warning)' : 'var(--success)' },
  ];

  const severityCounts = [
    { label: 'Critical', count: data?.critical_count || 0, color: 'var(--critical)' },
    { label: 'High', count: data?.high_count || 0, color: 'var(--high)' },
    { label: 'Medium', count: data?.medium_count || 0, color: 'var(--medium)' },
    { label: 'Low', count: data?.low_count || 0, color: 'var(--low)' },
  ];

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
        <div className="page-actions">
          <Link to="/projects" className="btn btn-primary">New Scan</Link>
        </div>
      </div>

      <div className="stats-grid">
        {stats.map((s) => (
          <div className="stat-card" key={s.label}>
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
              <div className="stat-label">{s.label}</div>
              <span style={{fontSize:'24px'}}>{s.icon}</span>
            </div>
            <div className="stat-value" style={{color: s.color}}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px',marginBottom:'24px'}}>
        <div className="card">
          <div className="card-header"><h3 className="card-title">Severity Breakdown</h3></div>
          {severityCounts.map((s) => (
            <div key={s.label} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 0',borderBottom:'1px solid var(--border)'}}>
              <span style={{color: s.color,fontWeight:600,fontSize:'14px'}}>{s.label}</span>
              <span style={{fontWeight:700,fontSize:'16px'}}>{s.count}</span>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-header"><h3 className="card-title">Quick Actions</h3></div>
          <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
            <Link to="/projects" className="btn btn-secondary btn-block">Manage Projects</Link>
            <Link to="/scans" className="btn btn-secondary btn-block">View Scans</Link>
            <Link to="/reports" className="btn btn-secondary btn-block">View Reports</Link>
            <Link to="/api-keys" className="btn btn-secondary btn-block">API Keys</Link>
          </div>
        </div>
      </div>

      {data?.recent_scans && data.recent_scans.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Scans</h3>
            <Link to="/scans" className="btn btn-sm btn-secondary">View All</Link>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr><th>Target</th><th>Status</th><th>Risk</th><th>Vulns</th><th>Date</th></tr>
              </thead>
              <tbody>
                {data.recent_scans.map((scan: any) => (
                  <tr key={scan.id} onClick={() => window.location.href = `/scans/${scan.id}`} style={{cursor:'pointer'}}>
                    <td style={{maxWidth:'200px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{scan.target_url}</td>
                    <td><span className={`status-dot ${scan.status}`} />{scan.status}</td>
                    <td><span className={`badge badge-${scan.risk_score > 60 ? 'high' : scan.risk_score > 30 ? 'medium' : 'low'}`}>{scan.risk_score || 0}%</span></td>
                    <td>{scan.vulnerabilities_count || 0}</td>
                    <td style={{fontSize:'12px',color:'var(--text-muted)'}}>{scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default DashboardPage;
