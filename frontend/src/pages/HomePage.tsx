import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, StatsData } from '../api';

const PROFILES = [
  { id: 'quick', label: 'Quick Scan', desc: 'Core vulnerability checks — runs in under 30 seconds' },
  { id: 'full', label: 'Full Scan', desc: 'All 18 scanners — comprehensive assessment (2-5 minutes)' },
];

const HomePage: React.FC = () => {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl] = useState('');
  const [profile, setProfile] = useState('quick');
  const [label, setLabel] = useState('');
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [stats, setStats] = useState<StatsData | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.stats().then(setStats).catch(() => {});
    api.listScans().then(s => setRecentScans(s.slice(0, 5))).catch(() => {});
    inputRef.current?.focus();
  }, []);

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const url = targetUrl.trim();
    if (!url) { setError('Please enter a target URL'); return; }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      setError('URL must start with http:// or https://');
      return;
    }
    setError('');
    setRunning(true);
    try {
      const scan = await api.createScan(url, profile, label);
      navigate(`/scan/${scan.id}`);
    } catch (err: any) {
      setError(err.message || 'Failed to start scan');
      setRunning(false);
    }
  };

  const scanCount = stats ? Object.values(stats.vulnerabilities).reduce((a: number, b: number) => a + b, 0) : 0;

  return (
    <div className="home-page">
      <div className="hero">
        <div className="hero-badge">v2.0.0 — Professional Security Scanner</div>
        <h1 className="hero-title">Security Scanner</h1>
        <p className="hero-subtitle">
          Enterprise-grade vulnerability assessment powered by 18 specialized scanners
          with multi-pass verification, correlation analysis, and professional reporting.
        </p>
      </div>

      <div className="scan-card">
        <form onSubmit={handleStartScan}>
          <div className="input-group">
            <div className="input-wrapper">
              <span className="input-icon">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
              </span>
              <input
                ref={inputRef}
                type="text"
                className="url-input"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={running}
                autoFocus
              />
            </div>
            <button type="submit" className="btn-scan" disabled={running}>
              {running ? (
                <><span className="btn-spinner" /> Starting...</>
              ) : (
                <><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Scan</>
              )}
            </button>
          </div>

          {error && <div className="form-error">{error}</div>}

          <div className="profile-grid">
            {PROFILES.map((p) => (
              <label key={p.id} className={`profile-option ${profile === p.id ? 'selected' : ''}`}>
                <input type="radio" name="profile" value={p.id} checked={profile === p.id} onChange={() => setProfile(p.id)} />
                <div className="profile-content">
                  <div className="profile-name">{p.label}</div>
                  <div className="profile-desc">{p.desc}</div>
                </div>
                {profile === p.id && <div className="profile-check">✓</div>}
              </label>
            ))}
          </div>

          <details className="advanced-toggle">
            <summary>Advanced Options</summary>
            <div className="advanced-content">
              <label className="field-label">Scan Label (optional)</label>
              <input type="text" className="form-input" placeholder="e.g., Production deployment v3" value={label} onChange={(e) => setLabel(e.target.value)} />
            </div>
          </details>
        </form>
      </div>

      {stats && (
        <div className="stats-row">
          <div className="stat-chip"><span className="stat-num">{stats.total_scans}</span> Scans Run</div>
          <div className="stat-chip"><span className="stat-num">{stats.total_findings}</span> Total Findings</div>
          <div className="stat-chip"><span className="stat-num sev-critical">{stats.vulnerabilities.critical || 0}</span> Critical</div>
          <div className="stat-chip"><span className="stat-num sev-high">{stats.vulnerabilities.high || 0}</span> High</div>
          <div className="stat-chip"><span className="stat-num sev-medium">{stats.vulnerabilities.medium || 0}</span> Medium</div>
        </div>
      )}

      {recentScans.length > 0 && (
        <div className="recent-section">
          <h2 className="section-title">Recent Scans</h2>
          <div className="recent-list">
            {recentScans.map((s) => (
              <div key={s.id} className="recent-item" onClick={() => navigate(s.status === 'completed' ? `/results/${s.id}` : `/scan/${s.id}`)}>
                <div>
                  <div className="recent-url">{s.target_url}</div>
                  <div className="recent-meta">
                    <span className={`badge badge-${s.status}`}>{s.status}</span>
                    <span>{s.profile}</span>
                    <span>{new Date(s.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
                <div className="recent-stats">
                  {s.status === 'completed' && (
                    <>
                      <span className="sev-critical">{s.critical_count}</span>/
                      <span className="sev-high">{s.high_count}</span>/
                      <span className="sev-medium">{s.medium_count}</span>
                      <span className="recent-risk">{s.risk_score}%</span>
                    </>
                  )}
                  {s.status === 'running' && <span className="badge badge-running">Scanning...</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default HomePage;
