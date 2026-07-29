import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ScanData } from '../api';

const HistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanData[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);

  useEffect(() => {
    setLoading(true);
    api.listScans(page).then(setScans).catch(() => {}).finally(() => setLoading(false));
  }, [page]);

  const fmt = (d: string) => {
    const dt = new Date(d);
    const diff = Date.now() - dt.getTime();
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    return dt.toLocaleDateString();
  };

  return (
    <div className="history-page">
      <div className="page-head">
        <h1>Scan History</h1>
        <button className="btn btn-primary" onClick={() => navigate('/')}>New Scan</button>
      </div>

      {loading ? (
        <div className="loading-wrap"><div className="spinner" /></div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <h3>No Scans Yet</h3>
          <p>Run your first scan to see results here.</p>
          <button className="btn btn-primary" onClick={() => navigate('/')} style={{marginTop:12}}>Start a Scan</button>
        </div>
      ) : (
        <div className="history-list">
          {scans.map((s) => (
            <div
              key={s.id}
              className={'history-item ' + s.status}
              onClick={() => navigate(s.status === 'completed' ? '/results/' + s.id : '/scan/' + s.id)}
            >
              <div className="history-main">
                <div className="history-url">{s.target_url}</div>
                <div className="history-sub">
                  <span className={'badge badge-' + s.status}>{s.status}</span>
                  <span>{s.profile}</span>
                  <span>{s.duration_seconds > 0 ? s.duration_seconds.toFixed(1) + 's' : '-'}</span>
                  <span className="history-date">{fmt(s.created_at)}</span>
                </div>
              </div>
              {s.status === 'completed' && (
                <div className="history-numbers">
                  <span className="sev-critical">{s.critical_count}</span>
                  <span className="sep">/</span>
                  <span className="sev-high">{s.high_count}</span>
                  <span className="sep">/</span>
                  <span className="sev-medium">{s.medium_count}</span>
                  <span className="sep">/</span>
                  <span className="sev-low">{s.low_count}</span>
                  <span className="history-risk">{s.risk_score + '%'}</span>
                </div>
              )}
              {s.status === 'running' && <span className="badge badge-running">Scanning...</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default HistoryPage;
