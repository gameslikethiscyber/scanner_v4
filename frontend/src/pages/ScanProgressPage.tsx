import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, ScanData } from '../api';

const ScanProgressPage: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanData | null>(null);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!id) return;
    const interval = setInterval(async () => {
      try {
        const data = await api.getScan(parseInt(id));
        setScan(data);
        if (data.status === 'completed') {
          clearInterval(interval);
          setTimeout(() => navigate(`/results/${id}`, { replace: true }), 800);
        } else if (data.status === 'failed') {
          clearInterval(interval);
        }
      } catch {
        clearInterval(interval);
      }
    }, 1500);
    return () => clearInterval(interval);
  }, [id, navigate]);

  useEffect(() => {
    const timer = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  if (!scan) {
    return (
      <div className="progress-page">
        <div className="progress-card"><div className="spinner" /><p style={{marginTop:'16px',color:'var(--text-muted)'}}>Loading scan...</p></div>
      </div>
    );
  }

  const progress = scan.progress || 0;
  const isError = scan.status === 'failed';

  const formatTime = (s: number) => {
    const mins = Math.floor(s / 60);
    const secs = s % 60;
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  };

  return (
    <div className="progress-page">
      <div className="progress-card">
        <div className="progress-header">
          <h1>{isError ? 'Scan Failed' : 'Scan in Progress'}</h1>
          <div className={`badge badge-${scan.status}`}>{scan.status.toUpperCase()}</div>
        </div>

        <div className="progress-target">{scan.target_url}</div>
        {scan.profile && <div className="progress-profile">Profile: {scan.profile}</div>}

        <div className="progress-bar-container">
          <div className="progress-track">
            <div className={`progress-fill ${isError ? 'danger' : ''}`} style={{ width: `${progress}%` }} />
          </div>
          <div className="progress-label">
            <span>{progress}%</span>
            <span>{scan.progress_message || 'Initializing...'}</span>
          </div>
        </div>

        {!isError && (
          <div className="progress-animation">
            <div className="scan-line" style={{ animationDelay: '0s' }} />
            <div className="scan-line" style={{ animationDelay: '0.3s' }} />
            <div className="scan-line" style={{ animationDelay: '0.6s' }} />
          </div>
        )}

        <div className="progress-info">
          <div className="info-item">
            <span className="info-label">Elapsed</span>
            <span className="info-value">{formatTime(elapsed)}</span>
          </div>
          <div className="info-item">
            <span className="info-label">Modules</span>
            <span className="info-value">18</span>
          </div>
        </div>

        {scan.error_message && (
          <div className="error-box">
            <strong>Error:</strong> {scan.error_message}
          </div>
        )}

        {isError && (
          <button className="btn btn-primary" onClick={() => navigate('/')} style={{marginTop:'16px'}}>
            Back to Home
          </button>
        )}
      </div>
    </div>
  );
};

export default ScanProgressPage;
