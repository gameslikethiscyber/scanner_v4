import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { api, ScanResultData, FindingData } from '../api';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff9800', medium: '#ffc107', low: '#4caf50',
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  info: 'Info', warning: 'Warning', pass: 'Pass', none: 'None',
};

const ScanResultsPage: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState<ScanResultData | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);

  useEffect(() => {
    if (!id) return;
    api.getScanResult(parseInt(id)).then((res) => {
      setData(res);
    }).catch(() => {
      navigate('/');
    }).finally(() => setLoading(false));
  }, [id, navigate]);

  if (loading) return <div className="progress-page"><div className="progress-card"><div className="spinner" /></div></div>;
  if (!data) return null;

  const { scan, findings, reports } = data;

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'warning', 'pass'];
  const filtered = severityFilter
    ? findings.filter((f) => f.severity === severityFilter)
    : findings;

  const sorted = [...filtered].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  const severityCounts: Record<string, number> = {};
  findings.forEach((f) => { severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1; });

  const riskColor = (scan.risk_score || 0) > 60 ? '#f44336' : (scan.risk_score || 0) > 30 ? '#ff9800' : '#4caf50';
  const riskLabel = (scan.risk_score || 0) > 60 ? 'High Risk' : (scan.risk_score || 0) > 30 ? 'Medium Risk' : 'Low Risk';

  const downloadReport = (reportId: number) => {
    window.open(api.reportDownloadUrl(reportId), '_blank');
  };

  return (
    <div className="results-page">
      <div className="results-header">
        <div>
          <Link to="/" className="back-link">← New Scan</Link>
          <h1>Scan Results</h1>
          <div className="results-meta">
            <span className="badge badge-completed">COMPLETED</span>
            <span className="result-url">{scan.target_url}</span>
            <span className="result-profile">Profile: {scan.profile}</span>
            <span className="result-duration">Duration: {scan.duration_seconds.toFixed(1)}s</span>
            <span className="result-date">{new Date(scan.created_at).toLocaleString()}</span>
          </div>
        </div>
        <div className="risk-gauge">
          <div className="gauge-value" style={{ color: riskColor }}>{scan.risk_score}%</div>
          <div className="gauge-label">{riskLabel}</div>
        </div>
      </div>

      <div className="severity-summary">
        {['critical', 'high', 'medium', 'low'].map((sev) => (
          <div key={sev} className="severity-card" style={{ borderTop: `3px solid ${SEVERITY_COLORS[sev]}` }}>
            <div className="sev-count" style={{ color: SEVERITY_COLORS[sev] }}>{severityCounts[sev] || 0}</div>
            <div className="sev-label">{SEVERITY_LABELS[sev]}</div>
          </div>
        ))}
        <div className="severity-card">
          <div className="sev-count" style={{ color: '#ff9800' }}>{scan.warning_count || 0}</div>
          <div className="sev-label">Warnings</div>
        </div>
        <div className="severity-card">
          <div className="sev-count" style={{ color: '#4caf50' }}>{scan.passed_count || 0}</div>
          <div className="sev-label">Passed</div>
        </div>
      </div>

      <div className="coverage-bar">
        <div className="coverage-label">Coverage: {scan.coverage_percentage}%</div>
        <div className="progress-track" style={{ flex: 1 }}>
          <div className="progress-fill" style={{ width: `${scan.coverage_percentage}%` }} />
        </div>
      </div>

      <div className="reports-section">
        <h2>Reports</h2>
        <div className="report-buttons">
          {reports.map((r) => (
            <button key={r.id} className="btn btn-secondary" onClick={() => downloadReport(r.id)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Download {r.format.toUpperCase()} ({(r.file_size / 1024).toFixed(1)} KB)
            </button>
          ))}
        </div>
      </div>

      <div className="findings-section">
        <div className="findings-header">
          <h2>Findings ({findings.length})</h2>
          <div className="filter-group">
            {['', 'critical', 'high', 'medium', 'low', 'info', 'warning'].map((sev) => (
              <button
                key={sev}
                className={`filter-btn ${severityFilter === sev ? 'active' : ''}`}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev ? SEVERITY_LABELS[sev] : 'All'}
              </button>
            ))}
          </div>
        </div>

        {sorted.length === 0 ? (
          <div className="empty-findings">
            <div className="empty-icon">🛡️</div>
            <h3>No Findings</h3>
            <p>No vulnerabilities detected in this scan.</p>
          </div>
        ) : (
          <div className="findings-list">
            {sorted.map((f) => (
              <div key={f.id} className={`finding-card severity-${f.severity}`}>
                <div className="finding-header" onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}>
                  <div className="finding-sev">
                    <span className={`badge badge-${f.severity}`}>{f.severity.toUpperCase()}</span>
                  </div>
                  <div className="finding-info">
                    <div className="finding-title">{f.title || f.module}</div>
                    <div className="finding-meta">
                      <span className="finding-module">{f.module}</span>
                      <span className="finding-confidence">{f.confidence}% confidence</span>
                      <span className="finding-verification">{f.verification_status}</span>
                      {f.cvss_score > 0 && <span className="finding-cvss">CVSS {f.cvss_score}</span>}
                    </div>
                  </div>
                  <div className="finding-expand">{expandedFinding === f.id ? '−' : '+'}</div>
                </div>

                {expandedFinding === f.id && (
                  <div className="finding-body">
                    {f.description && <p className="finding-desc">{f.description}</p>}
                    {f.cwe_id && <div className="finding-tag"><strong>CWE:</strong> {f.cwe_id}</div>}
                    {f.owasp_category && <div className="finding-tag"><strong>OWASP:</strong> {f.owasp_category}</div>}
                    {f.affected_url && <div className="finding-tag"><strong>URL:</strong> {f.affected_url}</div>}

                    {f.remediation_steps && f.remediation_steps.length > 0 && (
                      <div className="finding-section">
                        <h4>Remediation</h4>
                        <ul>{f.remediation_steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
                      </div>
                    )}

                    {f.recommendation && (
                      <div className="finding-section">
                        <h4>Recommendation</h4>
                        <p>{f.recommendation}</p>
                      </div>
                    )}

                    {f.evidence && f.evidence.length > 0 && (
                      <div className="finding-section">
                        <h4>Evidence</h4>
                        <div className="evidence-list">
                          {f.evidence.slice(0, 5).map((ev: any, i: number) => (
                            <div key={i} className="evidence-item">
                              {ev.description && <div className="ev-desc">{ev.description}</div>}
                              {ev.payload && <div className="ev-payload">Payload: <code>{ev.payload}</code></div>}
                              {ev.parameter && <div className="ev-param">Parameter: {ev.parameter}</div>}
                              {typeof ev === 'string' && <div>{ev}</div>}
                            </div>
                          ))}
                          {f.evidence.length > 5 && <div className="ev-more">+{f.evidence.length - 5} more evidence items</div>}
                        </div>
                      </div>
                    )}

                    {f.scanner_data?.verify_commands && f.scanner_data.verify_commands.length > 0 && (
                      <div className="finding-section">
                        <h4>Verification Commands</h4>
                        {f.scanner_data.verify_commands.map((cmd: string, i: number) => (
                          <pre key={i} className="verify-cmd"><code>{cmd}</code></pre>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanResultsPage;
