const API = import.meta.env.VITE_API_URL || '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export interface ScanData {
  id: number; target_url: string; profile: string; status: string;
  progress: number; progress_message: string;
  risk_score: number | null; vulnerabilities_count: number;
  critical_count: number; high_count: number; medium_count: number; low_count: number;
  warning_count: number; info_count: number; passed_count: number;
  coverage_percentage: number; duration_seconds: number;
  error_message: string | null;
  started_at: string | null; completed_at: string | null; created_at: string;
}

export interface FindingData {
  id: number; scan_id: number; module: string; title: string; description: string;
  status: string; severity: string; confidence: number;
  evidence: any[]; impact: Record<string, any>;
  cvss_score: number; cvss_vector: string; cwe_id: string; owasp_category: string;
  recommendation: string; occurrences: number; affected_url: string;
  verification_status: string; remediation_steps: string[];
  created_at: string | null;
}

export interface ReportData {
  id: number; scan_id: number; format: string; file_path: string;
  file_size: number; created_at: string;
}

export interface ScanResultData {
  scan: ScanData;
  findings: FindingData[];
  reports: ReportData[];
}

export interface StatsData {
  total_scans: number; total_findings: number;
  vulnerabilities: Record<string, number>;
  recent_scans: ScanData[];
}

export const api = {
  // Health
  health: () => request<any>('/health'),

  // Stats
  stats: () => request<StatsData>('/stats'),

  // Scans
  listScans: (page = 1) => request<ScanData[]>(`/scans?page=${page}`),

  createScan: (target_url: string, profile = 'quick', label = '') =>
    request<ScanData>('/scans', {
      method: 'POST',
      body: JSON.stringify({ target_url, profile, label }),
    }),

  getScan: (id: number) => request<ScanData>(`/scans/${id}`),

  getScanResult: (id: number) => request<ScanResultData>(`/scans/${id}/result`),

  // Findings
  listFindings: (scanId?: number, severity?: string) => {
    let path = '/findings';
    const params = new URLSearchParams();
    if (scanId) params.set('scan_id', String(scanId));
    if (severity) params.set('severity', severity);
    const qs = params.toString();
    if (qs) path += `?${qs}`;
    return request<FindingData[]>(path);
  },

  // Reports
  listReports: (scanId?: number) =>
    request<ReportData[]>(`/reports${scanId ? `?scan_id=${scanId}` : ''}`),

  reportDownloadUrl: (reportId: number) => `${API}/reports/${reportId}/download`,

  // Targets
  listTargets: () => request<any[]>('/targets'),
};
