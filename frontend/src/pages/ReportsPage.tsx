import React from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import ReportList from './ScanDetailPage';

const ReportsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get('scan_id');
  return <ReportList scanId={scanId ? parseInt(scanId) : undefined} />;
};

export default ReportsPage;
