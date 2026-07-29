import React from 'react';
import { Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ScanProgressPage from './pages/ScanProgressPage';
import ScanResultsPage from './pages/ScanResultsPage';
import HistoryPage from './pages/HistoryPage';

const NavBar: React.FC = () => {
  const location = useLocation();
  const isActive = (p: string) => location.pathname === p || location.pathname.startsWith(p + '/');

  return (
    <nav className="navbar">
      <div className="nav-inner">
        <Link to="/" className="nav-brand">
          <svg width="28" height="28" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="8" fill="#00d4aa"/>
            <path d="M20 8L28 14V26L20 32L12 26V14L20 8Z" fill="#0a1628" stroke="#00d4aa" strokeWidth="1.5"/>
            <path d="M20 14L24 17V23L20 26L16 23V17L20 14Z" fill="#00d4aa"/>
          </svg>
          <span className="brand-text">SEA Scanner</span>
        </Link>
        <div className="nav-links">
          <Link to="/" className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}>New Scan</Link>
          <Link to="/history" className={`nav-link ${isActive('/history') ? 'active' : ''}`}>History</Link>
        </div>
      </div>
    </nav>
  );
};

const App: React.FC = () => (
  <>
    <NavBar />
    <main className="app-main">
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan/:id" element={<ScanProgressPage />} />
        <Route path="/results/:id" element={<ScanResultsPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </main>
  </>
);

export default App;
