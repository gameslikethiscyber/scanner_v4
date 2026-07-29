import React, { useState, useEffect } from 'react';
import api from '../api/client';

const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    api.get('/settings').then((res) => {
      setSettings(res.data);
    }).catch(console.error).finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setMessage('');
    try {
      await api.put('/settings', settings);
      setMessage('Settings saved successfully');
    } catch (err: any) {
      setMessage(err.response?.data?.detail || 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div style={{textAlign:'center',padding:'60px'}}><div className="spinner" /></div>;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Settings</h1>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      {message && (
        <div className="card" style={{background:'rgba(76,175,80,0.1)',borderColor:'var(--success)',padding:'12px',marginBottom:'16px',fontSize:'13px',color:'var(--success)'}}>
          {message}
        </div>
      )}

      {settings && (
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'20px'}}>
          <div className="card">
            <div className="card-header"><h3 className="card-title">Notifications</h3></div>
            {['email_notifications','scan_completed_notify','scan_failed_notify','critical_finding_notify'].map((key) => (
              <div key={key} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'12px 0',borderBottom:'1px solid var(--border)'}}>
                <span style={{fontSize:'14px'}}>{key.replace(/_/g,' ').replace(/\b\w/g,(c:string)=>c.toUpperCase())}</span>
                <label style={{position:'relative',display:'inline-block',width:'44px',height:'24px'}}>
                  <input type="checkbox" checked={settings[key]} onChange={(e) => setSettings({...settings, [key]: e.target.checked})} style={{opacity:0,width:0,height:0}} />
                  <span style={{
                    position:'absolute',cursor:'pointer',top:0,left:0,right:0,bottom:0,
                    background: settings[key] ? 'var(--accent)' : 'var(--border)',
                    borderRadius:'24px',transition:'0.3s'
                  }}>
                    <span style={{
                      position:'absolute',height:'18px',width:'18px',left: settings[key] ? '22px' : '3px',
                      bottom:'3px',background:'white',borderRadius:'50%',transition:'0.3s'
                    }} />
                  </span>
                </label>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-header"><h3 className="card-title">Preferences</h3></div>
            <div className="form-group">
              <label>Theme</label>
              <select className="form-input" value={settings.theme} onChange={(e) => setSettings({...settings, theme: e.target.value})}>
                <option value="dark">Dark</option>
                <option value="light">Light</option>
                <option value="system">System</option>
              </select>
            </div>
            <div className="form-group">
              <label>Timezone</label>
              <select className="form-input" value={settings.timezone} onChange={(e) => setSettings({...settings, timezone: e.target.value})}>
                <option value="UTC">UTC</option>
                <option value="US/Eastern">US/Eastern</option>
                <option value="US/Pacific">US/Pacific</option>
                <option value="Europe/London">Europe/London</option>
                <option value="Europe/Berlin">Europe/Berlin</option>
                <option value="Asia/Tokyo">Asia/Tokyo</option>
              </select>
            </div>
            <div className="form-group">
              <label>Language</label>
              <select className="form-input" value={settings.language} onChange={(e) => setSettings({...settings, language: e.target.value})}>
                <option value="en">English</option>
              </select>
            </div>
            <div className="form-group">
              <label>Default Report Format</label>
              <select className="form-input" value={settings.default_report_format} onChange={(e) => setSettings({...settings, default_report_format: e.target.value})}>
                <option value="html">HTML</option>
                <option value="json">JSON</option>
                <option value="markdown">Markdown</option>
                <option value="csv">CSV</option>
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsPage;
