import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../api/client';

const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: '', username: '', password: '', full_name: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await api.post('/auth/register', form);
      navigate('/login');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && <div className="card" style={{background:'rgba(244,67,54,0.1)',borderColor:'var(--danger)',padding:'12px',marginBottom:'16px',fontSize:'13px',color:'var(--danger)'}}>{error}</div>}
      <div className="form-group">
        <label>Full Name</label>
        <input type="text" className="form-input" value={form.full_name} onChange={(e) => setForm({...form, full_name: e.target.value})} placeholder="Your name" />
      </div>
      <div className="form-group">
        <label>Username</label>
        <input type="text" className="form-input" value={form.username} onChange={(e) => setForm({...form, username: e.target.value})} placeholder="Choose a username" required />
      </div>
      <div className="form-group">
        <label>Email</label>
        <input type="email" className="form-input" value={form.email} onChange={(e) => setForm({...form, email: e.target.value})} placeholder="Enter your email" required />
      </div>
      <div className="form-group">
        <label>Password</label>
        <input type="password" className="form-input" value={form.password} onChange={(e) => setForm({...form, password: e.target.value})} placeholder="Min 8 characters" required minLength={8} />
      </div>
      <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
        {loading ? 'Creating account...' : 'Create Account'}
      </button>
      <p style={{textAlign:'center',marginTop:'16px',fontSize:'13px',color:'var(--text-muted)'}}>
        Already have an account? <Link to="/login">Sign In</Link>
      </p>
    </form>
  );
};

export default RegisterPage;
