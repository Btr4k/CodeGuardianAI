import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, ScanLine, LogOut, Circle, Wifi, WifiOff } from 'lucide-react';
import { useAuth } from '../App.jsx';
import api from '../api/client.js';

function NavItem({ to, icon, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150
        ${isActive
          ? 'bg-accent/10 text-accent border border-accent/20'
          : 'text-slate-500 hover:text-slate-300 hover:bg-panel'
        }`
      }
    >
      {icon}
      {label}
    </NavLink>
  );
}

export default function Sidebar() {
  const { logout, authRequired } = useAuth();
  const navigate = useNavigate();
  const [serverStatus, setServerStatus] = useState(null); // null = checking

  useEffect(() => {
    const check = () =>
      api.get('/health')
        .then(() => setServerStatus('online'))
        .catch(() => setServerStatus('offline'));

    check();
    const interval = setInterval(check, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="w-56 bg-surface border-r border-border flex flex-col h-screen shrink-0">
      {/* Brand */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-accent/20 flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-accent" />
          </div>
          <div>
            <div className="text-sm font-bold text-slate-100 leading-none">CodeGuardian</div>
            <div className="text-xs text-accent font-mono leading-none mt-0.5">AI</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1">
        <NavItem
          to="/dashboard"
          icon={<LayoutDashboard className="w-4 h-4" />}
          label="Dashboard"
        />
        <NavItem
          to="/scan"
          icon={<ScanLine className="w-4 h-4" />}
          label="New Scan"
        />
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-border space-y-2">
        {/* Server status */}
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-panel">
          {serverStatus === null ? (
            <Circle className="w-3 h-3 text-slate-600 animate-pulse" />
          ) : serverStatus === 'online' ? (
            <Wifi className="w-3 h-3 text-low" />
          ) : (
            <WifiOff className="w-3 h-3 text-critical" />
          )}
          <span className={`text-xs font-mono ${
            serverStatus === 'online' ? 'text-low' :
            serverStatus === 'offline' ? 'text-critical' :
            'text-slate-600'
          }`}>
            {serverStatus === null ? 'Checking...' :
             serverStatus === 'online' ? 'API Online' : 'API Offline'}
          </span>
        </div>

        {/* Logout */}
        {authRequired && (
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-slate-500 hover:text-critical hover:bg-critical/5 transition-all"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        )}

        <div className="px-3 py-1">
          <span className="text-xs text-slate-700 font-mono">v2.3.0</span>
        </div>
      </div>
    </aside>
  );
}
