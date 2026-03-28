import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ScanLine, Shield, AlertTriangle, Bug, Info, TrendingUp, RefreshCw } from 'lucide-react';
import Layout from '../components/Layout.jsx';
import ScanHistory from '../components/ScanHistory.jsx';
import { getHistory, getScan } from '../api/client.js';

function StatCard({ label, value, icon, colorClass }) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${colorClass}`}>
        {icon}
      </div>
      <div>
        <div className="text-2xl font-bold font-mono text-slate-100">{value}</div>
        <div className="text-xs text-slate-500 mt-0.5">{label}</div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const loadHistory = async (showRefreshing = false) => {
    if (showRefreshing) setRefreshing(true);
    try {
      const data = await getHistory();
      setScans(data);
    } catch (e) {
      console.error('Failed to load history', e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  // Aggregate stats
  const totals = scans.reduce(
    (acc, s) => {
      acc.scans += 1;
      acc.critical += s.critical || 0;
      acc.high += s.high || 0;
      acc.medium += s.medium || 0;
      acc.low += s.low || 0;
      return acc;
    },
    { scans: 0, critical: 0, high: 0, medium: 0, low: 0 }
  );

  const handleSelectScan = async (scanId) => {
    navigate(`/scan?id=${scanId}`);
  };

  return (
    <Layout
      title="Dashboard"
      subtitle="Overview of your security scan history"
    >
      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-6">
        <StatCard
          label="Total Scans"
          value={totals.scans}
          icon={<ScanLine className="w-5 h-5 text-accent" />}
          colorClass="bg-accent/10"
        />
        <StatCard
          label="Critical"
          value={totals.critical}
          icon={<AlertTriangle className="w-5 h-5 text-critical" />}
          colorClass="bg-critical/10"
        />
        <StatCard
          label="High"
          value={totals.high}
          icon={<Bug className="w-5 h-5 text-high" />}
          colorClass="bg-high/10"
        />
        <StatCard
          label="Medium"
          value={totals.medium}
          icon={<TrendingUp className="w-5 h-5 text-medium" />}
          colorClass="bg-medium/10"
        />
        <StatCard
          label="Low"
          value={totals.low}
          icon={<Info className="w-5 h-5 text-low" />}
          colorClass="bg-low/10"
        />
      </div>

      {/* Quick scan CTA */}
      <div className="card border-accent/20 bg-accent/5 flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-accent" />
          <div>
            <div className="font-semibold text-slate-200 text-sm">Ready to scan?</div>
            <div className="text-xs text-slate-500">Upload or paste code to run an AI-powered security analysis.</div>
          </div>
        </div>
        <button
          onClick={() => navigate('/scan')}
          className="btn-primary shrink-0"
        >
          <ScanLine className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* History */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-300">Recent Scans</h2>
          <button
            onClick={() => loadHistory(true)}
            disabled={refreshing}
            className="btn-ghost text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="card text-center py-10">
            <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            <p className="text-slate-500 text-sm">Loading history...</p>
          </div>
        ) : (
          <ScanHistory scans={scans} onSelect={handleSelectScan} />
        )}
      </div>
    </Layout>
  );
}
