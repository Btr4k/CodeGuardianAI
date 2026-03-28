import React, { useState } from 'react';
import { Shield, AlertTriangle, Download, FileText, Filter } from 'lucide-react';
import VulnCard from './VulnCard.jsx';
import SeverityBadge from './SeverityBadge.jsx';
import { downloadReport } from '../api/client.js';

const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low'];

export default function ResultsPanel({ scan }) {
  const [filter, setFilter] = useState('All');
  const [downloading, setDownloading] = useState(null);

  if (!scan) return null;

  const { scan_id, vulnerabilities = [], analysis } = scan;
  const isSecure =
    !vulnerabilities.length ||
    analysis?.includes('[Secure]');

  const counts = vulnerabilities.reduce(
    (acc, v) => {
      const s = v.severity || 'Info';
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    },
    {}
  );

  const filtered =
    filter === 'All'
      ? vulnerabilities
      : vulnerabilities.filter((v) => v.severity === filter);

  const handleDownload = async (format) => {
    setDownloading(format);
    try {
      const res = await downloadReport(scan_id, format);
      const blob = new Blob([res.data], {
        type: format === 'json' ? 'application/json' : 'text/plain',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security_analysis_${scan_id.slice(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Download failed', e);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-4 animate-slide-up">
      {/* Summary bar */}
      <div className="card">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            {isSecure && !vulnerabilities.length ? (
              <div className="flex items-center gap-2 text-low">
                <Shield className="w-5 h-5" />
                <span className="font-semibold">No Vulnerabilities Found</span>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-high" />
                  <span className="font-semibold text-slate-200">
                    {vulnerabilities.length} Vulnerabilit{vulnerabilities.length === 1 ? 'y' : 'ies'}
                  </span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {['Critical', 'High', 'Medium', 'Low'].map((sev) =>
                    counts[sev] ? (
                      <div key={sev} className="flex items-center gap-1">
                        <SeverityBadge severity={sev} showDot />
                        <span className="text-slate-300 text-sm font-mono">{counts[sev]}</span>
                      </div>
                    ) : null
                  )}
                </div>
              </>
            )}
          </div>

          {/* Export buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleDownload('txt')}
              disabled={!!downloading}
              className="btn-secondary text-sm"
            >
              <FileText className="w-4 h-4" />
              {downloading === 'txt' ? 'Generating...' : 'TXT Report'}
            </button>
            <button
              onClick={() => handleDownload('json')}
              disabled={!!downloading}
              className="btn-secondary text-sm"
            >
              <Download className="w-4 h-4" />
              {downloading === 'json' ? 'Generating...' : 'JSON Report'}
            </button>
          </div>
        </div>
      </div>

      {/* Secure banner */}
      {isSecure && !vulnerabilities.length && (
        <div className="card border-low/30 bg-low/5">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-low/20 flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-low" />
            </div>
            <div>
              <div className="font-semibold text-low">Code Appears Secure</div>
              <div className="text-sm text-slate-400 mt-0.5">
                No exploitable vulnerabilities were detected in this scan.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter tabs */}
      {vulnerabilities.length > 0 && (
        <div className="flex items-center gap-1 bg-surface border border-border rounded-lg p-1">
          <Filter className="w-4 h-4 text-slate-500 ml-2 mr-1 shrink-0" />
          {SEVERITIES.map((sev) => {
            const count = sev === 'All' ? vulnerabilities.length : counts[sev] || 0;
            const isActive = filter === sev;
            return (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-all
                  ${isActive
                    ? 'bg-panel text-slate-200 shadow-sm'
                    : 'text-slate-500 hover:text-slate-300'
                  }`}
              >
                {sev}
                {count > 0 && (
                  <span className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${
                    isActive ? 'bg-border text-slate-300' : 'text-slate-600'
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      )}

      {/* Vuln list */}
      {filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map((vuln, i) => (
            <VulnCard key={`${vuln.number}-${i}`} vuln={vuln} index={i} />
          ))}
        </div>
      )}

      {vulnerabilities.length > 0 && filtered.length === 0 && (
        <div className="card text-center py-8 text-slate-500">
          No {filter} severity vulnerabilities found.
        </div>
      )}
    </div>
  );
}
