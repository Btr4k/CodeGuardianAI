import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, File, AlertTriangle, ChevronRight } from 'lucide-react';
import SeverityBadge from './SeverityBadge.jsx';

function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export default function ScanHistory({ scans = [], onSelect }) {
  const navigate = useNavigate();

  if (!scans.length) {
    return (
      <div className="card text-center py-10">
        <Clock className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-slate-500 text-sm">No scans yet. Run your first scan.</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {scans.map((scan) => {
        const hasCritical = scan.critical > 0;
        const hasHigh = scan.high > 0;
        const hasMedium = scan.medium > 0;
        const hasLow = scan.low > 0;
        const clean = scan.total_vulns === 0;

        return (
          <button
            key={scan.scan_id}
            onClick={() => onSelect ? onSelect(scan.scan_id) : navigate(`/scan?id=${scan.scan_id}`)}
            className="w-full card hover:border-accent/50 transition-all duration-200 text-left group"
          >
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-panel flex items-center justify-center shrink-0">
                <File className="w-4 h-4 text-slate-500 group-hover:text-accent transition-colors" />
              </div>

              <div className="flex-1 min-w-0">
                <div className="text-slate-200 font-medium text-sm truncate">{scan.filename}</div>
                <div className="flex items-center gap-2 mt-0.5">
                  <Clock className="w-3 h-3 text-slate-600 shrink-0" />
                  <span className="text-xs text-slate-600 font-mono">{formatDate(scan.timestamp)}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {clean ? (
                  <span className="text-xs text-low font-medium px-2 py-0.5 rounded-full bg-low/10 border border-low/20">
                    Clean
                  </span>
                ) : (
                  <div className="flex items-center gap-1.5">
                    {hasCritical && (
                      <div className="flex items-center gap-1">
                        <SeverityBadge severity="Critical" showDot={false} />
                        <span className="text-xs font-mono text-critical">{scan.critical}</span>
                      </div>
                    )}
                    {hasHigh && (
                      <div className="flex items-center gap-1">
                        <SeverityBadge severity="High" showDot={false} />
                        <span className="text-xs font-mono text-high">{scan.high}</span>
                      </div>
                    )}
                    {hasMedium && !hasCritical && !hasHigh && (
                      <div className="flex items-center gap-1">
                        <SeverityBadge severity="Medium" showDot={false} />
                        <span className="text-xs font-mono text-medium">{scan.medium}</span>
                      </div>
                    )}
                    {hasLow && !hasCritical && !hasHigh && !hasMedium && (
                      <div className="flex items-center gap-1">
                        <SeverityBadge severity="Low" showDot={false} />
                        <span className="text-xs font-mono text-low">{scan.low}</span>
                      </div>
                    )}
                  </div>
                )}
                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-accent transition-colors" />
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
