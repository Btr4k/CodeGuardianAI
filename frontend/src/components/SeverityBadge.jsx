import React from 'react';

const SEVERITY_CONFIG = {
  Critical: {
    bg: 'bg-critical/10',
    border: 'border-critical/30',
    text: 'text-critical',
    dot: 'bg-critical',
  },
  High: {
    bg: 'bg-high/10',
    border: 'border-high/30',
    text: 'text-high',
    dot: 'bg-high',
  },
  Medium: {
    bg: 'bg-medium/10',
    border: 'border-medium/30',
    text: 'text-medium',
    dot: 'bg-medium',
  },
  Low: {
    bg: 'bg-low/10',
    border: 'border-low/30',
    text: 'text-low',
    dot: 'bg-low',
  },
  Info: {
    bg: 'bg-slate-500/10',
    border: 'border-slate-500/30',
    text: 'text-slate-400',
    dot: 'bg-slate-400',
  },
};

export default function SeverityBadge({ severity, size = 'sm', showDot = true }) {
  const config = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.Info;
  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border font-mono font-semibold uppercase tracking-wide
        ${config.bg} ${config.border} ${config.text} ${sizeClasses}`}
    >
      {showDot && (
        <span className={`w-1.5 h-1.5 rounded-full ${config.dot} shrink-0`} />
      )}
      {severity}
    </span>
  );
}
