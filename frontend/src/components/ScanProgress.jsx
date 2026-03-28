import React from 'react';
import { Loader2, CheckCircle2, XCircle, Radio } from 'lucide-react';

const EVENT_LABELS = {
  detecting: 'Detecting language',
  detected: 'Language detected',
  analyzing: 'Running AI analysis',
  ai_complete: 'AI analysis complete',
  deterministic: 'Running pattern checks',
  verifying: 'Verifying findings',
  verified: 'Verification complete',
  complete: 'Scan complete',
  error: 'Error',
};

const EVENT_ICONS = {
  complete: <CheckCircle2 className="w-4 h-4 text-low" />,
  error: <XCircle className="w-4 h-4 text-critical" />,
};

export default function ScanProgress({ events = [], progress = 0, isRunning = false }) {
  if (events.length === 0 && !isRunning) return null;

  const lastEvent = events[events.length - 1];
  const isError = lastEvent?.event === 'error';
  const isComplete = lastEvent?.event === 'complete';

  return (
    <div className="card space-y-4">
      {/* Progress bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {isRunning && !isComplete && !isError && (
              <Loader2 className="w-4 h-4 text-accent animate-spin" />
            )}
            {isComplete && <CheckCircle2 className="w-4 h-4 text-low" />}
            {isError && <XCircle className="w-4 h-4 text-critical" />}
            <span className="text-sm font-medium text-slate-300">
              {isComplete ? 'Scan Complete' : isError ? 'Scan Failed' : 'Scanning...'}
            </span>
          </div>
          <span className="text-sm font-mono text-accent">{progress}%</span>
        </div>

        <div className="h-1.5 bg-panel rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              isError ? 'bg-critical' : isComplete ? 'bg-low' : 'bg-accent'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Live event feed */}
      <div className="space-y-1.5 max-h-40 overflow-y-auto">
        {events.map((evt, i) => {
          const isLast = i === events.length - 1;
          const icon = EVENT_ICONS[evt.event] || (
            isLast && isRunning ? (
              <Radio className="w-3.5 h-3.5 text-accent animate-pulse" />
            ) : (
              <div className="w-3.5 h-3.5 rounded-full bg-border" />
            )
          );

          return (
            <div
              key={i}
              className={`flex items-center gap-2 text-xs transition-opacity ${
                isLast ? 'opacity-100' : 'opacity-50'
              }`}
            >
              <div className="shrink-0">{icon}</div>
              <span className={`font-mono ${
                evt.event === 'error' ? 'text-critical' :
                isLast ? 'text-slate-300' : 'text-slate-500'
              }`}>
                {evt.message || EVENT_LABELS[evt.event] || evt.event}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
