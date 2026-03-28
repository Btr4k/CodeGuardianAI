import React from 'react';
import { Zap, Brain, SlidersHorizontal, Search, ShieldCheck } from 'lucide-react';

const CONFIDENCE_OPTIONS = ['Low', 'Medium', 'High'];

export default function ScanConfig({ config, onChange }) {
  const { apiType, confidence, verify, query } = config;

  return (
    <div className="card space-y-5">
      <div className="flex items-center gap-2 text-slate-300 font-semibold text-sm">
        <SlidersHorizontal className="w-4 h-4 text-accent" />
        Scan Configuration
      </div>

      {/* API selector */}
      <div>
        <label className="label">AI Provider</label>
        <div className="flex gap-2">
          {[
            { id: 'openai', label: 'OpenAI', icon: <Brain className="w-4 h-4" />, desc: 'GPT-4 / GPT-3.5' },
            { id: 'deepseek', label: 'DeepSeek', icon: <Zap className="w-4 h-4" />, desc: 'DeepSeek Chat' },
          ].map(({ id, label, icon, desc }) => (
            <button
              key={id}
              onClick={() => onChange({ ...config, apiType: id })}
              className={`flex-1 flex items-center gap-3 p-3 rounded-lg border transition-all text-left
                ${apiType === id
                  ? 'border-accent bg-accent/10 text-accent'
                  : 'border-border bg-panel text-slate-400 hover:border-slate-500'
                }`}
            >
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                apiType === id ? 'bg-accent/20' : 'bg-surface'
              }`}>
                {icon}
              </div>
              <div>
                <div className="font-semibold text-sm">{label}</div>
                <div className="text-xs opacity-70">{desc}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Confidence threshold */}
      <div>
        <label className="label">Verification Confidence Threshold</label>
        <div className="flex gap-2">
          {CONFIDENCE_OPTIONS.map((opt) => (
            <button
              key={opt}
              onClick={() => onChange({ ...config, confidence: opt })}
              className={`flex-1 py-2 px-3 rounded-lg border text-sm font-medium transition-all
                ${confidence === opt
                  ? opt === 'Low'
                    ? 'border-low/40 bg-low/10 text-low'
                    : opt === 'Medium'
                    ? 'border-medium/40 bg-medium/10 text-medium'
                    : 'border-critical/40 bg-critical/10 text-critical'
                  : 'border-border bg-panel text-slate-400 hover:border-slate-500'
                }`}
            >
              {opt}
            </button>
          ))}
        </div>
        <p className="text-xs text-slate-600 mt-1.5">
          {confidence === 'Low' && 'Report all potential issues — may include false positives'}
          {confidence === 'Medium' && 'Balanced — filter low-confidence findings'}
          {confidence === 'High' && 'Strict — only high-confidence verified vulnerabilities'}
        </p>
      </div>

      {/* Verify toggle */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-slate-400" />
          <div>
            <div className="text-sm font-medium text-slate-300">AI Verification Pass</div>
            <div className="text-xs text-slate-600">Second AI call to confirm findings</div>
          </div>
        </div>
        <button
          onClick={() => onChange({ ...config, verify: !verify })}
          className={`relative w-11 h-6 rounded-full transition-colors duration-200 ${
            verify ? 'bg-accent' : 'bg-panel border border-border'
          }`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full shadow-sm transition-transform duration-200 ${
              verify ? 'translate-x-5' : 'translate-x-0'
            }`}
          />
        </button>
      </div>

      {/* Optional query */}
      <div>
        <label className="label">
          <div className="flex items-center gap-1.5">
            <Search className="w-3.5 h-3.5" />
            Focus Area (optional)
          </div>
        </label>
        <input
          type="text"
          value={query}
          onChange={(e) => onChange({ ...config, query: e.target.value })}
          placeholder="e.g. SQL injection, authentication, file upload..."
          className="input-field text-sm"
        />
      </div>
    </div>
  );
}
