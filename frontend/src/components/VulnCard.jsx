import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Copy, Check, Shield, ShieldAlert } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import SeverityBadge from './SeverityBadge.jsx';

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1 text-xs text-slate-500 hover:text-accent transition-colors px-2 py-1 rounded"
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-low" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function extractField(content, fieldName) {
  const patterns = [
    new RegExp(`\\*\\*${fieldName}:\\*\\*\\s*([^\\n]+)`, 'i'),
    new RegExp(`${fieldName}:\\s*([^\\n]+)`, 'i'),
  ];
  for (const p of patterns) {
    const m = content.match(p);
    if (m) return m[1].trim();
  }
  return null;
}

function extractCodeBlock(content, afterField) {
  // Find the field, then grab the next code block
  const fieldIdx = content.toLowerCase().indexOf(afterField.toLowerCase());
  if (fieldIdx === -1) return null;
  const after = content.slice(fieldIdx);
  const m = after.match(/```[^\n]*\n([\s\S]*?)```/);
  return m ? m[1].trim() : null;
}

export default function VulnCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false);

  const { severity, type, location, code_snippet, verification, full_content, number } = vuln;

  const cwe = extractField(full_content || '', 'CWE');
  const owasp = extractField(full_content || '', 'OWASP 2021') || extractField(full_content || '', 'OWASP');
  const attackVector = extractField(full_content || '', 'Attack Vector');
  const poc = extractField(full_content || '', 'POC');
  const impact = extractField(full_content || '', 'Impact');
  const fixCode = extractCodeBlock(full_content || '', '**Fix:**');
  const confidence = extractField(full_content || '', 'Confidence');

  const isVerified = verification?.verdict === 'TRUE POSITIVE';
  const isFalsePositive = verification?.verdict === 'FALSE POSITIVE';

  const severityBorderColor = {
    Critical: 'border-l-critical',
    High: 'border-l-high',
    Medium: 'border-l-medium',
    Low: 'border-l-low',
    Info: 'border-l-slate-500',
  }[severity] || 'border-l-slate-500';

  return (
    <div className={`bg-surface border border-border border-l-4 ${severityBorderColor} rounded-lg overflow-hidden animate-fade-in`}>
      {/* Header */}
      <button
        className="w-full flex items-center gap-3 p-4 hover:bg-panel/50 transition-colors text-left"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="shrink-0">
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-slate-500" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-500" />
          )}
        </div>

        <SeverityBadge severity={severity} />

        <span className="text-slate-200 font-medium flex-1 text-sm leading-snug">
          #{number || index + 1} — {type}
        </span>

        <div className="flex items-center gap-2 shrink-0">
          {location && location !== 'Unknown' && (
            <span className="text-xs text-slate-500 font-mono">Line {location}</span>
          )}

          {verification && (
            <span
              className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${
                isVerified
                  ? 'bg-low/10 text-low border border-low/30'
                  : isFalsePositive
                  ? 'bg-slate-500/10 text-slate-400 border border-slate-500/30'
                  : 'bg-medium/10 text-medium border border-medium/30'
              }`}
            >
              {isVerified ? (
                <><ShieldAlert className="w-3 h-3" /> Verified</>
              ) : isFalsePositive ? (
                <><Shield className="w-3 h-3" /> FP</>
              ) : (
                'Uncertain'
              )}
            </span>
          )}
        </div>
      </button>

      {/* Expanded body */}
      {expanded && (
        <div className="border-t border-border">
          {/* Code snippet */}
          {code_snippet && (
            <div className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-slate-500 font-mono uppercase tracking-wide">Vulnerable Code</span>
                <CopyButton text={code_snippet} />
              </div>
              <SyntaxHighlighter
                language="text"
                style={vscDarkPlus}
                customStyle={{
                  background: '#0d0d0d',
                  border: '1px solid #2a2a2a',
                  borderRadius: '8px',
                  fontSize: '0.8125rem',
                  margin: 0,
                  padding: '12px 16px',
                }}
                wrapLongLines
              >
                {code_snippet}
              </SyntaxHighlighter>
            </div>
          )}

          {/* Details grid */}
          <div className="px-4 pb-2 grid grid-cols-1 gap-3">
            {cwe && (
              <InfoRow label="CWE" value={cwe} />
            )}
            {owasp && (
              <InfoRow label="OWASP 2021" value={owasp} />
            )}
            {confidence && (
              <InfoRow label="Confidence" value={confidence} />
            )}
            {attackVector && (
              <InfoRow label="Attack Vector" value={attackVector} />
            )}
            {poc && (
              <InfoRow label="POC" value={poc} mono />
            )}
            {impact && (
              <InfoRow label="Impact" value={impact} />
            )}
          </div>

          {/* Fix */}
          {fixCode && (
            <div className="px-4 pb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-low font-mono uppercase tracking-wide">Recommended Fix</span>
                <CopyButton text={fixCode} />
              </div>
              <SyntaxHighlighter
                language="text"
                style={vscDarkPlus}
                customStyle={{
                  background: '#0d1a0d',
                  border: '1px solid rgba(46,213,115,0.2)',
                  borderRadius: '8px',
                  fontSize: '0.8125rem',
                  margin: 0,
                  padding: '12px 16px',
                }}
                wrapLongLines
              >
                {fixCode}
              </SyntaxHighlighter>
            </div>
          )}

          {/* Verification details */}
          {verification && (
            <div className={`mx-4 mb-4 p-3 rounded-lg border text-sm ${
              isVerified
                ? 'bg-low/5 border-low/20'
                : isFalsePositive
                ? 'bg-slate-500/5 border-slate-500/20'
                : 'bg-medium/5 border-medium/20'
            }`}>
              <div className="flex items-center gap-2 mb-1">
                <span className={`font-semibold text-xs uppercase tracking-wide ${
                  isVerified ? 'text-low' : isFalsePositive ? 'text-slate-400' : 'text-medium'
                }`}>
                  {verification.verdict}
                </span>
                <span className="text-slate-500 text-xs">
                  {verification.confidence}% confidence
                </span>
              </div>
              {verification.explanation && (
                <p className="text-slate-400 text-xs leading-relaxed">{verification.explanation}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function InfoRow({ label, value, mono = false }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-slate-500 font-medium shrink-0 w-28 pt-0.5">{label}</span>
      <span className={`text-xs text-slate-300 leading-relaxed ${mono ? 'font-mono bg-panel px-2 py-0.5 rounded' : ''}`}>
        {value}
      </span>
    </div>
  );
}
