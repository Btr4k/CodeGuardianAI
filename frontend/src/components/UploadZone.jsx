import React, { useCallback, useRef, useState } from 'react';
import { Upload, FileCode, X } from 'lucide-react';

const ACCEPTED_EXTENSIONS = ['.php', '.py', '.js', '.java', '.cpp', '.cs', '.ts', '.rb', '.go'];
const MAX_SIZE_KB = 200;

export default function UploadZone({ code, filename, onChange }) {
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef(null);

  const processFile = useCallback((file) => {
    setError('');
    if (!file) return;

    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      setError(`Unsupported file type. Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}`);
      return;
    }

    if (file.size > MAX_SIZE_KB * 1024) {
      setError(`File too large. Maximum size is ${MAX_SIZE_KB}KB.`);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      onChange({ code: e.target.result, filename: file.name });
    };
    reader.onerror = () => setError('Failed to read file.');
    reader.readAsText(file);
  }, [onChange]);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    processFile(file);
  }, [processFile]);

  const onDragOver = useCallback((e) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback(() => setDragging(false), []);

  const onFileInput = useCallback((e) => {
    processFile(e.target.files[0]);
    e.target.value = '';
  }, [processFile]);

  const clearFile = () => {
    onChange({ code: '', filename: '' });
    setError('');
  };

  const hasFile = !!code;

  return (
    <div className="space-y-3">
      {/* Drop zone */}
      <div
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => !hasFile && fileRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl transition-all duration-200 cursor-pointer
          ${dragging
            ? 'border-accent bg-accent/5 scale-[1.01]'
            : hasFile
            ? 'border-low/40 bg-low/5 cursor-default'
            : 'border-border hover:border-accent/50 hover:bg-panel/50 bg-surface'
          }`}
      >
        {hasFile ? (
          <div className="flex items-center gap-3 p-4">
            <div className="w-10 h-10 rounded-lg bg-low/10 flex items-center justify-center shrink-0">
              <FileCode className="w-5 h-5 text-low" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-slate-200 font-medium truncate">{filename}</div>
              <div className="text-xs text-slate-500 font-mono mt-0.5">
                {(code.length / 1024).toFixed(1)} KB · {code.split('\n').length} lines
              </div>
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); clearFile(); }}
              className="w-7 h-7 rounded-full bg-panel hover:bg-border flex items-center justify-center transition-colors shrink-0"
            >
              <X className="w-3.5 h-3.5 text-slate-400" />
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-10 px-4 text-center">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-3 transition-colors ${
              dragging ? 'bg-accent/20' : 'bg-panel'
            }`}>
              <Upload className={`w-6 h-6 transition-colors ${dragging ? 'text-accent' : 'text-slate-500'}`} />
            </div>
            <div className="text-slate-300 font-medium mb-1">
              {dragging ? 'Drop file here' : 'Drop your code file here'}
            </div>
            <div className="text-slate-500 text-sm mb-3">
              or click to browse
            </div>
            <div className="flex flex-wrap justify-center gap-1.5">
              {ACCEPTED_EXTENSIONS.map((ext) => (
                <span key={ext} className="text-xs font-mono text-slate-600 bg-panel px-2 py-0.5 rounded border border-border">
                  {ext}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Or paste code */}
      {!hasFile && (
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-border" />
          </div>
          <div className="relative flex justify-center">
            <span className="bg-bg px-3 text-xs text-slate-600">or paste code directly</span>
          </div>
        </div>
      )}

      {!hasFile && (
        <textarea
          className="input-field font-mono text-xs resize-none h-40"
          placeholder="// Paste your code here..."
          onChange={(e) => onChange({ code: e.target.value, filename: filename || 'pasted_code.txt' })}
        />
      )}

      {/* Error */}
      {error && (
        <div className="text-xs text-critical bg-critical/10 border border-critical/20 rounded-lg px-3 py-2">
          {error}
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        className="hidden"
        accept={ACCEPTED_EXTENSIONS.join(',')}
        onChange={onFileInput}
      />
    </div>
  );
}
