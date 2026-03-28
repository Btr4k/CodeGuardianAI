import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ScanLine, Play, RotateCcw, Zap } from 'lucide-react';
import Layout from '../components/Layout.jsx';
import UploadZone from '../components/UploadZone.jsx';
import ScanConfig from '../components/ScanConfig.jsx';
import ScanProgress from '../components/ScanProgress.jsx';
import ResultsPanel from '../components/ResultsPanel.jsx';
import { runScan, getScan, createScanWebSocket } from '../api/client.js';

const DEFAULT_CONFIG = {
  apiType: 'openai',
  confidence: 'Medium',
  verify: true,
  query: '',
};

export default function Scan() {
  const [searchParams] = useSearchParams();
  const existingScanId = searchParams.get('id');

  const [fileData, setFileData] = useState({ code: '', filename: '' });
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [scanning, setScanning] = useState(false);
  const [wsEvents, setWsEvents] = useState([]);
  const [progress, setProgress] = useState(0);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState('');
  const [useWebSocket, setUseWebSocket] = useState(true);

  // Load existing scan if ID provided in URL
  useEffect(() => {
    if (existingScanId) {
      getScan(existingScanId)
        .then((data) => setScanResult(data))
        .catch(() => setError('Failed to load scan result.'));
    }
  }, [existingScanId]);

  const resetScan = useCallback(() => {
    setScanResult(null);
    setWsEvents([]);
    setProgress(0);
    setError('');
    setScanning(false);
  }, []);

  const runWithWebSocket = useCallback(() => {
    setScanning(true);
    setWsEvents([]);
    setProgress(0);
    setError('');
    setScanResult(null);

    const payload = {
      code: fileData.code,
      filename: fileData.filename || 'code.txt',
      api_type: config.apiType,
      confidence: config.confidence,
      verify: config.verify,
      query: config.query,
    };

    const ws = createScanWebSocket(payload, (evt) => {
      if (evt.event === 'error') {
        setError(evt.message || 'Scan failed');
        setScanning(false);
        return;
      }
      if (evt.event === 'closed') {
        setScanning(false);
        return;
      }

      setWsEvents((prev) => [...prev, evt]);
      if (evt.progress !== undefined) setProgress(evt.progress);

      if (evt.event === 'complete') {
        setScanResult(evt.data);
        setScanning(false);
      }
    });
  }, [fileData, config]);

  const runWithRest = useCallback(async () => {
    setScanning(true);
    setError('');
    setScanResult(null);

    try {
      const result = await runScan({
        code: fileData.code,
        filename: fileData.filename || 'code.txt',
        api_type: config.apiType,
        confidence: config.confidence,
        verify: config.verify,
        query: config.query,
      });
      setScanResult(result);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed. Check your API key.');
    } finally {
      setScanning(false);
    }
  }, [fileData, config]);

  const handleScan = useCallback(() => {
    if (!fileData.code.trim()) {
      setError('Please upload or paste code before scanning.');
      return;
    }
    if (useWebSocket) {
      runWithWebSocket();
    } else {
      runWithRest();
    }
  }, [fileData.code, useWebSocket, runWithWebSocket, runWithRest]);

  const canScan = fileData.code.trim().length > 0 && !scanning;

  return (
    <Layout
      title="Security Scan"
      subtitle="Upload or paste code to run an AI-powered security analysis"
    >
      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left column — upload + config */}
        <div className="lg:col-span-1 space-y-4">
          {/* Upload */}
          <div className="card">
            <div className="flex items-center gap-2 mb-3 text-slate-300 font-semibold text-sm">
              <ScanLine className="w-4 h-4 text-accent" />
              Code Input
            </div>
            <UploadZone
              code={fileData.code}
              filename={fileData.filename}
              onChange={(data) => {
                setFileData(data);
                resetScan();
              }}
            />
          </div>

          {/* Config */}
          <ScanConfig config={config} onChange={setConfig} />

          {/* Mode toggle */}
          <div className="flex items-center justify-between px-1">
            <div className="flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-xs text-slate-500">Streaming mode</span>
            </div>
            <button
              onClick={() => setUseWebSocket(!useWebSocket)}
              className={`relative w-9 h-5 rounded-full transition-colors duration-200 ${
                useWebSocket ? 'bg-accent' : 'bg-panel border border-border'
              }`}
            >
              <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform duration-200 ${
                useWebSocket ? 'translate-x-4' : 'translate-x-0'
              }`} />
            </button>
          </div>

          {/* Scan button */}
          <button
            onClick={handleScan}
            disabled={!canScan}
            className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold transition-all duration-200
              ${canScan
                ? 'bg-accent text-bg hover:bg-opacity-90 shadow-lg shadow-accent/20'
                : 'bg-panel border border-border text-slate-600 cursor-not-allowed'
              }`}
          >
            {scanning ? (
              <>
                <div className="w-4 h-4 border-2 border-bg border-t-transparent rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Start Scan
              </>
            )}
          </button>

          {/* Reset */}
          {scanResult && (
            <button
              onClick={resetScan}
              className="w-full btn-secondary justify-center"
            >
              <RotateCcw className="w-4 h-4" />
              New Scan
            </button>
          )}
        </div>

        {/* Right column — progress + results */}
        <div className="lg:col-span-2 space-y-4">
          {/* Error */}
          {error && (
            <div className="card border-critical/30 bg-critical/5 text-critical text-sm">
              {error}
            </div>
          )}

          {/* Progress (WebSocket) */}
          {(scanning || wsEvents.length > 0) && useWebSocket && (
            <ScanProgress
              events={wsEvents}
              progress={progress}
              isRunning={scanning}
            />
          )}

          {/* REST scanning spinner */}
          {scanning && !useWebSocket && (
            <div className="card flex items-center gap-3">
              <div className="w-5 h-5 border-2 border-accent border-t-transparent rounded-full animate-spin shrink-0" />
              <span className="text-sm text-slate-400">
                Running security analysis... this may take 30-60 seconds.
              </span>
            </div>
          )}

          {/* Results */}
          {scanResult && <ResultsPanel scan={scanResult} />}

          {/* Empty state */}
          {!scanning && !scanResult && !error && wsEvents.length === 0 && (
            <div className="card text-center py-16 border-dashed">
              <div className="w-14 h-14 rounded-2xl bg-panel flex items-center justify-center mx-auto mb-4">
                <ScanLine className="w-7 h-7 text-slate-600" />
              </div>
              <p className="text-slate-500 font-medium mb-1">No scan results yet</p>
              <p className="text-slate-600 text-sm">Upload code and click Start Scan to begin.</p>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
