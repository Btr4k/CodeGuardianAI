import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 300000, // 5 minutes — scans can be slow
});

// Attach JWT token from localStorage on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('cg_token');
  if (token && token !== 'no-auth') {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-logout on 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('cg_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function checkAuthStatus() {
  try {
    const res = await api.get('/api/auth/status');
    return res.data.auth_required;
  } catch {
    return false;
  }
}

export async function login(password) {
  const res = await api.post('/api/auth/login', { password });
  return res.data;
}

// ── Scan ──────────────────────────────────────────────────────────────────────

export async function runScan(scanRequest) {
  const res = await api.post('/api/scan', scanRequest);
  return res.data;
}

export async function getScan(scanId) {
  const res = await api.get(`/api/scan/${scanId}`);
  return res.data;
}

// ── History ───────────────────────────────────────────────────────────────────

export async function getHistory() {
  const res = await api.get('/api/history');
  return res.data;
}

// ── Reports ───────────────────────────────────────────────────────────────────

export async function downloadReport(scanId, format = 'txt') {
  const res = await api.post(
    '/api/report/download',
    { scan_id: scanId, format },
    { responseType: 'blob' }
  );
  return res;
}

// ── WebSocket scan (streaming) ────────────────────────────────────────────────

export function createScanWebSocket(payload, onEvent) {
  const wsBase = import.meta.env.VITE_WS_URL || (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host;
  const ws = new WebSocket(`${wsBase}/ws/scan`);

  ws.onopen = () => {
    const token = localStorage.getItem('cg_token');
    ws.send(JSON.stringify({ ...payload, token: token !== 'no-auth' ? token : undefined }));
  };

  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      onEvent(data);
    } catch {
      // ignore parse errors
    }
  };

  ws.onerror = () => {
    onEvent({ event: 'error', message: 'WebSocket connection failed', progress: 0 });
  };

  ws.onclose = () => {
    onEvent({ event: 'closed', message: 'Connection closed', progress: 0 });
  };

  return ws;
}

export default api;
