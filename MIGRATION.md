# CodeGuardianAI — Migration Guide (Streamlit → FastAPI + React)

## What changed

The original Streamlit app (`app.py`) is preserved as-is. This migration adds a production-grade web stack alongside it:

- **`backend/`** — FastAPI REST + WebSocket API (all security logic extracted from `app.py`)
- **`frontend/`** — React + Vite + Tailwind CSS UI for penetration testers

---

## Running locally (development)

### 1. Prerequisites

- Python 3.11+
- Node.js 20+
- An `.env` file at the project root with your API keys

```bash
# /root/CodeGuardianAI/.env
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=...

# Optional — enables password gate
APP_PASSWORD=your_secret_password

# Optional — override models
OPENAI_MODEL=gpt-4o
DEEPSEEK_MODEL=deepseek-chat
```

### 2. Backend

```bash
cd /root/CodeGuardianAI

# Create venv (or reuse existing)
python -m venv venv
source venv/bin/activate

pip install -r backend/requirements.txt

# Start the API server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

API is available at: `http://localhost:8000`
Swagger docs: `http://localhost:8000/docs`
Health check: `http://localhost:8000/health`

### 3. Frontend

```bash
cd /root/CodeGuardianAI/frontend

npm install
npm run dev
```

UI is available at: `http://localhost:3000`

---

## Running with Docker Compose (production)

```bash
cd /root/CodeGuardianAI

# Copy and fill your .env
cp .env.example .env  # or create .env manually

# Build and start both services
docker-compose up --build -d

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend
```

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:3000`

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENAI_API_KEY` | Yes (for OpenAI) | — | OpenAI API key |
| `DEEPSEEK_API_KEY` | Yes (for DeepSeek) | — | DeepSeek API key |
| `APP_PASSWORD` | No | — | If set, enables password gate |
| `JWT_SECRET_KEY` | No | Random | JWT signing secret (set for persistence across restarts) |
| `TOKEN_EXPIRE_MINUTES` | No | 480 | JWT expiry (default 8 hours) |
| `OPENAI_MODEL` | No | `gpt-3.5-turbo` | OpenAI model to use |
| `DEEPSEEK_MODEL` | No | `deepseek-chat` | DeepSeek model to use |
| `CACHE_DURATION` | No | 86400 | Analysis cache TTL in seconds |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000,...` | Comma-separated CORS origins |

---

## API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Server health and config status |
| GET | `/api/auth/status` | No | Whether auth is required |
| POST | `/api/auth/login` | No | Login, returns JWT |
| POST | `/api/scan` | Yes | Run a security scan |
| GET | `/api/scan/{id}` | Yes | Get scan result by ID |
| GET | `/api/history` | Yes | List recent scans |
| POST | `/api/report/download` | Yes | Download TXT or JSON report |
| WS | `/ws/scan` | Yes | WebSocket streaming scan |

---

## WebSocket scan protocol

Send JSON after connecting:
```json
{
  "code": "...",
  "filename": "app.php",
  "api_type": "openai",
  "confidence": "Medium",
  "verify": true,
  "query": "",
  "token": "your-jwt-token"
}
```

Server emits progress events:
```json
{ "event": "detecting", "message": "Detecting language...", "progress": 5 }
{ "event": "analyzing", "message": "Running AI analysis (openai)...", "progress": 25 }
{ "event": "verifying", "message": "Verifying findings...", "progress": 75 }
{ "event": "complete", "message": "Scan complete", "progress": 100, "data": { ...scan_result } }
```

---

## Notes on backward compatibility

- `app.py` is NOT modified and remains fully functional — run it with `streamlit run app.py`
- All security logic (14 PHP checks, Python checks, JS checks, AI analysis) is extracted verbatim into `backend/core/`
- Scan results are stored in memory (restarting the backend clears history)
