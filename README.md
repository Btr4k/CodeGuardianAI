# CodeGuardianAI

<div align="center">

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--3.5%2F4-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![Deepseek](https://img.shields.io/badge/Deepseek-Chat-0066CC?style=flat-square)](https://www.deepseek.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Btr4k/CodeGuardianAI/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Btr4k/CodeGuardianAI/actions)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

**AI-powered code security scanner built for penetration testers.**
Upload code → live scan progress → structured vulnerability report with CWE, OWASP, PoC, and fix.

</div>

---

## What it does

CodeGuardianAI performs a **multi-layer security analysis** on source code using two engines working in parallel:

- **AI analysis** — GPT-3.5/4 or Deepseek with OWASP Top 10 2021 prompt, taint analysis instructions, and per-language deep checklists
- **Deterministic checks** — regex-based pattern scanner with 29 hand-crafted rules (14 PHP + 8 Python + 7 JavaScript) that always run regardless of AI verdict

Findings are verified in a single batch API call to cut false positives, then delivered as severity-classified cards with location, code snippet, CWE, OWASP category, proof-of-concept exploit, impact, and remediation code.

---

## Features

| | Feature | Detail |
|---|---|---|
| 🔍 | **Multi-language** | PHP, Python, JavaScript, Java, C++, C# |
| 🤖 | **Dual AI providers** | OpenAI and Deepseek — toggle at runtime |
| ⚡ | **Deterministic engine** | 29 pattern rules always run — catches what AI misses |
| 🔄 | **Live scan streaming** | WebSocket — see progress stage by stage as it happens |
| 🎯 | **False-positive filter** | Batch verification pass, adjustable confidence threshold |
| 📁 | **Project scanning** | Upload a `.zip` to scan an entire codebase |
| 🔗 | **Shareable results** | Every scan gets a permanent URL (`/scan?id=...`) |
| 📊 | **Dashboard** | Scan history, severity stats, quick re-run |
| 📥 | **Export** | Download reports as `.txt` or `.json` |
| 🔐 | **Auth** | Optional JWT login gate via `APP_PASSWORD` env var |
| 💾 | **Caching** | 24-hour SHA-256 cache — no duplicate API calls |
| 🐳 | **Docker** | One command deployment with `docker-compose up` |

---

## Vulnerability Coverage

### Severity levels

| Badge | Level | Meaning |
|---|---|---|
| 🔴 Critical | Direct compromise | RCE, full auth bypass, critical data exposure — fix immediately |
| 🟠 High | Significant impact | SQLi, stored XSS, SSRF, deserialization — fix soon |
| 🟡 Medium | Moderate impact | Reflected XSS, open redirect, CSRF — plan to address |
| 🟢 Low | Limited impact | Missing headers, verbose errors — fix when possible |
| ℹ️ Info | Not a vulnerability | Best-practice note |

### Detection categories (OWASP Top 10 2021)

| Category | Examples |
|---|---|
| A01 Broken Access Control | IDOR, path traversal, open redirect |
| A02 Cryptographic Failures | MD5/SHA1 passwords, weak PRNG, hardcoded secrets |
| A03 Injection | SQL, command, code injection, SSTI, XSS |
| A04 Insecure Design | Race conditions, TOCTOU, mass assignment |
| A05 Misconfiguration | Debug mode, verbose errors |
| A07 Auth Failures | Session fixation, weak tokens |
| A08 Integrity Failures | Pickle/unserialize, YAML RCE, PHP object injection |
| A10 SSRF | User-controlled URL fetching |

---

## Quick Start

### Option A — Local development (recommended for first run)

**1. Clone**
```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI
```

**2. Configure environment**
```bash
cp .env.example .env
```
Edit `.env` — you only need one API key:
```env
OPENAI_API_KEY=sk-...          # Required if using OpenAI
DEEPSEEK_API_KEY=sk-...        # Required if using Deepseek
APP_PASSWORD=yourpassword      # Optional — enable login gate
JWT_SECRET_KEY=change-me-32chars  # Required for auth to work
```

**3. Start the backend**
```bash
cd CodeGuardianAI
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt

uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
Backend available at **http://localhost:8000** — API docs at **http://localhost:8000/docs**

**4. Start the frontend** (new terminal)
```bash
cd frontend
npm install
npm run dev
```
App available at **http://localhost:5173**

---

### Option B — Docker (one command)

```bash
cp .env.example .env   # fill in your API keys
docker-compose up -d
```

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

---

## How to Use

1. **Open the app** — log in with your `APP_PASSWORD` (or skip if not set)
2. **Go to Scan** — drag-drop or click to upload a file (`.php`, `.py`, `.js`, `.java`, `.cpp`, `.cs`, `.zip`)
3. **Configure** — choose OpenAI or Deepseek, set confidence threshold, optionally enter a focused query
4. **Run scan** — watch live progress via WebSocket as each stage completes
5. **Review results** — vulnerability cards show severity, location, code snippet, CWE, OWASP, PoC exploit, and fix
6. **Export** — download as `.txt` or `.json`, or share the scan URL

---

## How It Works

```
File upload
    │
    ▼
Language detection (filename extension → content fallback)
    │
    ├─► PHP ──► AI multi-pass analysis (+ adversarial second opinion if "secure")
    │           + 14 deterministic PHP checks (always run)
    │
    ├─► Python ──► AI analysis + 8 deterministic Python checks
    │
    ├─► JavaScript ──► AI analysis + 7 deterministic JS checks
    │
    └─► Java / C++ / C# ──► AI analysis
    │
    ▼
[Optional] Batch verification — single API call to confirm true positives
    │
    ▼
Structured report → Cache (24h) → WebSocket stream to browser → Export
```

---

## API Reference

The backend exposes a full REST API:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/api/auth/status` | Returns `auth_required` flag |
| `POST` | `/api/auth/login` | Login — returns JWT token |
| `POST` | `/api/scan` | Run a scan (multipart or JSON) |
| `GET` | `/api/scan/{id}` | Retrieve a scan result by ID |
| `GET` | `/api/history` | List recent scans |
| `POST` | `/api/report/download` | Generate TXT or JSON report |
| `WS` | `/ws/scan` | WebSocket — stream scan progress live |

Full interactive docs: **http://localhost:8000/docs**

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `DEEPSEEK_API_KEY` | — | Deepseek API key |
| `OPENAI_MODEL` | `gpt-3.5-turbo` | OpenAI model (`gpt-4o`, `gpt-4-turbo`, etc.) |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Deepseek model |
| `APP_PASSWORD` | _(empty)_ | Set to enable login gate |
| `JWT_SECRET_KEY` | — | Secret for signing JWT tokens (min 32 chars) |
| `CACHE_DURATION` | `86400` | Cache TTL in seconds (default 24 h) |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS allowed origins (comma-separated) |

---

## Project Structure

```
CodeGuardianAI/
├── backend/
│   ├── main.py               # FastAPI app — routes, WebSocket, scan pipeline
│   ├── auth.py               # JWT authentication
│   ├── models.py             # Pydantic request/response models
│   ├── requirements.txt
│   ├── Dockerfile
│   └── core/
│       ├── analyzer.py       # SecurityAnalyzer — AI prompts, language detection
│       ├── checks.py         # 29 deterministic rules (PHP + Python + JS)
│       ├── api_client.py     # APIClient (OpenAI/Deepseek), APIOptimizer (cache)
│       └── reports.py        # extract_vulnerabilities, verify_all, export
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Router + auth context
│   │   ├── api/client.js     # Axios API client with JWT
│   │   ├── pages/
│   │   │   ├── Login.jsx
│   │   │   ├── Dashboard.jsx # Stats + scan history
│   │   │   └── Scan.jsx      # Upload → progress → results
│   │   └── components/
│   │       ├── VulnCard.jsx       # Expandable vuln card with syntax highlighting
│   │       ├── ResultsPanel.jsx   # Severity filter + export
│   │       ├── ScanProgress.jsx   # Live WebSocket event feed
│   │       ├── UploadZone.jsx     # Drag-drop file upload
│   │       ├── ScanConfig.jsx     # Provider, confidence, query
│   │       └── ...
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.js
│   └── Dockerfile
│
├── app.py                    # Legacy Streamlit app (still works standalone)
├── docker-compose.yml
├── MIGRATION.md              # Detailed migration and deployment notes
├── tests/
│   └── test_app.py           # 26 unit tests
└── .github/workflows/ci.yml  # GitHub Actions CI
```

---

## Running Tests

```bash
source venv/bin/activate
pytest tests/ -v
```

26 tests covering: caching, language detection, vulnerability extraction, report generation, batch verification.

---

## Security Notes

- API keys are loaded from `.env` — **never commit this file** (it is `.gitignore`d)
- Cache is stored at `cache/analysis_cache.json` with `0600` permissions
- JWT tokens expire after 24 hours
- `APP_PASSWORD` and `JWT_SECRET_KEY` should be strong random values in production
- The old `app.py` (Streamlit) still works standalone — `streamlit run app.py`

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit: `git commit -m "feat: description"`
4. Push and open a Pull Request

Run `pytest tests/ -v` before submitting — CI will block failing PRs.

---

## License

MIT — see [LICENSE](LICENSE) for details.
