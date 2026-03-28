# 🛡️ CodeGuardianAI

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--3.5+-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![Deepseek](https://img.shields.io/badge/Deepseek-Chat-0066CC?style=flat-square)](https://www.deepseek.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Btr4k/CodeGuardianAI/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Btr4k/CodeGuardianAI/actions)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

**AI-powered security vulnerability scanner for source code.**
Upload your code → get a detailed, actionable security report in seconds.

</div>

---

## Overview

CodeGuardianAI is a Streamlit web application that uses **OpenAI** or **Deepseek** to automatically detect security vulnerabilities in your source code. It performs a multi-pass analysis, verifies findings to cut false positives, and delivers structured reports with severity ratings, CWE/OWASP classifications, proof-of-concept exploits, and fix suggestions.

---

## Features

| Feature | Details |
|---------|---------|
| **Multi-language support** | PHP, Python, JavaScript, Java, C++, C# |
| **Dual AI providers** | OpenAI (GPT-3.5/4) and Deepseek — switchable at runtime |
| **False-positive reduction** | Batch verification pass in a single API call |
| **Adjustable confidence** | Low / Medium / High threshold filter |
| **PHP deep analysis** | Dedicated multi-pass scanner with adversarial second opinion |
| **Directory scanning** | Upload a ZIP archive to scan an entire project |
| **Structured reports** | Severity · CWE · OWASP · PoC · Impact · Fix |
| **Export** | Download reports as `.txt` or `.json` |
| **Result caching** | 24-hour cache to avoid redundant API calls |
| **Scan history** | Per-file history across scans in the same session |
| **Auth gate** | Optional password protection via `APP_PASSWORD` env var |
| **CI pipeline** | GitHub Actions runs the test suite on every push |

---

## Severity Levels

| Badge | Level | Meaning |
|-------|-------|---------|
| 🔴 **Critical** | Direct compromise | Fix immediately — exploitable with no preconditions |
| 🟠 **High** | Significant impact | Fix soon — likely exploitable under common conditions |
| 🟡 **Medium** | Moderate impact | Plan to address — requires specific conditions to exploit |
| 🟢 **Low** | Limited impact | Fix when possible — minor risk or defence-in-depth issue |
| ℹ️ **Info** | Not a vulnerability | Informational note or best-practice suggestion |

---

## Quick Start

### 1 — Clone the repo

```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI
```

### 2 — Create a virtual environment and install dependencies

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

### 3 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your keys:

```env
OPENAI_API_KEY=sk-...          # Required if using OpenAI
DEEPSEEK_API_KEY=sk-...        # Required if using Deepseek
```

> You only need **one** API key. Leave the other as the placeholder.

### 4 — Run the app

```bash
streamlit run app.py
```

The app opens at **http://localhost:8501** in your browser.

---

## Configuration Reference

All settings live in `.env`. Copy `.env.example` as a starting point.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | OpenAI API key |
| `DEEPSEEK_API_KEY` | — | Deepseek API key |
| `OPENAI_MODEL` | `gpt-3.5-turbo` | OpenAI model to use (e.g. `gpt-4o`) |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Deepseek model to use |
| `MAX_FILE_SIZE` | `102400` | Max upload size in bytes (default 100 KB) |
| `CACHE_DURATION` | `86400` | Cache TTL in seconds (default 24 h) |
| `APP_PASSWORD` | _(empty)_ | Enable login gate by setting a password |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `ERROR`) |

---

## How to Use

1. **Upload code** — use the sidebar to upload a single file or a `.zip` archive
2. **Choose provider** — select OpenAI or Deepseek from the sidebar
3. **Set confidence** — pick Low / Medium / High to control false-positive filtering
4. **Choose scan mode** — *Full Security Scan* or *Custom Query* (e.g. "check for SQL injection")
5. **Review results** — findings are grouped by severity with location, PoC, impact, and fix
6. **Export** — download the report as `.txt` or `.json`

---

## How It Works

```
Upload
  │
  ▼
Language detection (filename / content)
  │
  ├─► PHP  ──► Multi-pass AI analysis + deterministic regex checks
  │                └─► Adversarial second-opinion pass (if first pass says "secure")
  │
  └─► Other ──► Single AI analysis pass with language-specific prompt
                    │
                    ▼
              [Optional] Batch verification (1 API call)
              → filters findings below confidence threshold
                    │
                    ▼
              Structured report  →  Cache  →  Display  →  Export
```

---

## Supported File Types

| Language | Extensions |
|----------|------------|
| PHP | `.php` |
| Python | `.py` |
| JavaScript | `.js` |
| Java | `.java` |
| C++ | `.cpp` |
| C# | `.cs` |
| Plain text | `.txt` |

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

26 unit tests covering caching, language detection, vulnerability extraction, report generation, and batch verification.

---

## Project Structure

```
CodeGuardianAI/
├── app.py                  # Main application (all logic + UI)
├── setup.py                # Optional automated setup script
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── logging_config.json     # Logging configuration
├── logo.png                # App logo
├── tests/
│   └── test_app.py         # 26 unit tests
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI
├── cache/                  # Analysis cache (auto-created, git-ignored)
├── logs/                   # Log files (auto-created, git-ignored)
└── reports/                # Report output (auto-created, git-ignored)
```

---

## Security Notes

- API keys are loaded from `.env` — **never commit this file**
- The cache file is stored at `cache/analysis_cache.json` with `0600` permissions
- Error messages shown in the UI are sanitised — full details are written to the log only
- An optional login gate can be enabled via `APP_PASSWORD` in `.env`

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "feat: description"`
4. Push and open a Pull Request

Please ensure `pytest tests/` passes before submitting.

---

## License

MIT — see [LICENSE](LICENSE) for details.
