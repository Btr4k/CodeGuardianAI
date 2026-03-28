# CodeGuardianAI

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.55-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--3.5%2F4-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com)
[![Deepseek](https://img.shields.io/badge/Deepseek-Chat-0066CC?style=flat-square)](https://www.deepseek.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Btr4k/CodeGuardianAI/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Btr4k/CodeGuardianAI/actions)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

**AI-powered code security scanner — upload code, get a full vulnerability report in seconds.**

Combines a deterministic pattern engine (29 rules) with GPT/Deepseek AI analysis aligned to OWASP Top 10 2021. Every finding includes CWE, severity, proof-of-concept exploit, and a ready-to-use fix.

</div>

---

## Quick Start

Choose the method that works for you:

---

### Option 1 — One script (easiest)

**Linux / macOS**
```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI
chmod +x start.sh
./start.sh
```

**Windows** — double-click `start.bat`
*(or right-click → Run as administrator if you get a permission error)*

The script handles everything automatically:
- Checks your Python version
- Creates a virtual environment
- Installs all dependencies
- Asks for your API key (one time only)
- Opens the app at **http://localhost:8501**

---

### Option 2 — Docker (no Python needed)

```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI

# Create your config file
cp .env.example .env
# Open .env and add your API key(s)

docker compose up
```

App opens at **http://localhost:8501**

To stop: `docker compose down`

---

### Option 3 — Manual

```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI

# 1. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API keys
cp .env.example .env
# Edit .env — add at least one API key

# 4. Run
streamlit run app.py
```

---

## API Keys

You need **at least one** of these:

| Provider | Where to get it | Cost |
|---|---|---|
| **OpenAI** | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | Pay-per-use |
| **Deepseek** | [platform.deepseek.com](https://platform.deepseek.com) | Very cheap |

Add the key to your `.env` file:
```env
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
```

---

## How to Use

1. Open **http://localhost:8501** in your browser
2. **Upload** a code file (`.php`, `.py`, `.js`, `.java`, `.cpp`, `.cs`) or a `.zip` folder
3. **Choose** OpenAI or Deepseek and set your confidence threshold
4. Click **Run Analysis**
5. Review the results — each finding shows:
   - Severity badge (Critical / High / Medium / Low)
   - Exact line number and code snippet
   - CWE and OWASP 2021 category
   - Proof-of-concept exploit
   - Ready-to-use fix code
6. **Download** as `.txt` or `.json`

---

## What it Detects

### Coverage by language

| Language | Deterministic rules | AI analysis |
|---|---|---|
| PHP | 14 rules | ✅ + adversarial second opinion |
| Python | 8 rules | ✅ |
| JavaScript / Node.js | 7 rules | ✅ |
| Java | — | ✅ |
| C++ / C# | — | ✅ |

### Vulnerability categories (OWASP Top 10 2021)

| Category | Examples |
|---|---|
| A01 Broken Access Control | Path traversal, IDOR, open redirect |
| A02 Cryptographic Failures | MD5/SHA1 passwords, weak PRNG, hardcoded secrets |
| A03 Injection | SQL injection, command injection, XSS, SSTI |
| A04 Insecure Design | Race conditions, TOCTOU, mass assignment |
| A05 Misconfiguration | Debug mode, verbose errors, unsafe defaults |
| A07 Auth Failures | Session fixation, predictable tokens |
| A08 Integrity Failures | pickle/unserialize RCE, YAML injection, PHP object injection |
| A10 SSRF | User-controlled URL fetching |

### Severity guide

| Level | Meaning |
|---|---|
| 🔴 Critical | Fix immediately — RCE, full auth bypass, direct data loss |
| 🟠 High | Fix soon — SQL injection, stored XSS, SSRF, deserialization |
| 🟡 Medium | Plan to fix — reflected XSS, CSRF, open redirect |
| 🟢 Low | Fix when convenient — missing headers, verbose errors |
| ℹ️ Info | Best-practice note, not exploitable |

---

## Configuration Reference

All settings go in your `.env` file:

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | Your OpenAI API key |
| `DEEPSEEK_API_KEY` | — | Your Deepseek API key |
| `OPENAI_MODEL` | `gpt-3.5-turbo` | Model to use (`gpt-4o`, `gpt-4-turbo`, etc.) |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Deepseek model |
| `APP_PASSWORD` | _(none)_ | Set to password-protect the app |
| `CACHE_DURATION` | `86400` | How long to cache results (seconds) |

---

## How It Works

```
Upload file
    │
    ▼
Language detection  (filename extension → content fallback)
    │
    ├─► PHP ────► 14 deterministic checks  +  AI multi-pass  (+  adversarial 2nd opinion if "secure")
    │
    ├─► Python ─► 8 deterministic checks   +  AI analysis
    │
    ├─► JS ─────► 7 deterministic checks   +  AI analysis
    │
    └─► Java / C++ / C# ─────────────────────► AI analysis only
    │
    ▼
[Optional] Batch verification — single API call, filters false positives
    │
    ▼
Structured report → 24h cache → UI display → TXT / JSON export
```

---

## Project Structure

```
CodeGuardianAI/
├── app.py                    # Full application — all logic and UI
├── start.sh                  # One-click launcher (Linux/macOS)
├── start.bat                 # One-click launcher (Windows)
├── Dockerfile                # Docker image
├── docker-compose.yml        # Docker Compose setup
├── requirements.txt          # Python dependencies
├── .env.example              # Config template
├── logging_config.json       # Logging config
├── tests/
│   └── test_app.py           # 26 unit tests
└── .github/workflows/ci.yml  # GitHub Actions CI
```

---

## Running Tests

```bash
source venv/bin/activate      # Windows: venv\Scripts\activate
pytest tests/ -v
```

26 tests covering: caching, language detection, vulnerability extraction, report generation, batch verification.

---

## Security Notes

- API keys live in `.env` — **never commit this file** (it is in `.gitignore`)
- Analysis cache is stored with `0600` permissions (owner-only read/write)
- `APP_PASSWORD` is optional — set it if the app is exposed beyond localhost

---

## Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Make your changes and run `pytest tests/ -v`
4. Open a Pull Request — CI must pass

---

## License

MIT — see [LICENSE](LICENSE) for details.
