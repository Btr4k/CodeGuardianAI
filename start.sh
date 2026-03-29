#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════╗
# ║           CodeGuardianAI — Quick Start               ║
# ║  Run this once and the app opens in your browser.    ║
# ╚══════════════════════════════════════════════════════╝
set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

print()  { echo -e "${CYAN}${BOLD}▶${RESET} $*"; }
ok()     { echo -e "${GREEN}${BOLD}✔${RESET} $*"; }
warn()   { echo -e "${YELLOW}${BOLD}⚠${RESET}  $*"; }
error()  { echo -e "${RED}${BOLD}✘${RESET}  $*"; exit 1; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║       CodeGuardianAI  Launcher        ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""

# ── 1. Python ────────────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$($cmd -c "import sys; print(sys.version_info >= (3,9))" 2>/dev/null)
        if [ "$VER" = "True" ]; then
            PYTHON=$cmd
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.9+ not found.\nInstall it from https://www.python.org/downloads/ and re-run this script."
fi
ok "Python found: $($PYTHON --version)"

# ── 2. Virtual environment ───────────────────────────────────────────────────
if [ ! -d "venv" ]; then
    print "Creating virtual environment..."
    $PYTHON -m venv venv
    ok "Virtual environment created."
fi

# Activate
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null

# ── 3. Dependencies ──────────────────────────────────────────────────────────
if ! python -c "import streamlit" &>/dev/null; then
    print "Installing dependencies (first run — takes ~1 minute)..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    ok "Dependencies installed."
else
    ok "Dependencies already installed."
fi

# ── 4. API keys (.env) ───────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    warn ".env file not found. Let's set it up."
    echo ""
    echo -e "  You need at least one AI API key to use CodeGuardianAI."
    echo -e "  Get your OpenAI key at: ${CYAN}https://platform.openai.com/api-keys${RESET}"
    echo -e "  Get your Deepseek key at: ${CYAN}https://platform.deepseek.com${RESET}"
    echo ""

    read -r -p "  Enter your OpenAI API key   (press Enter to skip): " OKEY
    read -r -p "  Enter your Deepseek API key (press Enter to skip): " DKEY

    if [ -z "$OKEY" ] && [ -z "$DKEY" ]; then
        warn "No API key entered. The app will start but won't be able to analyse code."
        warn "Edit the .env file later and add your key."
    fi

    cat > .env <<EOF
# ── API Keys ──────────────────────────────────────────
OPENAI_API_KEY=${OKEY}
DEEPSEEK_API_KEY=${DKEY}

# ── Optional ──────────────────────────────────────────
# APP_PASSWORD=your_password_here
OPENAI_MODEL=gpt-3.5-turbo
DEEPSEEK_MODEL=deepseek-chat
CACHE_DURATION=86400
EOF
    ok ".env file created."
else
    ok ".env file found."
fi

# ── 5. Create required directories ──────────────────────────────────────────
mkdir -p logs cache uploads reports

# ── 6. Launch ────────────────────────────────────────────────────────────────
echo ""
# Detect public IP for display
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  Local:   http://localhost:8501                  ${RESET}"
echo -e "${GREEN}${BOLD}  Network: http://${SERVER_IP}:8501               ${RESET}"
echo -e "${GREEN}${BOLD}  Press Ctrl+C to stop.                           ${RESET}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

streamlit run app.py \
    --server.headless true \
    --browser.gatherUsageStats false \
    --server.port 8501 \
    --server.address 0.0.0.0
