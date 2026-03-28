#!/usr/bin/env python3
"""
CodeGuardianAI CLI Scanner
Usage:
  python scan_cli.py <file>                    # AI + deterministic scan
  python scan_cli.py <file> --api deepseek     # use Deepseek
  python scan_cli.py <file> --no-ai            # deterministic only (free)
  python scan_cli.py <file> --format json      # JSON output
  python scan_cli.py <file> --fail-on high     # exit 1 if High+ found
"""
import argparse, json, os, sys
from pathlib import Path
from unittest.mock import MagicMock

# Mock streamlit so we can import app.py without a browser
sys.modules.setdefault("streamlit", MagicMock())
sys.modules.setdefault("PIL", MagicMock())
sys.modules.setdefault("PIL.Image", MagicMock())

from dotenv import load_dotenv
load_dotenv()

from app import (
    SecurityAnalyzer, verify_php_security, verify_python_security,
    verify_javascript_security, extract_vulnerabilities
)

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def main():
    p = argparse.ArgumentParser(description="CodeGuardianAI — AI-powered security scanner")
    p.add_argument("file", help="Source file to scan")
    p.add_argument("--api", choices=["openai", "deepseek"], default=None,
                   help="AI provider (default: whichever key is in .env)")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--query", default="", help="Custom security focus query")
    p.add_argument("--no-ai", action="store_true", help="Deterministic checks only (no API key needed)")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                   default="high", help="Exit code 1 if any finding at this severity or above")
    args = p.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        code = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[ERROR] Cannot read file: {e}", file=sys.stderr)
        sys.exit(1)

    analyzer = SecurityAnalyzer()

    # Auto-detect API provider from env if not specified
    if args.api is None:
        oai = os.getenv("OPENAI_API_KEY", "")
        dsk = os.getenv("DEEPSEEK_API_KEY", "")
        bad = ("your_openai_api_key_here", "your_deepseek_api_key_here", "")
        args.api = "openai" if (oai and oai not in bad) else "deepseek"

    print(f"[*] Scanning: {path.name}  |  API: {'none (deterministic)' if args.no_ai else args.api}", file=sys.stderr)

    if args.no_ai:
        lang = analyzer._detect_language(code, str(path))
        if lang == "php":
            analysis = verify_php_security(code) or "## [Secure] No issues found by deterministic checks."
        elif lang == "python":
            analysis = verify_python_security(code) or "## [Secure] No issues found by deterministic checks."
        elif lang == "javascript":
            analysis = verify_javascript_security(code) or "## [Secure] No issues found by deterministic checks."
        else:
            analysis = "## [Info] No deterministic checks available for this language. Use AI scan."
        result = {"status": "success", "analysis": analysis}
    else:
        result = analyzer.analyze_code(code, args.query, args.api, filename=str(path))

    if result["status"] == "error":
        print(f"[ERROR] {result.get('message', 'Analysis failed')}", file=sys.stderr)
        sys.exit(2)

    analysis = result["analysis"]
    vulns = extract_vulnerabilities(analysis)

    if args.format == "json":
        by_sev = {}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        print(json.dumps({
            "file": str(path),
            "status": result["status"],
            "summary": {"total": len(vulns), "by_severity": by_sev},
            "vulnerabilities": vulns,
            "raw_analysis": analysis,
        }, indent=2))
    elif args.format == "markdown":
        print(f"# Security Scan — `{path.name}`\n\n{analysis}")
    else:
        print(analysis)

    # Exit code based on --fail-on threshold
    if args.fail_on != "none":
        threshold = SEVERITY_RANK.get(args.fail_on.capitalize(), 3)
        for v in vulns:
            if SEVERITY_RANK.get(v["severity"], 0) >= threshold:
                sys.exit(1)

if __name__ == "__main__":
    main()
