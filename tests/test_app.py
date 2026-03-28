"""
Unit tests for CodeGuardianAI — app.py
Run with: pytest tests/
"""

import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

# Prevent Streamlit from executing during import
import sys
sys.modules.setdefault("streamlit", MagicMock())

# Ensure .env is not required for tests
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")

from app import (
    APIOptimizer,
    SecurityAnalyzer,
    _batch_verify_vulnerabilities,
    extract_vulnerabilities,
    generate_text_report,
)


# ---------------------------------------------------------------------------
# APIOptimizer
# ---------------------------------------------------------------------------

class TestAPIOptimizer:
    def setup_method(self):
        self.tmp = tempfile.TemporaryDirectory()
        # Patch the cache path to a temp dir
        import app as app_module
        self._orig_cache_dir = app_module._CACHE_DIR
        self._orig_cache_file = app_module._CACHE_FILE
        from pathlib import Path
        app_module._CACHE_DIR = Path(self.tmp.name)
        app_module._CACHE_FILE = Path(self.tmp.name) / "analysis_cache.json"

    def teardown_method(self):
        import app as app_module
        app_module._CACHE_DIR = self._orig_cache_dir
        app_module._CACHE_FILE = self._orig_cache_file
        self.tmp.cleanup()

    def test_cache_miss_returns_none(self):
        opt = APIOptimizer()
        assert opt.get_cached_analysis("some code", "some query") is None

    def test_cache_round_trip(self):
        opt = APIOptimizer()
        result = {"status": "success", "analysis": "findings..."}
        opt.cache_analysis("code", "query", result)
        cached = opt.get_cached_analysis("code", "query")
        assert cached == result

    def test_cache_key_is_stable(self):
        opt = APIOptimizer()
        key1 = opt._make_cache_key("code", "query")
        key2 = opt._make_cache_key("code", "query")
        assert key1 == key2

    def test_different_queries_produce_different_keys(self):
        opt = APIOptimizer()
        assert opt._make_cache_key("code", "q1") != opt._make_cache_key("code", "q2")

    def test_expired_cache_returns_none(self):
        opt = APIOptimizer()
        result = {"status": "success", "analysis": "old"}
        opt.cache_analysis("code", "query", result)

        # Backdate the timestamp past the TTL
        cache_key = opt._make_cache_key("code", "query")
        old_time = (datetime.now() - timedelta(seconds=90000)).isoformat()
        opt.cache[cache_key]["timestamp"] = old_time

        assert opt.get_cached_analysis("code", "query") is None

    def test_get_code_hash_is_sha256(self):
        opt = APIOptimizer()
        code = "print('hello')"
        expected = hashlib.sha256(code.encode()).hexdigest()
        assert opt.get_code_hash(code) == expected


# ---------------------------------------------------------------------------
# SecurityAnalyzer
# ---------------------------------------------------------------------------

class TestSecurityAnalyzer:
    def setup_method(self):
        self.analyzer = SecurityAnalyzer()

    def test_detect_language_from_filename_php(self):
        assert self.analyzer._detect_language("<?php echo 'hi';", "index.php") == "php"

    def test_detect_language_from_filename_python(self):
        assert self.analyzer._detect_language("x = 1", "script.py") == "python"

    def test_detect_language_from_filename_js(self):
        assert self.analyzer._detect_language("console.log(1)", "app.js") == "javascript"

    def test_detect_language_fallback_php_content(self):
        assert self.analyzer._detect_language("<?php echo 'hi';") == "php"

    def test_detect_language_unknown_returns_none(self):
        assert self.analyzer._detect_language("hello world") is None

    def test_add_summary_secure_code_passthrough(self):
        # Content that already has [Secure] header is returned unchanged
        content = "## [Secure] No Vulnerabilities Detected\nLooks good."
        result = self.analyzer._add_summary(content)
        assert result == content

    def test_add_summary_counts_severities(self):
        content = (
            "## [Critical] Vulnerability #1: SQL Injection\n"
            "## [High] Vulnerability #2: XSS\n"
            "## [Medium] Vulnerability #3: Info Disclosure\n"
        )
        result = self.analyzer._add_summary(content)
        assert "1 Critical" in result
        assert "1 High" in result
        assert "1 Medium" in result

    def test_create_enhanced_prompt_contains_language(self):
        prompt = self.analyzer.create_enhanced_prompt("x=1", "python")
        assert "python" in prompt.lower()

    def test_create_enhanced_prompt_php_checklist(self):
        prompt = self.analyzer.create_enhanced_prompt("<?php ?>", "php")
        assert "PHP SECURITY CHECKLIST" in prompt


# ---------------------------------------------------------------------------
# extract_vulnerabilities
# ---------------------------------------------------------------------------

SAMPLE_ANALYSIS = """
## Summary
Found 2 issues.

## [Critical] Vulnerability #1: SQL Injection
- **Location:** Lines 10-12
- **Code Snippet:**
```php
$query = "SELECT * FROM users WHERE id=" . $_GET['id'];
```
- **CWE:** 89 - SQL Injection
- **OWASP:** A03:2021
- **Confidence:** High
- **POC:** pass `1 OR 1=1`
- **Impact:** Full database read
- **Fix:** Use prepared statements

## [High] Vulnerability #2: XSS
- **Location:** Lines 20-22
- **Code Snippet:**
```php
echo $_GET['name'];
```
- **CWE:** 79 - XSS
- **OWASP:** A03:2021
- **Confidence:** High
- **POC:** pass `<script>alert(1)</script>`
- **Impact:** Session hijack
- **Fix:** Use htmlspecialchars()
"""


class TestExtractVulnerabilities:
    def test_extracts_correct_count(self):
        vulns = extract_vulnerabilities(SAMPLE_ANALYSIS)
        assert len(vulns) == 2

    def test_first_vuln_severity(self):
        vulns = extract_vulnerabilities(SAMPLE_ANALYSIS)
        assert vulns[0]["severity"] == "Critical"

    def test_second_vuln_type(self):
        vulns = extract_vulnerabilities(SAMPLE_ANALYSIS)
        assert "XSS" in vulns[1]["type"]

    def test_location_parsed(self):
        vulns = extract_vulnerabilities(SAMPLE_ANALYSIS)
        assert vulns[0]["location"] == "10-12"

    def test_empty_text_returns_empty_list(self):
        assert extract_vulnerabilities("No issues here.") == []


# ---------------------------------------------------------------------------
# generate_text_report
# ---------------------------------------------------------------------------

class TestGenerateTextReport:
    def test_contains_analysis_text(self):
        content, filename = generate_text_report("some findings")
        assert "some findings" in content

    def test_filename_ends_with_txt(self):
        _, filename = generate_text_report("x")
        assert filename.endswith(".txt")

    def test_report_has_header(self):
        content, _ = generate_text_report("x")
        assert "CodeGuardianAI Security Analysis Report" in content


# ---------------------------------------------------------------------------
# _batch_verify_vulnerabilities
# ---------------------------------------------------------------------------

class TestBatchVerify:
    def _make_vulns(self):
        return [
            {"type": "SQL Injection", "severity": "Critical", "location": "10", "code_snippet": "SELECT * FROM users WHERE id=$id"},
            {"type": "XSS", "severity": "High", "location": "20", "code_snippet": "echo $_GET['x'];"},
        ]

    def test_returns_same_count_as_input(self):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = (
            "ID: 1\nVerdict: TRUE POSITIVE\nConfidence: 90\nExplanation: Clearly injectable.\n\n"
            "ID: 2\nVerdict: FALSE POSITIVE\nConfidence: 40\nExplanation: Already escaped.\n"
        )

        with patch("app.APIClient") as MockClient:
            MockClient.return_value.create_completion.return_value = mock_response
            results = _batch_verify_vulnerabilities(self._make_vulns(), "openai")

        assert len(results) == 2

    def test_true_positive_parsed(self):
        mock_response = MagicMock()
        mock_response.choices[0].message.content = (
            "ID: 1\nVerdict: TRUE POSITIVE\nConfidence: 95\nExplanation: Direct injection.\n\n"
            "ID: 2\nVerdict: TRUE POSITIVE\nConfidence: 80\nExplanation: Reflected XSS.\n"
        )

        with patch("app.APIClient") as MockClient:
            MockClient.return_value.create_completion.return_value = mock_response
            results = _batch_verify_vulnerabilities(self._make_vulns(), "openai")

        assert results[0]["verdict"] == "TRUE POSITIVE"
        assert results[0]["confidence"] == 95

    def test_empty_input_returns_empty(self):
        assert _batch_verify_vulnerabilities([], "openai") == []
