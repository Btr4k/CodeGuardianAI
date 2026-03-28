import streamlit as st
import openai
import os
import base64
import re
from PIL import Image
import requests
from dotenv import load_dotenv
from typing import Dict, List, Tuple
import hashlib
import logging
import logging.config
import time
from datetime import datetime
import socket
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import json
from pathlib import Path
import zipfile
import io

# Setup logging — load from config file if present, otherwise fall back to basicConfig
_log_config = Path("logging_config.json")
if _log_config.exists():
    with open(_log_config) as _f:
        logging.config.dictConfig(json.load(_f))
else:
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('security_analyzer.log')]
    )

# Load environment variables
load_dotenv()

REQUIRED_KEYS = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
    "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY"),
}


def check_password() -> bool:
    """Password gate. Set APP_PASSWORD in .env to enable; skipped when unset."""
    app_password = os.getenv("APP_PASSWORD")
    if not app_password:
        return True
    if st.session_state.get("authenticated"):
        return True

    enhance_streamlit_ui()
    st.markdown("""
        <div class="login-wrap">
            <div class="login-card">
                <div class="login-icon">🛡️</div>
                <div class="login-title">CodeGuardianAI</div>
                <div class="login-sub">Enter your access password to continue</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    col = st.columns([1, 2, 1])[1]
    with col:
        pwd = st.text_input("Password", type="password", placeholder="Enter password…", label_visibility="collapsed")
        if st.button("Unlock Access", use_container_width=True):
            if pwd == app_password:
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Incorrect password. Please try again.")
    return False


def check_internet_connection(host="8.8.8.8", port=53, timeout=3):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, socket.gaierror, ConnectionRefusedError):
            return False


def generate_text_report(analysis_results: str, base_filename: str = "security_analysis_report") -> tuple:
    """Generate a text report content without saving to file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_filename}_{timestamp}.txt"
    report_content = f"""==============================================
CodeGuardianAI Security Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==============================================

{analysis_results}
"""
    return report_content, filename


def generate_download_report(analysis_results):
    """Provide download buttons for text and JSON reports."""
    try:
        if not analysis_results:
            st.error("No analysis results available to generate report")
            return

        report_content, txt_filename = generate_text_report(analysis_results)

        # JSON export
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vulnerabilities = extract_vulnerabilities(analysis_results)
        json_payload = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total": len(vulnerabilities),
                "by_severity": {},
            },
            "vulnerabilities": [
                {
                    "number": v["number"],
                    "type": v["type"],
                    "severity": v["severity"],
                    "location": v["location"],
                    "code_snippet": v["code_snippet"],
                    "verification": v.get("verification"),
                }
                for v in vulnerabilities
            ],
            "raw_analysis": analysis_results,
        }
        for v in vulnerabilities:
            sev = v["severity"]
            json_payload["summary"]["by_severity"][sev] = json_payload["summary"]["by_severity"].get(sev, 0) + 1

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Download TXT Report",
                data=report_content,
                file_name=txt_filename,
                mime="text/plain",
                key="download_report_txt"
            )
        with col2:
            st.download_button(
                label="Download JSON Report",
                data=json.dumps(json_payload, indent=2),
                file_name=f"security_analysis_{timestamp}.json",
                mime="application/json",
                key="download_report_json"
            )
    except Exception as e:
        logging.error(f"Report generation error: {str(e)}", exc_info=True)
        st.error("Error generating report. Please try again.")


_CACHE_DURATION = int(os.getenv("CACHE_DURATION", "86400"))
_CACHE_DIR = Path("cache")
_CACHE_FILE = _CACHE_DIR / "analysis_cache.json"


class APIOptimizer:
    def __init__(self):
        _CACHE_DIR.mkdir(exist_ok=True)
        self.cache_file = _CACHE_FILE
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.cache = {}

    def get_code_hash(self, code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()

    def _make_cache_key(self, code: str, query) -> str:
        """Build a deterministic cache key from code content and query."""
        code_hash = self.get_code_hash(code)
        query_hash = hashlib.sha256(str(query).encode()).hexdigest() if query else "full_scan"
        return f"{code_hash}_{query_hash}"

    def get_cached_analysis(self, code: str, query: str = None) -> dict:
        """Retrieve cached analysis if available and fresh."""
        cache_key = self._make_cache_key(code, query)
        if cache_key in self.cache:
            cached_time = datetime.fromisoformat(self.cache[cache_key]['timestamp'])
            if (datetime.now() - cached_time).total_seconds() < _CACHE_DURATION:
                return self.cache[cache_key]['results']
        return None

    def cache_analysis(self, code: str, query: str, results: dict):
        """Store analysis results in cache for later use."""
        cache_key = self._make_cache_key(code, query)
        self.cache[cache_key] = {
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
            os.chmod(self.cache_file, 0o600)
        except IOError as e:
            logging.error(f"Cache write error: {str(e)}")


class _APIResponse:
    """Simple normalized response wrapper for both OpenAI and Deepseek responses."""

    def __init__(self, content: str):
        self._content = content

    @property
    def choices(self):
        return [self]

    @property
    def message(self):
        return self

    @property
    def content(self):
        return self._content


class APIClient:
    def __init__(self, api_type: str):
        self.api_type = api_type.lower()
        if self.api_type == "openai":
            self._openai_client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        elif self.api_type == "deepseek":
            self.session = requests.Session()
            self.session.headers.update({
                "Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}",
                "Content-Type": "application/json"
            })
        else:
            raise ValueError("Unsupported API type. Please use 'openai' or 'deepseek'.")

    def create_completion(self, messages: list, **kwargs) -> _APIResponse:
        """Create completion with the chosen API provider, always returning an _APIResponse."""
        try:
            if self.api_type == "openai":
                response = self._openai_client.chat.completions.create(
                    model=os.getenv("OPENAI_MODEL", "gpt-3.5-turbo"),
                    messages=messages,
                    temperature=kwargs.get('temperature', 0.1),
                    max_tokens=kwargs.get('max_tokens', 3000)
                )
                content = response.choices[0].message.content
                return _APIResponse(content)

            elif self.api_type == "deepseek":
                payload = {
                    "model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
                    "messages": messages,
                    "temperature": kwargs.get('temperature', 0.1),
                    "max_tokens": kwargs.get('max_tokens', 3000),
                    "stream": False
                }
                response = self.session.post(
                    "https://api.deepseek.com/v1/chat/completions", json=payload
                )
                resp_data = response.json()
                if not resp_data.get('choices'):
                    raise ValueError("No response choices available")
                content = resp_data['choices'][0]['message'].get('content')
                if not content:
                    raise ValueError("No content in API response")
                return _APIResponse(content)

        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            raise ValueError(f"API request failed: {str(e)}")
        except Exception as e:
            logging.error(f"API error: {str(e)}")
            raise ValueError(f"API error: {str(e)}")


class SecurityAnalyzer:
    def __init__(self):
        self.vulnerability_categories = {
            "injection": [
                "SQL Injection",
                "Command Injection",
                "Code Injection",
                "Template Injection"
            ],
            "rce": [
                "Remote Code Execution",
                "Arbitrary Code Execution",
                "Unsafe Deserialization"
            ],
            "auth": [
                "Authentication Bypass",
                "Authorization Bypass",
                "Privilege Escalation"
            ],
            "data": [
                "Sensitive Data Exposure",
                "Information Disclosure",
                "Data Leakage"
            ],
            "csrf": [
                "Cross-Site Request Forgery"
            ],
            "xss": [
                "Cross-Site Scripting (Stored, Reflected, DOM-based)"
            ],
            "misconfiguration": [
                "Security Misconfiguration",
                "Insecure Default Configurations"
            ],
            "insecure_design": [
                "Insecure Design"
            ],
            "business_logic": [
                "Business Logic Vulnerabilities"
            ]
        }

        self.language_specific_checks = {
            "php": {
                'critical_functions': [
                    "eval()",
                    "system()",
                    "exec()",
                    "shell_exec()",
                    "passthru()",
                    "unserialize()",
                    "include()/require()",
                    "file_get_contents()",
                    "mysql_query()",
                    "echo without htmlspecialchars()",
                    "md5() for passwords",
                    "sha1() for passwords",
                    "direct HTML output of variables",
                    "unvalidated img src attributes"
                ],
                'dangerous_patterns': [
                    {"pattern": r"md5\s*\(\s*\$pass", "name": "Insecure Password Hashing", "severity": "critical"},
                    {"pattern": r"<.*?>\s*{\s*\$.+?\s*}\s*<", "name": "Potential XSS", "severity": "high"},
                    {"pattern": r"<img.*?src\s*=\s*[\"\']\s*{\s*\$.+?\s*}\s*[\"\']\s*[^>]*>", "name": "XSS via Image Source", "severity": "high"}
                ]
            },
            "python": {
                'critical_functions': [
                    "eval()",
                    "exec()",
                    "os.system()",
                    "subprocess.call()",
                    "pickle.loads()",
                    "input()",
                    "yaml.load()",
                    "sqlite3.execute()"
                ]
            },
            "javascript": {
                'critical_functions': [
                    "eval()",
                    "Function()",
                    "setTimeout()/setInterval() with string",
                    "innerHTML",
                    "document.write()",
                    "dangerouslySetInnerHTML",
                    "child_process.exec()"
                ]
            }
        }

        self.severity_levels = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
            "secure": 0
        }

    def _detect_language(self, code: str, filename: str = None) -> str:
        """Detect the programming language from filename or code content."""
        if filename:
            ext = filename.rsplit('.', 1)[-1].lower()
            ext_map = {
                'php': 'php', 'py': 'python', 'js': 'javascript',
                'java': 'java', 'cpp': 'c++', 'cs': 'csharp'
            }
            if ext in ext_map:
                return ext_map[ext]
        # Fallback: detect from content
        if re.search(r'<\?php', code):
            return 'php'
        return None

    def create_enhanced_prompt(self, code: str, language: str = None) -> str:
        severity_formats = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Info",
            "SECURE": "Secure"
        }

        severity_legend = "\nSEVERITY LEVELS:\n"
        for severity, formatted in severity_formats.items():
            severity_legend += f"- {formatted}: {self._get_severity_description(severity)}\n"

        lang = language if language else "code"
        base_prompt = f"""You are a security expert. Analyze the following {lang} for vulnerabilities.

IMPORTANT: Be very careful to avoid false positives. Only report issues that you are confident are actual vulnerabilities with real security impact. If you're uncertain, classify it as INFO. If the code appears secure, explicitly state that no vulnerabilities were found.

{severity_legend}

For each confirmed finding, follow this EXACT format:

## [SEVERITY_EMOJI SEVERITY] Vulnerability #N: TYPE

Example headers:
- ## [Critical] Vulnerability #1: Remote Code Execution
- ## [High] Vulnerability #2: SQL Injection
- ## [Medium] Vulnerability #3: XSS Vulnerability
- ## [Low] Vulnerability #4: Information Disclosure
- ## [Info] Note #1: Potential concern (not a confirmed vulnerability)

Required sections for each finding:
- **Location:** Lines [exact_start-exact_end]
- **Code Snippet:**
[Exact vulnerable code snippet]
- **CWE:** [specific_id] - [name]
- **OWASP:** [exact_category]
- **Confidence:** [High/Medium/Low] - How certain you are this is a real vulnerability
- **POC:**
[Concise, technical exploit demonstrating the vulnerability]
- **Impact:**
[Brief description of consequences]
- **Fix:**
[Minimal code change to resolve the issue]

If no vulnerabilities are found, start your analysis with:
## [Secure] No Vulnerabilities Detected
Then explain why the code appears secure and any best practices it follows.
"""

        if language and language.lower() == "php":
            base_prompt += """
PHP SECURITY CHECKLIST - VERIFY THESE ISSUES CAREFULLY:

1. INSECURE PASSWORD STORAGE: If using md5() or sha1() for passwords, this is a Critical vulnerability.

2. XSS VULNERABILITIES:
   - Direct output of variables without htmlspecialchars() is vulnerable
   - Check all echo, print statements and string concatenation with $html .=
   - URLs in <a href> and <img src> attributes need validation

3. FILE UPLOAD SECURITY:
   - Always validate MIME type AND content, not just extensions
   - Check where files are stored - web-accessible folders are risky
   - Ensure filenames are sanitized with basename()

4. SQL INJECTION: Must use prepared statements with bound parameters.

5. SESSION SECURITY: Check for proper session management and validation.

Remember: err on the side of reporting issues rather than missing them.
"""

        base_prompt += "\n\nVULNERABILITY CATEGORIES TO CHECK:"
        for category, checks in self.vulnerability_categories.items():
            cat_upper = category.upper()
            checks_str = ", ".join(checks)
            severity_indicator = self._get_severity_indicator(category)
            base_prompt += f"\n- {severity_indicator} {cat_upper}: {checks_str}"

        if language and language.lower() in self.language_specific_checks:
            funcs = self.language_specific_checks[language.lower()]['critical_functions']
            base_prompt += f"\n\n{language.upper()} SPECIFIC CHECKS:"
            base_prompt += f"\n- Review dangerous functions: {', '.join(funcs)}"

        base_prompt += "\n\nIMPORTANT: Before reporting any vulnerability, validate that it is exploitable and not just a theoretical concern. It is better to miss a low-severity issue than to report a false positive."
        return base_prompt

    def _get_severity_description(self, severity: str) -> str:
        descriptions = {
            "CRITICAL": "Needs immediate attention - Direct system/data compromise",
            "HIGH": "Should be fixed soon - Significant security impact",
            "MEDIUM": "Plan to address - Moderate security impact",
            "LOW": "Good to fix when possible - Limited security impact",
            "INFO": "Not a vulnerability - Just something to be aware of",
            "SECURE": "Code appears secure - No vulnerabilities detected"
        }
        return descriptions.get(severity, "Unknown severity level")

    def _get_severity_indicator(self, category: str) -> str:
        indicators = {
            "injection": "[Critical]",
            "rce": "[Critical]",
            "auth": "[High]",
            "data": "[Medium]"
        }
        return indicators.get(category.lower(), "[Low]")

    def _add_summary(self, content: str) -> str:
        """Add a vulnerability summary header to analysis results."""
        if "[Secure] No Vulnerabilities Detected" in content:
            return content
        if content.startswith("## Summary"):
            return content

        critical = len(re.findall(r"\[Critical\]", content))
        high = len(re.findall(r"\[High\]", content))
        medium = len(re.findall(r"\[Medium\]", content))
        low = len(re.findall(r"\[Low\]", content))
        info = len(re.findall(r"\[Info\]", content))
        total_vulns = critical + high + medium + low

        summary = "## Summary\n"
        if total_vulns == 0:
            summary += "No confirmed vulnerabilities detected.\n\n"
            if info > 0:
                summary += f"{info} informational note(s) provided.\n\n"
            if "[Secure]" not in content:
                content = (
                    "## [Secure] No Vulnerabilities Detected\n\n"
                    "The code appears to be secure. No exploitable vulnerabilities were identified.\n\n"
                    + content
                )
        else:
            summary += f"Found {total_vulns} potential security issue(s):\n"
            if critical > 0:
                summary += f"- {critical} Critical\n"
            if high > 0:
                summary += f"- {high} High\n"
            if medium > 0:
                summary += f"- {medium} Medium\n"
            if low > 0:
                summary += f"- {low} Low\n"
            if info > 0:
                summary += f"- {info} Info\n"
            summary += "\nPlease review each finding carefully to confirm it is a real vulnerability.\n\n"

        return summary + content

    def analyze_code(self, code: str, user_query: str, api_type: str, filename: str = None) -> Dict:
        """Analyze code using the selected API with caching."""
        try:
            api_optimizer = APIOptimizer()

            # Check cache first
            cached_result = api_optimizer.get_cached_analysis(code, user_query)
            if cached_result:
                logging.info("Using cached analysis results")
                return cached_result

            language = self._detect_language(code, filename)

            # Use dedicated PHP analyzer for PHP files
            if language == 'php':
                result = analyze_php_security(code, api_type)
            else:
                result = self._analyze_generic(code, user_query, api_type, language)

            # Cache successful results
            if result.get("status") == "success":
                api_optimizer.cache_analysis(code, user_query, result)

            return result

        except Exception as e:
            logging.error(f"Analysis error: {str(e)}")
            return {
                "status": "error",
                "message": "Analysis failed. Please check your API key and try again."
            }

    def _analyze_generic(self, code: str, user_query: str, api_type: str, language: str = None) -> Dict:
        """Generic analysis for non-PHP languages."""
        client = APIClient(api_type)
        analysis_prompt = self.create_enhanced_prompt(code, language)

        if user_query:
            analysis_prompt += f"\n\nFOCUS AREA: {user_query}"

        messages = [
            {"role": "system", "content": "You are a security analyst. Analyze the code thoroughly and report any security vulnerabilities."},
            {"role": "user", "content": analysis_prompt}
        ]

        response = client.create_completion(
            messages=messages,
            temperature=0.1,
            max_tokens=3000,
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("Empty response content")

        processed_content = self._add_summary(content)
        return {
            "status": "success",
            "analysis": processed_content,
            "metadata": {
                "api": api_type,
                "timestamp": datetime.now().isoformat(),
                "query": user_query
            }
        }


def _batch_verify_vulnerabilities(vulnerabilities: list, api_type: str) -> list:
    """Verify all vulnerabilities in a single API call. Returns list of verification dicts."""
    if not vulnerabilities:
        return []

    vuln_lines = []
    for i, v in enumerate(vulnerabilities, 1):
        snippet = v["code_snippet"][:300] if v["code_snippet"] else "(no snippet)"
        vuln_lines.append(
            f"[{i}] Type={v['type']} | Severity={v['severity']} | Location={v['location']}\n"
            f"    Snippet: {snippet}"
        )

    prompt = (
        "You are a security verification expert. For each vulnerability listed below, "
        "determine if it is a TRUE POSITIVE or FALSE POSITIVE.\n\n"
        "For EACH item respond with exactly this format (one block per item, no extra text):\n\n"
        "ID: <number>\n"
        "Verdict: TRUE POSITIVE or FALSE POSITIVE\n"
        "Confidence: <0-100>\n"
        "Explanation: <one sentence>\n\n"
        "VULNERABILITIES TO VERIFY:\n\n"
        + "\n\n".join(vuln_lines)
    )

    try:
        client = APIClient(api_type)
        response = client.create_completion(
            messages=[
                {"role": "system", "content": "You are a security verification expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=min(300 * len(vulnerabilities), 3000)
        )
        content = response.choices[0].message.content

        results = []
        for i in range(1, len(vulnerabilities) + 1):
            block_pattern = rf"ID:\s*{i}\s*\nVerdict:\s*(TRUE POSITIVE|FALSE POSITIVE)\s*\nConfidence:\s*(\d+)\s*\nExplanation:\s*([^\n]+)"
            m = re.search(block_pattern, content, re.IGNORECASE)
            if m:
                results.append({
                    "verdict": m.group(1).upper(),
                    "confidence": int(m.group(2)),
                    "explanation": m.group(3).strip(),
                })
            else:
                results.append({"verdict": "UNCERTAIN", "confidence": 50, "explanation": "Could not parse verification response."})
        return results

    except Exception as e:
        logging.error(f"Batch verification error: {str(e)}")
        return [{"verdict": "ERROR", "confidence": 0, "explanation": "Verification failed."} for _ in vulnerabilities]


def extract_vulnerabilities(analysis_text: str) -> list:
    """Extracts individual vulnerabilities from the analysis text."""
    vulnerability_pattern = r"##\s*\[(?:Critical|High|Medium|Low)\]\s*Vulnerability\s*#(\d+):\s*([^\n]+)"
    vulnerability_matches = list(re.finditer(vulnerability_pattern, analysis_text))

    vulnerabilities = []
    for i, match in enumerate(vulnerability_matches):
        number, vuln_type = match.groups()

        # Determine severity from the header
        severity_match = re.search(r"\[(Critical|High|Medium|Low)\]", match.group(0))
        severity = severity_match.group(1) if severity_match else "Unknown"
        emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        emoji = emoji_map.get(severity, "")

        location_match = re.search(r"\*\*Location:\*\*\s*Lines\s*([\d\-]+)", analysis_text[match.end():], re.DOTALL)
        location = location_match.group(1) if location_match else "Unknown"

        snippet_match = re.search(r"\*\*Code Snippet:\*\*\s*```[^\n]*\n(.*?)```", analysis_text[match.end():], re.DOTALL)
        code_snippet = snippet_match.group(1).strip() if snippet_match else ""

        end_pos = vulnerability_matches[i + 1].start() if i + 1 < len(vulnerability_matches) else len(analysis_text)

        vulnerabilities.append({
            "emoji": emoji,
            "severity": severity,
            "number": number,
            "type": vuln_type.strip(),
            "location": location,
            "code_snippet": code_snippet,
            "full_content": analysis_text[match.start():end_pos].strip()
        })

    return vulnerabilities


def verify_all_vulnerabilities(analysis_text: str, api_type: str, confidence_threshold: str) -> str:
    """Verifies all vulnerabilities and filters based on confidence threshold."""
    vulnerabilities = extract_vulnerabilities(analysis_text)

    if not vulnerabilities:
        return analysis_text

    threshold_values = {"Low": 30, "Medium": 60, "High": 80}
    threshold = threshold_values.get(confidence_threshold, 60)

    verifications = _batch_verify_vulnerabilities(vulnerabilities, api_type)
    verified_vulnerabilities = []
    for vuln, verification in zip(vulnerabilities, verifications):
        vuln["verification"] = verification
        if verification["verdict"] == "TRUE POSITIVE" and verification["confidence"] >= threshold:
            verified_vulnerabilities.append(vuln)

    if not verified_vulnerabilities:
        return (
            "## [Secure] No Verified Vulnerabilities Detected\n\n"
            f"The initial analysis identified {len(vulnerabilities)} potential issues, "
            f"but none passed verification at the current confidence threshold ({confidence_threshold}).\n\n"
            "### Original Analysis (Not Verified)\n\n" + analysis_text
        )

    new_analysis = "## Summary\n\n"
    new_analysis += f"Found {len(verified_vulnerabilities)} verified vulnerabilities out of {len(vulnerabilities)} reported issues.\n\n"

    severity_counts: Dict[str, int] = {}
    for vuln in verified_vulnerabilities:
        sev = vuln["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
    for severity, count in severity_counts.items():
        emoji = emoji_map.get(severity, "")
        new_analysis += f"- {emoji} {count} {severity}\n"

    new_analysis += "\n\n"

    for i, vuln in enumerate(verified_vulnerabilities, 1):
        updated_content = re.sub(
            r"##\s*\[(Critical|High|Medium|Low)\]\s*Vulnerability\s*#\d+:",
            f"## [{vuln['severity']}] Vulnerability #{i}:",
            vuln["full_content"]
        )
        verification_info = (
            f"\n\n**Verification:** Confirmed with {vuln['verification']['confidence']}% confidence\n"
            f"**Justification:** {vuln['verification']['explanation']}\n"
        )
        updated_content += verification_info
        new_analysis += updated_content + "\n\n"

    filtered_count = len(vulnerabilities) - len(verified_vulnerabilities)
    if filtered_count > 0:
        new_analysis += f"### Note\n\n{filtered_count} potential issue(s) were filtered out due to insufficient confidence.\n"

    return new_analysis


def verify_php_security(code: str, analysis_results: str) -> str:
    """Performs additional PHP-specific security checks that AI might miss.
    Returns a formatted result string if new issues are found, otherwise None."""
    issues = []

    # Check for insecure password hashing
    if re.search(r"md5\s*\(\s*\$(?:pass|password)", code):
        match = re.search(r"(.*md5\s*\(\s*\$(?:pass|password)[^\n]*)", code)
        snippet = match.group(1).strip() if match else "md5($password)"
        issues.append({
            "type": "Insecure Password Hashing",
            "severity": "Critical",
            "description": "MD5 is cryptographically broken and unsuitable for password storage.",
            "snippet": snippet,
            "fix": "Use password_hash() and password_verify() instead."
        })

    # Check for XSS via unescaped output
    echo_vars = re.findall(r'(?:echo|print|<\?=)\s*(?:"[^"]*\$[^"]*"|\'[^\']*\$[^\']*\'|\$[a-zA-Z0-9_]+)', code)
    html_vars = re.findall(r'\$html\s*\.=\s*["\'][^"\']*\$[^"\']*["\']', code)
    if (echo_vars or html_vars) and not re.search(r"htmlspecialchars\s*\(", code):
        snippet = (echo_vars[0] if echo_vars else html_vars[0] if html_vars else "$variable").strip()
        issues.append({
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "description": "Output contains unencoded variables, leading to XSS vulnerabilities.",
            "snippet": snippet,
            "fix": "Use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') for all output containing user data."
        })

    # Check for unsafe image source
    img_match = re.search(r'(<img[^>]*src\s*=\s*["\']?\s*\$[^>]*>)', code)
    if img_match:
        issues.append({
            "type": "Stored XSS via Image",
            "severity": "High",
            "description": "Unsanitized variables in image src attributes can lead to XSS.",
            "snippet": img_match.group(1)[:120],
            "fix": "Validate and sanitize all URLs before using them in img tags."
        })

    # Check for file upload vulnerabilities
    if re.search(r"\$_FILES", code):
        suspicious_paths = re.search(r"(uploads|hackable|www|public_html|web)", code, re.IGNORECASE)
        extension_only_validation = re.search(r"strtolower\s*\(\s*\$\w+_ext\s*\)", code)
        web_accessible = not re.search(r"\.htaccess|AddHandler", code)

        if suspicious_paths and extension_only_validation and web_accessible:
            # Extract actual upload path from code rather than hardcoding
            path_match = re.search(r'(["\'][^"\']*(?:uploads|hackable|www|public_html|web)[^"\']*["\'])', code, re.IGNORECASE)
            snippet = path_match.group(1) if path_match else '"<upload directory path>"'
            issues.append({
                "type": "Insecure File Upload - RCE Vulnerability",
                "severity": "Critical",
                "description": (
                    "Files are uploaded to a web-accessible directory with insufficient validation. "
                    "An attacker could upload a malicious script and execute it remotely."
                ),
                "snippet": snippet,
                "fix": (
                    "1. Move uploads outside the web root.\n"
                    "2. Validate file content (not just extension) via binary/MIME inspection.\n"
                    "3. Prevent code execution in upload directories via server config."
                )
            })

    if not issues:
        return None

    # Only report issues that the AI missed (it said the code was secure)
    if "[Secure]" not in analysis_results and "No Vulnerabilities Detected" not in analysis_results:
        return None

    result = "## [Critical] Security Issues Detected by Secondary Verification\n\n"
    for i, issue in enumerate(issues, 1):
        result += f"## [{issue['severity']}] Issue #{i}: {issue['type']}\n\n"
        result += f"**Description:** {issue['description']}\n\n"
        result += f"**Code Snippet:**\n```php\n{issue['snippet']}\n```\n\n"
        result += f"**Impact:** {issue['description']}\n\n"
        result += f"**Fix:** {issue['fix']}\n\n"

    return result


def analyze_php_security(code: str, api_type: str) -> dict:
    """Performs an in-depth, multi-pass security analysis of PHP code."""
    client = APIClient(api_type)

    # Properly closed code blocks — no unclosed backtick fences
    security_prompt = (
        "You are a world-class PHP security expert who finds ALL security vulnerabilities in code.\n"
        "Analyze the following PHP code for every possible vulnerability using the EXACT FORMAT specified below.\n\n"
        "For each vulnerability found, use this EXACT format:\n\n"
        "## [Critical] Vulnerability #N: VULNERABILITY_TYPE\n"
        "- **Location:** Lines X-Y or specific code reference\n"
        "- **Code Snippet:**\n"
        "```php\n"
        "// paste the actual vulnerable code here\n"
        "```\n"
        "- **CWE:** [id] - [name]\n"
        "- **OWASP:** [category]\n"
        "- **Confidence:** High/Medium/Low\n"
        "- **POC:** [exploit proof of concept]\n"
        "- **Impact:** [consequences]\n"
        "- **Fix:** [remediation]\n\n"
        "Pay special attention to:\n"
        "1. SQL Injection - especially from $_COOKIE, $_SESSION variables\n"
        "2. Cross-Site Scripting (reflected, stored, DOM-based)\n"
        "3. Command Injection\n"
        "4. File Inclusion / Path Traversal\n"
        "5. Authentication / Authorization issues\n"
        "6. Insecure File Uploads\n"
        "7. Information Disclosure\n"
        "8. Business Logic vulnerabilities\n\n"
        "If the code is truly secure, begin your response with:\n"
        "## [Secure] No Vulnerabilities Detected\n"
        "Then justify your conclusion.\n\n"
        "PHP CODE TO ANALYZE:\n"
        "```php\n"
        f"{code}\n"
        "```\n\n"
        "Start your response with '## Security Analysis Results' and list each vulnerability with its severity."
    )

    try:
        messages = [
            {"role": "system", "content": "You are an expert PHP security auditor focusing exclusively on finding security vulnerabilities."},
            {"role": "user", "content": security_prompt}
        ]

        logging.info("Performing targeted PHP security analysis...")
        response = client.create_completion(messages=messages, temperature=0.1, max_tokens=3000)
        security_analysis = response.choices[0].message.content

        appears_secure = (
            "secure" in security_analysis.lower()
            and not any(w in security_analysis.lower() for w in [
                "vulnerability", "vulnerabilities", "insecure", "risk", "exploit"
            ])
        )

        if appears_secure:
            # First: run our own deterministic PHP checks
            secondary = verify_php_security(code, security_analysis)
            if secondary:
                final_analysis = secondary + "\n\n### Initial AI Analysis (Overridden)\n\n" + security_analysis
            else:
                # Second: get an adversarial second opinion from the AI
                challenge_prompt = (
                    "You are a professional penetration tester who specializes in finding vulnerabilities that other auditors miss.\n"
                    "The following PHP code was marked 'secure' by another auditor. Find what they overlooked.\n\n"
                    "Look carefully for:\n"
                    "1. Subtle XSS (especially in error/success messages)\n"
                    "2. Indirect file inclusion risks\n"
                    "3. Race conditions\n"
                    "4. Insufficient validation of user input\n"
                    "5. Logic flaws that lead to security bypasses\n"
                    "6. Insecure configuration or implementation patterns\n"
                    "7. Insecure direct object references\n"
                    "8. Violated PHP security best practices\n\n"
                    "CODE TO ANALYZE:\n"
                    "```php\n"
                    f"{code}\n"
                    "```\n\n"
                    "If you find vulnerabilities, use '## VULNERABILITY DETECTED' headers.\n"
                    "If you agree the code is secure, respond with: ## [Secure] Code Verified Secure"
                )

                messages = [
                    {"role": "system", "content": "You are an adversarial security researcher who specializes in finding vulnerabilities other auditors miss."},
                    {"role": "user", "content": challenge_prompt}
                ]

                logging.info("Getting second opinion for PHP security analysis...")
                response2 = client.create_completion(messages=messages, temperature=0.2, max_tokens=3000)
                second_opinion = response2.choices[0].message.content

                if "vulnerability detected" in second_opinion.lower() or "insecure" in second_opinion.lower():
                    final_analysis = (
                        "## Security Analysis Results (Second Opinion)\n\n"
                        "A deeper review identified potential vulnerabilities initially overlooked:\n\n"
                        f"{second_opinion}\n\n"
                        "### Initial Analysis (Incomplete)\n\n"
                        f"{security_analysis}"
                    )
                else:
                    final_analysis = (
                        "## [Secure] Code Appears Secure After Multiple Reviews\n\n"
                        "Two separate security analyses found no significant vulnerabilities.\n\n"
                        f"{security_analysis}"
                    )
        else:
            final_analysis = security_analysis

        return {
            "status": "success",
            "analysis": final_analysis,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "api": api_type,
                "multiple_analyses": appears_secure
            }
        }

    except Exception as e:
        logging.error(f"PHP security analysis error: {str(e)}")
        return {
            "status": "error",
            "message": "PHP security analysis failed. Please check your API key and try again."
        }


def process_single_file(uploaded_file) -> bool:
    """Process a single uploaded file."""
    try:
        file_content = uploaded_file.getvalue().decode("utf-8")
        if len(file_content) > 100 * 1024:
            st.error("File is too large. Please upload a file smaller than 100KB.")
            return False
        st.session_state.user_code = file_content
        st.session_state.current_file = uploaded_file.name
        st.success("Code uploaded successfully!")
        with st.expander("View Uploaded Code"):
            ext = uploaded_file.name.rsplit('.', 1)[-1]
            st.code(st.session_state.user_code, language=ext)
        return True
    except Exception as e:
        logging.error(f"File read error: {str(e)}")
        st.error("Error reading file. Please ensure the file is valid UTF-8 text.")
        return False


def process_uploaded_folder(uploaded_zip):
    """Process a zipped folder of code files with metadata tracking."""
    folder_contents = {}
    file_metadata = {}
    with zipfile.ZipFile(io.BytesIO(uploaded_zip.read())) as z:
        for filename in z.namelist():
            if filename.endswith(('.php', '.py', '.js', '.java', '.cpp', '.cs')):
                with z.open(filename) as f:
                    content = f.read().decode('utf-8')
                    size_kb = len(content) / 1024
                    file_metadata[filename] = {
                        'size_kb': round(size_kb, 2),
                        'lines': len(content.splitlines()),
                        'extension': filename.rsplit('.', 1)[-1],
                        'scanned': False,
                        'last_scan': None
                    }
                    if size_kb <= 100:
                        folder_contents[filename] = content
                    else:
                        st.warning(f"Skipped {filename}: File size exceeds 100KB limit")

    if folder_contents:
        st.session_state.folder_contents = folder_contents
        st.session_state.file_metadata = file_metadata
        st.success(f"Loaded {len(folder_contents)} valid files.")
    else:
        st.error("No valid code files found.")

    return folder_contents, file_metadata


def enhance_streamlit_ui():
    """Inject professional CSS into the Streamlit app."""
    st.markdown("""
    <style>
    /* ── Google Font ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    /* ── Design tokens ── */
    :root {
        --bg:          #0d1117;
        --surface:     #161b22;
        --surface-2:   #21262d;
        --border:      #30363d;
        --border-soft: #21262d;
        --text:        #e6edf3;
        --text-muted:  #8b949e;
        --accent:      #1f6feb;
        --accent-soft: rgba(31,111,235,0.15);
        --green:       #238636;
        --green-soft:  rgba(35,134,54,0.15);
        --amber:       #d29922;
        --amber-soft:  rgba(210,153,34,0.15);
        --red:         #da3633;
        --red-soft:    rgba(218,54,51,0.15);
        --orange:      #e3702a;
        --orange-soft: rgba(227,112,42,0.15);
        --radius:      10px;
        --shadow:      0 4px 24px rgba(0,0,0,0.4);
        --transition:  0.2s ease;
    }

    /* ── Base ── */
    html, body, [class*="css"], .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: var(--bg) !important;
        color: var(--text) !important;
    }

    /* ── Hide Streamlit chrome ── */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 1.5rem !important; max-width: 1200px !important; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background-color: var(--surface) !important;
        border-right: 1px solid var(--border) !important;
    }
    section[data-testid="stSidebar"] * { color: var(--text) !important; }
    section[data-testid="stSidebar"] .stSelectbox label,
    section[data-testid="stSidebar"] .stRadio label,
    section[data-testid="stSidebar"] .stCheckbox label { color: var(--text-muted) !important; font-size: 0.82rem !important; text-transform: uppercase !important; letter-spacing: 0.05em !important; }
    section[data-testid="stSidebar"] [data-baseweb="select"] > div { background: var(--surface-2) !important; border-color: var(--border) !important; color: var(--text) !important; }
    .sidebar-logo { text-align: center; padding: 1.2rem 0 0.5rem; }
    .sidebar-logo-text { font-size: 1.1rem; font-weight: 700; color: var(--text) !important; letter-spacing: 0.02em; }
    .sidebar-logo-sub { font-size: 0.72rem; color: var(--text-muted) !important; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 2px; }
    .sidebar-divider { border: none; border-top: 1px solid var(--border); margin: 0.8rem 0; }
    .sidebar-section-label {
        font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em;
        color: var(--text-muted) !important; font-weight: 600; padding: 0.6rem 0 0.3rem;
    }

    /* ── Status pill ── */
    .status-pill {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600;
        margin: 2px 0;
    }
    .status-online  { background: var(--green-soft);  color: #3fb950 !important; border: 1px solid rgba(63,185,80,0.3); }
    .status-offline { background: var(--red-soft);    color: #f85149 !important; border: 1px solid rgba(248,81,73,0.3); }
    .status-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }

    /* ── Hero header ── */
    .hero {
        background: linear-gradient(135deg, #0d1117 0%, #161b22 40%, #0d2040 100%);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 2.5rem 2rem;
        text-align: center;
        margin-bottom: 1.8rem;
        position: relative;
        overflow: hidden;
    }
    .hero::before {
        content: '';
        position: absolute; inset: 0;
        background: radial-gradient(ellipse at 50% 0%, rgba(31,111,235,0.15) 0%, transparent 70%);
        pointer-events: none;
    }
    .hero-badge {
        display: inline-block;
        background: var(--accent-soft); color: #58a6ff !important;
        border: 1px solid rgba(88,166,255,0.3);
        border-radius: 20px; font-size: 0.72rem; font-weight: 600;
        padding: 3px 12px; letter-spacing: 0.08em; text-transform: uppercase;
        margin-bottom: 0.8rem;
    }
    .hero-title {
        font-size: 2.4rem !important; font-weight: 700 !important;
        color: var(--text) !important; margin: 0.3rem 0 !important;
        letter-spacing: -0.03em !important; line-height: 1.15 !important;
    }
    .hero-title span { color: #58a6ff !important; }
    .hero-subtitle {
        font-size: 1rem; color: var(--text-muted) !important;
        max-width: 560px; margin: 0.5rem auto 0; line-height: 1.6;
    }
    .hero-logo { width: 72px; height: 72px; border-radius: 16px; margin-bottom: 0.8rem; object-fit: contain; }

    /* ── Info cards ── */
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
    .info-card {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        padding: 1.3rem 1.4rem;
    }
    .info-card-title { font-size: 0.82rem; font-weight: 600; color: var(--text-muted) !important; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 0.8rem; display: flex; align-items: center; gap: 6px; }
    .info-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 0.87rem; color: var(--text) !important; }
    .info-check { color: #3fb950 !important; font-weight: 700; }

    /* ── Severity badges ── */
    .sev-badge {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 4px 12px; border-radius: 6px; font-size: 0.8rem; font-weight: 600;
        margin: 3px 2px;
    }
    .sev-critical { background: var(--red-soft);    color: #f85149 !important; border: 1px solid rgba(248,81,73,0.3); }
    .sev-high     { background: var(--orange-soft); color: #ffa657 !important; border: 1px solid rgba(255,166,87,0.3); }
    .sev-medium   { background: var(--amber-soft);  color: #d29922 !important; border: 1px solid rgba(210,153,34,0.3); }
    .sev-low      { background: var(--green-soft);  color: #3fb950 !important; border: 1px solid rgba(63,185,80,0.3); }

    /* ── Results panel ── */
    .results-header {
        display: flex; align-items: center; justify-content: space-between;
        padding: 1rem 1.4rem;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius) var(--radius) 0 0;
        margin-top: 1.2rem;
    }
    .results-title { font-size: 0.95rem; font-weight: 700; color: var(--text) !important; display: flex; align-items: center; gap: 8px; }
    .results-body {
        background: var(--surface);
        border: 1px solid var(--border); border-top: none;
        border-radius: 0 0 var(--radius) var(--radius);
        padding: 1.4rem;
    }

    /* ── Alert banners ── */
    .alert {
        display: flex; align-items: flex-start; gap: 10px;
        padding: 0.85rem 1.1rem; border-radius: 8px;
        font-size: 0.87rem; margin-bottom: 0.8rem; line-height: 1.5;
    }
    .alert-icon { font-size: 1rem; flex-shrink: 0; margin-top: 1px; }
    .alert-success { background: var(--green-soft);  color: #3fb950 !important; border: 1px solid rgba(63,185,80,0.3); }
    .alert-warning { background: var(--amber-soft);  color: #d29922 !important; border: 1px solid rgba(210,153,34,0.3); }
    .alert-info    { background: var(--accent-soft); color: #58a6ff !important; border: 1px solid rgba(88,166,255,0.3); }

    /* ── File table ── */
    .file-table-header {
        display: grid; grid-template-columns: 3fr 1fr 1fr;
        padding: 0.5rem 1rem; font-size: 0.72rem; font-weight: 600;
        text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted) !important;
        border-bottom: 1px solid var(--border);
    }
    .file-row {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px; margin: 4px 0; padding: 0.7rem 1rem;
        transition: border-color var(--transition);
    }
    .file-row:hover { border-color: var(--accent); }
    .file-name { font-weight: 600; font-size: 0.88rem; color: var(--text) !important; }
    .file-meta { font-size: 0.75rem; color: var(--text-muted) !important; margin-top: 1px; }

    /* ── Scan history ── */
    .history-item {
        background: var(--surface-2);
        border: 1px solid var(--border-soft);
        border-radius: 8px; padding: 0.8rem 1rem; margin: 6px 0; font-size: 0.84rem;
    }
    .history-meta { color: var(--text-muted) !important; font-size: 0.75rem; }

    /* ── Streamlit widget overrides ── */
    .stTextInput > div > div { background: var(--surface-2) !important; border-color: var(--border) !important; color: var(--text) !important; border-radius: 8px !important; }
    .stTextInput > div > div:focus-within { border-color: var(--accent) !important; box-shadow: 0 0 0 3px var(--accent-soft) !important; }
    .stButton > button {
        background: var(--accent) !important; color: #fff !important;
        border: none !important; border-radius: 8px !important;
        padding: 0.5rem 1.4rem !important; font-weight: 600 !important; font-size: 0.87rem !important;
        transition: all var(--transition) !important; letter-spacing: 0.01em !important;
    }
    .stButton > button:hover { background: #388bfd !important; box-shadow: 0 0 0 3px var(--accent-soft) !important; transform: translateY(-1px) !important; }
    .stButton > button:active { transform: translateY(0) !important; }
    .stDownloadButton > button {
        background: var(--surface-2) !important; color: var(--text) !important;
        border: 1px solid var(--border) !important; border-radius: 8px !important;
        padding: 0.45rem 1.2rem !important; font-weight: 500 !important; font-size: 0.84rem !important;
        transition: all var(--transition) !important;
    }
    .stDownloadButton > button:hover { border-color: var(--accent) !important; color: #58a6ff !important; }
    .stSelectbox [data-baseweb="select"] > div, .stRadio > div, .stCheckbox > label { color: var(--text) !important; }
    div[data-testid="stExpander"] { background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; }
    div[data-testid="stExpander"] summary { color: var(--text) !important; }
    .stSpinner > div { border-color: var(--accent) transparent transparent transparent !important; }
    div[data-testid="stMarkdownContainer"] p,
    div[data-testid="stMarkdownContainer"] li { color: var(--text) !important; }
    div[data-testid="stMarkdownContainer"] h1,
    div[data-testid="stMarkdownContainer"] h2,
    div[data-testid="stMarkdownContainer"] h3 { color: var(--text) !important; }
    div[data-testid="stMarkdownContainer"] code { background: var(--surface-2) !important; color: #79c0ff !important; border-radius: 4px !important; padding: 1px 5px !important; }
    div[data-testid="stMarkdownContainer"] pre { background: var(--surface-2) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; }
    .stAlert { border-radius: 8px !important; }
    .stCodeBlock { border-radius: 8px !important; }
    div[data-testid="stFileUploader"] { background: var(--surface) !important; border: 1px dashed var(--border) !important; border-radius: var(--radius) !important; }
    div[data-testid="stFileUploader"]:hover { border-color: var(--accent) !important; }
    div[data-testid="stFileUploader"] * { color: var(--text) !important; }
    .stSlider [data-testid="stThumbValue"] { background: var(--accent) !important; }

    /* ── Login screen ── */
    .login-wrap {
        max-width: 400px; margin: 6rem auto; text-align: center;
    }
    .login-card {
        background: var(--surface); border: 1px solid var(--border);
        border-radius: 16px; padding: 2.5rem 2rem;
        box-shadow: var(--shadow);
    }
    .login-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }
    .login-title { font-size: 1.4rem; font-weight: 700; color: var(--text) !important; margin-bottom: 0.3rem; }
    .login-sub { font-size: 0.85rem; color: var(--text-muted) !important; margin-bottom: 1.5rem; }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
    </style>
    """, unsafe_allow_html=True)


def initialize_session_state():
    """Initialize all session state variables with defaults."""
    defaults = {
        "messages": [],
        "user_code": "",
        "analysis_cache": {},
        "last_analysis_time": None,
        "connection_status": None,
        "folder_contents": {},
        "file_metadata": {},
        "selected_api": "OpenAI",
        "current_file": None,
        "scan_history": {},
        "confidence_level": "Medium",
        "verify_vulnerabilities": True,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_base64_img(image_path: str) -> str:
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()


def format_user_friendly_results(analysis_results: str):
    """Display contextual banner then full analysis markdown."""
    if "Original Analysis (Not Verified)" in analysis_results:
        m = re.search(r"identified (\d+) potential issues", analysis_results)
        count = m.group(1) if m else "some"
        st.markdown(f"""
            <div class="alert alert-warning">
                <span class="alert-icon">⚠️</span>
                <div>
                    <strong>{count} potential issues found — none passed verification</strong><br>
                    Lower the confidence threshold in the sidebar to "Low" to review them.
                </div>
            </div>
        """, unsafe_allow_html=True)
    elif "[Secure]" in analysis_results and "Vulnerability #" not in analysis_results:
        st.markdown("""
            <div class="alert alert-success">
                <span class="alert-icon">✅</span>
                <div><strong>No vulnerabilities detected</strong> — your code appears secure.</div>
            </div>
        """, unsafe_allow_html=True)
    elif "Vulnerability #" in analysis_results:
        vulns = extract_vulnerabilities(analysis_results)
        critical = sum(1 for v in vulns if v["severity"] == "Critical")
        high     = sum(1 for v in vulns if v["severity"] == "High")
        medium   = sum(1 for v in vulns if v["severity"] == "Medium")
        low      = sum(1 for v in vulns if v["severity"] == "Low")
        badge = lambda cls, label: f'<span class="sev-badge sev-{cls.lower()}">{label}</span>'
        counts = " ".join([
            badge("critical", f"● {critical} Critical") if critical else "",
            badge("high",     f"● {high} High")         if high     else "",
            badge("medium",   f"● {medium} Medium")     if medium   else "",
            badge("low",      f"● {low} Low")           if low      else "",
        ])
        st.markdown(f"""
            <div class="alert alert-warning">
                <span class="alert-icon">🔍</span>
                <div>
                    <strong>{len(vulns)} verified finding{"s" if len(vulns) != 1 else ""}</strong>
                    &nbsp;{counts}
                </div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown(
        '<div class="results-body">',
        unsafe_allow_html=True,
    )
    st.markdown(analysis_results)
    st.markdown("</div>", unsafe_allow_html=True)


def run_analysis(code: str, query: str, filename: str, analyzer: SecurityAnalyzer):
    """Run analysis and optionally verify results. Returns the final analysis string or None on error."""
    result = analyzer.analyze_code(code, query, st.session_state.selected_api.lower(), filename=filename)

    if result["status"] != "success":
        st.markdown(f"""
            <div class="alert alert-warning">
                <span class="alert-icon">❌</span>
                <div><strong>Analysis failed</strong><br>{result['message']}</div>
            </div>
        """, unsafe_allow_html=True)
        return None

    analysis_results = result["analysis"]

    if st.session_state.verify_vulnerabilities:
        with st.spinner("Verifying results to reduce false positives..."):
            analysis_results = verify_all_vulnerabilities(
                analysis_results,
                st.session_state.selected_api.lower(),
                st.session_state.confidence_level
            )

    return analysis_results


def display_results(analysis_results: str, file_key: str):
    """Store scan in history and display results with export buttons."""
    if file_key not in st.session_state.scan_history:
        st.session_state.scan_history[file_key] = []

    st.session_state.scan_history[file_key].append({
        'timestamp': datetime.now().isoformat(),
        'analysis': analysis_results,
        'api': st.session_state.selected_api,
        'confidence_level': st.session_state.confidence_level,
        'verification_used': st.session_state.verify_vulnerabilities,
    })

    ts = datetime.now().strftime("%H:%M:%S")
    api_lbl = st.session_state.selected_api
    conf_lbl = st.session_state.confidence_level
    st.markdown(f"""
        <div class="results-header">
            <div class="results-title">
                🔐 Security Analysis Report
            </div>
            <div style="font-size:0.75rem;color:var(--text-muted);">
                {ts} &nbsp;·&nbsp; {api_lbl} &nbsp;·&nbsp; Confidence: {conf_lbl}
            </div>
        </div>
    """, unsafe_allow_html=True)

    format_user_friendly_results(analysis_results)
    generate_download_report(analysis_results)

    history = st.session_state.scan_history[file_key]
    if len(history) > 1:
        with st.expander(f"Scan history ({len(history)} scans)"):
            for idx, scan in enumerate(reversed(history)):
                verified = "✓ verified" if scan.get('verification_used') else "unverified"
                st.markdown(f"""
                    <div class="history-item">
                        <strong>Scan {len(history) - idx}</strong>
                        <span class="history-meta"> · {scan['timestamp'][:19].replace('T',' ')} · {scan['api']} · {scan.get('confidence_level','—')} · {verified}</span>
                    </div>
                """, unsafe_allow_html=True)
                if st.button("View", key=f"hist_{file_key}_{idx}"):
                    st.markdown(scan['analysis'])


def _render_sidebar(analyzer: SecurityAnalyzer):
    """Render the full sidebar: branding, status, settings, upload."""
    with st.sidebar:
        # ── Brand ──────────────────────────────────────────────────────────
        try:
            img_b64 = get_base64_img("logo.png")
            st.markdown(f"""
                <div class="sidebar-logo">
                    <img src="data:image/png;base64,{img_b64}" width="54" style="border-radius:12px;margin-bottom:6px;">
                    <div class="sidebar-logo-text">CodeGuardianAI</div>
                    <div class="sidebar-logo-sub">Security Analysis Platform</div>
                </div>""", unsafe_allow_html=True)
        except Exception:
            st.markdown("""
                <div class="sidebar-logo">
                    <div style="font-size:2rem;">🛡️</div>
                    <div class="sidebar-logo-text">CodeGuardianAI</div>
                    <div class="sidebar-logo-sub">Security Analysis Platform</div>
                </div>""", unsafe_allow_html=True)

        st.markdown('<hr class="sidebar-divider">', unsafe_allow_html=True)

        # ── Connection status ───────────────────────────────────────────────
        if st.session_state.connection_status is None:
            with st.spinner("Checking connection…"):
                has_internet = check_internet_connection()
                can_reach_api = True
                try:
                    socket.gethostbyname('api.openai.com')
                except socket.gaierror:
                    can_reach_api = False
                st.session_state.connection_status = {
                    'internet': has_internet, 'api': can_reach_api
                }

        conn = st.session_state.connection_status
        net_cls  = "status-online"  if conn['internet'] else "status-offline"
        api_cls  = "status-online"  if conn['api']      else "status-offline"
        net_lbl  = "Internet: Connected"    if conn['internet'] else "Internet: Offline"
        api_lbl  = "API: Reachable"         if conn['api']      else "API: Unreachable"
        st.markdown(f"""
            <div style="padding:0 0 0.4rem;">
                <div class="status-pill {net_cls}"><span class="status-dot"></span>{net_lbl}</div><br>
                <div class="status-pill {api_cls}"><span class="status-dot"></span>{api_lbl}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown('<hr class="sidebar-divider">', unsafe_allow_html=True)

        # ── API provider ────────────────────────────────────────────────────
        st.markdown('<div class="sidebar-section-label">AI Provider</div>', unsafe_allow_html=True)
        api_choice = st.selectbox(
            "API Provider",
            ["OpenAI", "Deepseek"],
            label_visibility="collapsed",
            help="Select which AI provider to use for analysis",
        )
        st.session_state.selected_api = api_choice

        st.markdown('<hr class="sidebar-divider">', unsafe_allow_html=True)

        # ── Analysis settings ───────────────────────────────────────────────
        st.markdown('<div class="sidebar-section-label">Analysis Settings</div>', unsafe_allow_html=True)

        confidence_level = st.select_slider(
            "Confidence Threshold",
            options=["Low", "Medium", "High"],
            value=st.session_state.confidence_level,
            help="Higher = fewer false positives, but might miss subtle issues",
        )
        st.session_state.confidence_level = confidence_level

        verify_toggle = st.checkbox(
            "Verify findings (batch)",
            value=st.session_state.verify_vulnerabilities,
            help="Runs a second-pass verification in a single API call to reduce false positives.",
        )
        st.session_state.verify_vulnerabilities = verify_toggle

        with st.expander("Confidence level guide"):
            st.markdown("""
            - **Low** — Shows all potential issues; may include false positives
            - **Medium** — Balanced; filters low-confidence findings
            - **High** — Only highly confident findings; minimises noise
            """)

        st.markdown('<hr class="sidebar-divider">', unsafe_allow_html=True)

        # ── Upload ──────────────────────────────────────────────────────────
        st.markdown('<div class="sidebar-section-label">Upload Code</div>', unsafe_allow_html=True)

        upload_type = st.radio(
            "Upload type",
            ["Single File", "Directory (ZIP)"],
            label_visibility="collapsed",
        )

        if upload_type == "Single File":
            uploaded_file = st.file_uploader(
                "Drop a file here",
                type=["php", "txt", "py", "js", "java", "cpp", "cs"],
                help="Max 100 KB",
                label_visibility="collapsed",
            )
            if uploaded_file:
                process_single_file(uploaded_file)
        else:
            uploaded_folder = st.file_uploader(
                "Drop a ZIP here",
                type="zip",
                help="Upload a zipped directory of code files",
                label_visibility="collapsed",
            )
            if uploaded_folder:
                folder_contents, file_metadata = process_uploaded_folder(uploaded_folder)
                if folder_contents:
                    st.markdown('<div class="sidebar-section-label" style="margin-top:0.6rem;">Loaded Files</div>', unsafe_allow_html=True)
                    for fname, meta in file_metadata.items():
                        st.caption(f"📄 {fname} — {meta['size_kb']} KB")


def _render_analysis_panel(analyzer: SecurityAnalyzer, code: str, filename: str):
    """Render the scan-type picker, run analysis, and display results."""
    with st.expander(f"📄 View source — {filename}", expanded=False):
        ext = filename.rsplit('.', 1)[-1] if '.' in filename else 'text'
        st.code(code, language=ext)

    analysis_type = st.radio(
        "Scan mode",
        ["Full Security Scan", "Custom Query"],
        horizontal=True,
    )
    query = (
        st.text_input("Describe what to focus on…", placeholder="e.g. Check for SQL injection in the login flow")
        if analysis_type == "Custom Query"
        else "Perform a complete security analysis of the code."
    )

    if not query:
        return

    with st.spinner(f"Scanning with {st.session_state.selected_api}…"):
        analysis_results = run_analysis(code, query, filename, analyzer)

    if analysis_results:
        if (st.session_state.current_file and
                st.session_state.current_file in st.session_state.file_metadata):
            st.session_state.file_metadata[st.session_state.current_file]['scanned'] = True
            st.session_state.file_metadata[st.session_state.current_file]['last_scan'] = (
                datetime.now().strftime("%Y-%m-%d %H:%M")
            )
        display_results(analysis_results, filename)


def main():
    st.set_page_config(
        page_title="CodeGuardianAI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={'Get Help': None, 'Report a bug': None, 'About': None},
    )

    initialize_session_state()
    if not check_password():
        st.stop()

    enhance_streamlit_ui()
    analyzer = SecurityAnalyzer()
    _render_sidebar(analyzer)

    # ── Hero ────────────────────────────────────────────────────────────────
    try:
        img_b64 = get_base64_img("logo.png")
        logo_html = f'<img src="data:image/png;base64,{img_b64}" class="hero-logo">'
    except Exception:
        logo_html = '<div style="font-size:3rem;margin-bottom:0.5rem;">🛡️</div>'

    st.markdown(f"""
        <div class="hero">
            {logo_html}
            <div class="hero-badge">AI-Powered · Multi-Language · v2.1</div>
            <h1 class="hero-title">Code<span>Guardian</span>AI</h1>
            <p class="hero-subtitle">
                Automated security vulnerability analysis powered by OpenAI and Deepseek.
                Upload your code and get a detailed, actionable security report in seconds.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # ── Info cards ──────────────────────────────────────────────────────────
    st.markdown("""
        <div class="info-grid">
            <div class="info-card">
                <div class="info-card-title">🔍 What this tool does</div>
                <div class="info-row"><span class="info-check">✓</span> Scans every line for security vulnerabilities</div>
                <div class="info-row"><span class="info-check">✓</span> Pinpoints exact locations with code snippets</div>
                <div class="info-row"><span class="info-check">✓</span> Provides CWE / OWASP classification</div>
                <div class="info-row"><span class="info-check">✓</span> Gives minimal, actionable fix suggestions</div>
                <div class="info-row"><span class="info-check">✓</span> Batch-verifies findings to cut false positives</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">⚠️ Severity levels</div>
                <div class="info-row"><span class="sev-badge sev-critical">● Critical</span> Direct system compromise — fix now</div>
                <div class="info-row"><span class="sev-badge sev-high">● High</span> Significant impact — fix soon</div>
                <div class="info-row"><span class="sev-badge sev-medium">● Medium</span> Moderate impact — plan to address</div>
                <div class="info-row"><span class="sev-badge sev-low">● Low</span> Limited impact — fix when possible</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # ── Main content ────────────────────────────────────────────────────────
    if st.session_state.folder_contents:
        st.markdown("""
            <div style="font-size:0.72rem;font-weight:600;text-transform:uppercase;
                        letter-spacing:0.08em;color:var(--text-muted);margin-bottom:0.6rem;">
                Project Files
            </div>
        """, unsafe_allow_html=True)

        st.markdown("""
            <div class="file-table-header">
                <span>File</span><span>Status</span><span>Action</span>
            </div>
        """, unsafe_allow_html=True)

        for filename, content in st.session_state.folder_contents.items():
            metadata = st.session_state.file_metadata[filename]
            status_html = (
                '<span class="sev-badge sev-low">✓ Scanned</span>'
                if metadata['scanned']
                else '<span class="sev-badge sev-medium">Pending</span>'
            )
            st.markdown(f"""
                <div class="file-row" style="display:grid;grid-template-columns:3fr 1fr 1fr;align-items:center;">
                    <div>
                        <div class="file-name">📄 {filename}</div>
                        <div class="file-meta">{metadata['size_kb']} KB · {metadata['lines']} lines · .{metadata['extension']}</div>
                    </div>
                    <div>{status_html}</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Analyze →", key=f"analyze_{filename}"):
                st.session_state.current_file = filename
                st.session_state.user_code = content
                metadata['scanned'] = True
                metadata['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M")
                st.rerun()

        if st.session_state.current_file and st.session_state.user_code:
            st.markdown("---")
            st.markdown(f"#### Analyzing: `{st.session_state.current_file}`")
            _render_analysis_panel(
                analyzer,
                st.session_state.user_code,
                st.session_state.current_file,
            )

    elif st.session_state.user_code:
        file_key = st.session_state.current_file or "uploaded_file"
        _render_analysis_panel(analyzer, st.session_state.user_code, file_key)

    else:
        st.markdown("""
            <div style="text-align:center;padding:4rem 2rem;color:var(--text-muted);">
                <div style="font-size:3rem;margin-bottom:1rem;">📂</div>
                <div style="font-size:1.1rem;font-weight:600;margin-bottom:0.4rem;">No code loaded yet</div>
                <div style="font-size:0.88rem;">Upload a file or ZIP archive using the sidebar to begin analysis.</div>
            </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
