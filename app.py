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
import time
from datetime import datetime
import socket
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import json
from pathlib import Path
import zipfile
import io

# Setup logging - minimal output
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_analyzer.log')
    ]
)

# Load environment variables
load_dotenv()

REQUIRED_KEYS = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
    "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY"),
}


def check_internet_connection(host="8.8.8.8", port=53, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        return False
    finally:
        s.close()


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
    """Provide download link for text report without auto-saving."""
    try:
        if not analysis_results:
            st.error("No analysis results available to generate report")
            return
        report_content, filename = generate_text_report(analysis_results)
        st.download_button(
            label="Download Analysis Report",
            data=report_content,
            file_name=filename,
            mime="text/plain",
            key="download_report"
        )
    except Exception as e:
        st.error(f"Error generating text report: {str(e)}")
        logging.error(f"Text file generation error: {str(e)}", exc_info=True)


class APIOptimizer:
    def __init__(self):
        self.cache_file = "analysis_cache.json"
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.cache = {}

    def get_code_hash(self, code: str) -> str:
        return hashlib.sha256(code.encode()).hexdigest()

    def get_cached_analysis(self, code: str, query: str = None) -> dict:
        """Retrieve cached analysis if available and fresh (within 24 hours)."""
        code_hash = self.get_code_hash(code)
        query_hash = hashlib.sha256(str(query).encode()).hexdigest() if query else "full_scan"
        cache_key = f"{code_hash}_{query_hash}"
        if cache_key in self.cache:
            cached_time = datetime.fromisoformat(self.cache[cache_key]['timestamp'])
            if (datetime.now() - cached_time).total_seconds() < 86400:
                return self.cache[cache_key]['results']
        return None

    def cache_analysis(self, code: str, query: str, results: dict):
        """Store analysis results in cache for later use."""
        code_hash = self.get_code_hash(code)
        query_hash = hashlib.sha256(str(query).encode()).hexdigest() if query else "full_scan"
        cache_key = f"{code_hash}_{query_hash}"
        self.cache[cache_key] = {
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
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
            openai.api_key = os.getenv("OPENAI_API_KEY")
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
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=messages,
                    temperature=kwargs.get('temperature', 0.1),
                    max_tokens=kwargs.get('max_tokens', 3000)
                )
                content = response.choices[0].message.content
                return _APIResponse(content)

            elif self.api_type == "deepseek":
                payload = {
                    "model": "deepseek-chat",
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
            error_msg = str(e)
            logging.error(f"Analysis error: {error_msg}")
            return {
                "status": "error",
                "message": f"Analysis failed: {error_msg}"
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


def verify_vulnerability(vulnerability_details: dict, code_snippet: str, api_type: str) -> dict:
    """Performs a secondary verification of a reported vulnerability to reduce false positives."""
    try:
        client = APIClient(api_type)
        verification_prompt = f"""You are a security expert tasked with verifying if a reported vulnerability is an actual security issue or a false positive.

REPORTED VULNERABILITY:
Type: {vulnerability_details['type']}
Severity: {vulnerability_details['severity']}
Location: {vulnerability_details['location']}

CODE SNIPPET:
{code_snippet}

TASK:
Carefully analyze this code and determine if this is truly a vulnerability or a false positive.

Consider:
1. Is the code actually exploitable, or just theoretically vulnerable?
2. Are there mitigating factors elsewhere in the code?
3. Is this a legitimate security concern or a coding style issue?
4. Would an attacker actually be able to exploit this?

Respond with:
- Verdict: [TRUE POSITIVE or FALSE POSITIVE]
- Confidence: [percentage 0-100]
- Explanation: [detailed justification for your verdict]
"""
        messages = [
            {"role": "system", "content": "You are a security verification expert. Determine if reported vulnerabilities are real issues or false positives."},
            {"role": "user", "content": verification_prompt}
        ]

        response = client.create_completion(messages=messages, temperature=0, max_tokens=1000)
        content = response.choices[0].message.content

        verdict_match = re.search(r"Verdict:\s*(TRUE POSITIVE|FALSE POSITIVE)", content, re.IGNORECASE)
        confidence_match = re.search(r"Confidence:\s*(\d+)", content)
        explanation_match = re.search(r"Explanation:\s*(.*?)(?=$|\n\n)", content, re.DOTALL)

        verdict = verdict_match.group(1) if verdict_match else "UNCERTAIN"
        confidence = int(confidence_match.group(1)) if confidence_match else 50
        explanation = explanation_match.group(1).strip() if explanation_match else "No explanation provided."

        return {
            "verdict": verdict.upper(),
            "confidence": confidence,
            "explanation": explanation,
            "raw_response": content
        }

    except Exception as e:
        logging.error(f"Verification error: {str(e)}")
        return {
            "verdict": "ERROR",
            "confidence": 0,
            "explanation": f"Error during verification: {str(e)}",
            "raw_response": ""
        }


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

    verified_vulnerabilities = []
    for vuln in vulnerabilities:
        verification = verify_vulnerability(vuln, vuln["code_snippet"], api_type)
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
        error_msg = str(e)
        logging.error(f"PHP security analysis error: {error_msg}")
        return {
            "status": "error",
            "message": f"PHP security analysis failed: {error_msg}"
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
        st.error(f"Error reading file: {str(e)}")
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
    """Add enhanced UI styles to Streamlit."""
    st.markdown("""
        <style>
        .stApp { background-color: #f8f9fa !important; }
        .main-header {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            padding: 2rem 0 !important;
            background: linear-gradient(to right, #1a1f2c, #2c3e50) !important;
            border-radius: 10px !important;
            margin-bottom: 2rem !important;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1) !important;
        }
        .logo-title-container { display: flex !important; align-items: center !important; gap: 20px !important; }
        .logo-image { width: 120px !important; height: auto !important; }
        .title-text {
            color: #ffffff !important;
            font-size: 2.5rem !important;
            font-weight: bold !important;
            margin: 0 !important;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3) !important;
        }
        .feature-card {
            background-color: #ffffff !important;
            padding: 1.5rem !important;
            border-radius: 10px !important;
            margin: 1rem 0 !important;
            border: 1px solid #e9ecef !important;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05) !important;
            transition: transform 0.2s !important;
            color: #1a1f2c !important;
        }
        .feature-card:hover { transform: translateY(-2px) !important; box-shadow: 0 4px 8px rgba(0,0,0,0.1) !important; }
        .icon-title { display: flex !important; align-items: center !important; gap: 10px !important; margin-bottom: 1rem !important; color: #1a1f2c !important; }
        .severity-indicator { display: inline-flex !important; align-items: center !important; gap: 8px !important; padding: 4px 8px !important; border-radius: 4px !important; margin: 4px 0 !important; font-weight: 500 !important; }
        .severity-critical { background-color: #ff4444 !important; color: #ffffff !important; }
        .severity-high { background-color: #ffbb33 !important; color: #000000 !important; }
        .severity-medium { background-color: #ffeb3b !important; color: #333333 !important; }
        .severity-low { background-color: #00C851 !important; color: #ffffff !important; }
        .stButton>button {
            background: linear-gradient(to right, #4CAF50, #45a049) !important;
            color: #ffffff !important;
            border-radius: 5px !important;
            border: none !important;
            padding: 10px 24px !important;
            font-weight: 500 !important;
            transition: all 0.3s !important;
        }
        .stButton>button:hover { transform: translateY(-1px) !important; box-shadow: 0 4px 8px rgba(0,0,0,0.1) !important; }
        .upload-section { background-color: #ffffff !important; padding: 2rem !important; border-radius: 10px !important; border: 2px dashed #cccccc !important; text-align: center !important; }
        .icon-text { display: flex !important; align-items: center !important; gap: 8px !important; margin: 8px 0 !important; color: #1a1f2c !important; }
        .stMarkdown, p, li { color: #1a1f2c !important; }
        h1, h2, h3, h4, h5, h6 { color: #1a1f2c !important; }
        .icon-text span:first-child { color: #00C851 !important; font-weight: bold !important; }
        @media (prefers-color-scheme: dark) {
            .stApp { background-color: #1a1f2c !important; }
            .feature-card { background-color: #2c3e50 !important; color: #ffffff !important; }
            .upload-section { background-color: #2c3e50 !important; border-color: #666666 !important; }
            .stMarkdown, p, li { color: #ffffff !important; }
            h1, h2, h3, h4, h5, h6 { color: #ffffff !important; }
            .icon-title, .icon-text { color: #ffffff !important; }
        }
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
    """Display banner messages based on analysis outcome."""
    if "Original Analysis (Not Verified)" in analysis_results:
        potential_issues_match = re.search(r"identified (\d+) potential issues", analysis_results)
        issue_count = potential_issues_match.group(1) if potential_issues_match else "some"
        st.warning("Potential vulnerabilities detected but not verified")
        st.markdown(
            f"The initial analysis found **{issue_count} potential security issues**, "
            "but they did not pass verification at your current confidence threshold."
        )
        st.info("Tip: Lower your confidence threshold to 'Low' in settings to see these potential issues.")
    elif "[Secure]" in analysis_results and "Vulnerability #" not in analysis_results:
        st.success("Your code appears to be secure! No vulnerabilities were detected.")

    st.markdown(analysis_results)


def run_analysis(code: str, query: str, filename: str, analyzer: SecurityAnalyzer):
    """Run analysis and optionally verify results. Returns the final analysis string or None on error."""
    result = analyzer.analyze_code(code, query, st.session_state.selected_api.lower(), filename=filename)

    if result["status"] != "success":
        st.error(f"Analysis failed: {result['message']}")
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
    """Store scan in history and display analysis results."""
    if file_key not in st.session_state.scan_history:
        st.session_state.scan_history[file_key] = []

    st.session_state.scan_history[file_key].append({
        'timestamp': datetime.now().isoformat(),
        'analysis': analysis_results,
        'api': st.session_state.selected_api,
        'confidence_level': st.session_state.confidence_level,
        'verification_used': st.session_state.verify_vulnerabilities
    })

    st.markdown("### Analysis Results")
    format_user_friendly_results(analysis_results)
    generate_download_report(analysis_results)

    history = st.session_state.scan_history[file_key]
    if len(history) > 1:
        with st.expander("View Scan History"):
            for idx, scan in enumerate(reversed(history)):
                st.markdown(f"**Scan {idx + 1}** — {scan['timestamp']}")
                st.markdown(f"API: {scan['api']} | Confidence: {scan.get('confidence_level', 'N/A')}")
                if st.button("Show Results", key=f"history_{file_key}_{idx}"):
                    st.markdown(scan['analysis'])


def main():
    st.set_page_config(
        page_title="CodeGuardianAI v2",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={'Get Help': None, 'Report a bug': None, 'About': None}
    )

    initialize_session_state()
    analyzer = SecurityAnalyzer()
    enhance_streamlit_ui()

    # Header with logo
    try:
        img_base64 = get_base64_img("logo.png")
        st.markdown(f"""
            <div class="main-header">
                <div class="logo-title-container">
                    <img src="data:image/png;base64,{img_base64}" class="logo-image">
                    <h1 class="title-text">CodeGuardianAI</h1>
                </div>
            </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.markdown("""
            <div class="main-header">
                <div class="logo-title-container">
                    <h1 class="title-text">CodeGuardianAI</h1>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # Feature cards
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
            <div class="feature-card">
                <div class="icon-title"><span style="font-size:24px;">&#128269;</span><h3>What This Tool Does:</h3></div>
                <div class="icon-text"><span>&#10003;</span><span>Scans Your Code: Checks every line for security problems</span></div>
                <div class="icon-text"><span>&#10003;</span><span>Simple Explanations: Describes issues in easy-to-understand terms</span></div>
                <div class="icon-text"><span>&#10003;</span><span>Shows Exact Problems: Highlights exactly where the issues are</span></div>
                <div class="icon-text"><span>&#10003;</span><span>Provides Solutions: Gives step-by-step instructions to fix each issue</span></div>
            </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
            <div class="feature-card">
                <div class="icon-title"><span style="font-size:24px;">&#9888;&#65039;</span><h3>Severity Levels:</h3></div>
                <div class="severity-indicator severity-critical"><span>&#9679;</span><span>Critical Risk: Needs immediate attention</span></div>
                <div class="severity-indicator severity-high"><span>&#9679;</span><span>High Risk: Should be fixed soon</span></div>
                <div class="severity-indicator severity-medium"><span>&#9679;</span><span>Medium Risk: Plan to address</span></div>
                <div class="severity-indicator severity-low"><span>&#9679;</span><span>Low Risk: Good to fix when possible</span></div>
            </div>
        """, unsafe_allow_html=True)

    # Connection check (only once per session)
    if st.session_state.connection_status is None:
        with st.spinner("Checking connection..."):
            has_connection = check_internet_connection()
            can_reach_api = True
            try:
                socket.gethostbyname('api.openai.com')
            except socket.gaierror:
                can_reach_api = False
            st.session_state.connection_status = {'internet': has_connection, 'api': can_reach_api}

    # Sidebar settings
    with st.sidebar:
        st.header("Settings")

        api_choice = st.selectbox(
            "Choose API Provider",
            ["OpenAI", "Deepseek"],
            help="Select which AI provider to use for analysis"
        )
        st.session_state.selected_api = api_choice

        st.subheader("False Positive Control")
        confidence_level = st.select_slider(
            "Confidence Threshold",
            options=["Low", "Medium", "High"],
            value=st.session_state.confidence_level,
            help="Higher settings reduce false positives but might miss some issues"
        )
        st.session_state.confidence_level = confidence_level

        verify_toggle = st.checkbox(
            "Verify vulnerabilities (reduces false positives)",
            value=st.session_state.verify_vulnerabilities,
            help="Runs a secondary verification pass on each finding. Doubles API calls but greatly improves accuracy."
        )
        st.session_state.verify_vulnerabilities = verify_toggle

        with st.expander("About Confidence Levels"):
            st.markdown("""
            - **Low**: Shows all potential issues, may include false positives
            - **Medium**: Balanced approach, filters some uncertain findings
            - **High**: Only shows issues with high confidence, minimizes false positives
            """)

        upload_type = st.radio(
            "Upload Type",
            ["Single File", "Directory"],
            help="Choose to upload a single file or entire directory"
        )

        if upload_type == "Single File":
            uploaded_file = st.file_uploader(
                "Upload Code File",
                type=["php", "txt", "py", "js", "java", "cpp", "cs"],
                help="Maximum file size: 100KB"
            )
            if uploaded_file:
                process_single_file(uploaded_file)
        else:
            uploaded_folder = st.file_uploader(
                "Upload Directory",
                type="zip",
                help="Upload a zipped directory of code files"
            )
            if uploaded_folder:
                folder_contents, file_metadata = process_uploaded_folder(uploaded_folder)
                if folder_contents:
                    st.markdown("### Files Overview")
                    for filename, metadata in file_metadata.items():
                        st.text(f"{filename} ({metadata['size_kb']}KB)")

    # Main content area
    if st.session_state.folder_contents:
        st.markdown("### Project Files")

        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.markdown("**Filename**")
        with col2:
            st.markdown("**Status**")
        with col3:
            st.markdown("**Actions**")

        for filename, content in st.session_state.folder_contents.items():
            metadata = st.session_state.file_metadata[filename]
            with st.container():
                cols = st.columns([2, 1, 1])
                with cols[0]:
                    st.markdown(f"**{filename}**  \n_{metadata['size_kb']}KB, {metadata['lines']} lines_")
                with cols[1]:
                    if metadata['scanned']:
                        st.success("Scanned")
                        st.caption(f"Last: {metadata['last_scan']}")
                    else:
                        st.warning("Not scanned")
                with cols[2]:
                    if st.button("Analyze", key=f"analyze_{filename}"):
                        st.session_state.current_file = filename
                        st.session_state.user_code = content
                        metadata['scanned'] = True
                        metadata['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M")
                        st.rerun()

        if st.session_state.current_file and st.session_state.user_code:
            st.markdown("---")
            st.markdown(f"### Analyzing: {st.session_state.current_file}")

            with st.expander("View File Content"):
                ext = st.session_state.current_file.rsplit('.', 1)[-1]
                st.code(st.session_state.user_code, language=ext)

            analysis_type = st.radio(
                "Choose what to focus on:",
                ["Full Security Scan", "Custom Query"],
                horizontal=True
            )

            query = None
            if analysis_type == "Custom Query":
                query = st.text_input("Type your specific security question here...")
            else:
                query = "Perform a complete security analysis of the code."

            if query:
                with st.spinner(f"Analyzing using {st.session_state.selected_api}..."):
                    analysis_results = run_analysis(
                        st.session_state.user_code, query,
                        st.session_state.current_file, analyzer
                    )
                if analysis_results:
                    display_results(analysis_results, st.session_state.current_file)

    elif st.session_state.user_code:
        st.markdown("### Analysis Options")
        analysis_type = st.radio(
            "Choose what to focus on:",
            ["Full Security Scan", "Custom Query"],
            horizontal=True
        )

        query = None
        if analysis_type == "Custom Query":
            query = st.text_input("Type your specific security question here...")
        else:
            query = "Perform a complete security analysis of the code."

        # Use the actual filename or fall back to a stable key
        file_key = st.session_state.current_file or "uploaded_file"

        if query:
            with st.spinner(f"Analyzing using {st.session_state.selected_api}..."):
                analysis_results = run_analysis(
                    st.session_state.user_code, query, file_key, analyzer
                )
            if analysis_results:
                # Update file metadata if it exists
                if (st.session_state.current_file and
                        st.session_state.current_file in st.session_state.file_metadata):
                    st.session_state.file_metadata[st.session_state.current_file]['scanned'] = True
                    st.session_state.file_metadata[st.session_state.current_file]['last_scan'] = (
                        datetime.now().strftime("%Y-%m-%d %H:%M")
                    )
                display_results(analysis_results, file_key)

    else:
        st.info("Please upload your code using the sidebar to begin analysis")


if __name__ == "__main__":
    main()
