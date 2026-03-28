"""SecurityAnalyzer class — extracted from app.py."""

import re
import logging
from datetime import datetime
from typing import Dict

from .api_client import APIClient, APIOptimizer
from .checks import verify_php_security, verify_python_security, verify_javascript_security


def analyze_php_security(code: str, api_type: str) -> dict:
    """Performs an in-depth, multi-pass security analysis of PHP code."""
    client = APIClient(api_type)

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
            secondary = verify_php_security(code, security_analysis)
            if secondary:
                final_analysis = secondary + "\n\n### Initial AI Analysis (Overridden)\n\n" + security_analysis
            else:
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
                    "eval()", "assert() with user input", "create_function()",
                    "preg_replace() with /e modifier",
                    "system()", "exec()", "shell_exec()", "passthru()",
                    "popen()", "proc_open()", "pcntl_exec()",
                    "unserialize()", "json_decode() feeding into unserialize()",
                    "include()/require() with user input",
                    "include_once()/require_once() with user input",
                    "file_get_contents() with URL", "file_put_contents()",
                    "move_uploaded_file()", "readfile()", "fopen()",
                    "mysql_query()", "mysqli_query() without prepared statements",
                    "extract($_GET/$_POST/$_REQUEST/$_COOKIE)",
                    "parse_str() without second arg", "$$variable (variable variables)",
                    "md5() for passwords", "sha1() for passwords",
                    "rand()/mt_rand() for security tokens",
                    "echo/print of unescaped user input",
                    "header() without sanitization (open redirect/injection)",
                    "simplexml_load_string()", "DOMDocument::loadXML()",
                    "SimpleXMLElement()", "XMLReader",
                    "curl_exec() with user-controlled URL",
                    "file_get_contents() with user-controlled URL",
                    "session_id() with user input (session fixation)",
                    "mail() with user-controlled headers",
                ],
            },
            "python": {
                'critical_functions': [
                    "eval()", "exec()", "compile()", "__import__()",
                    "importlib.import_module() with user input",
                    "os.system()", "os.popen()", "os.exec*()",
                    "subprocess.call()", "subprocess.run(shell=True)",
                    "subprocess.Popen(shell=True)", "commands.getoutput()",
                    "pickle.loads()", "pickle.load()", "marshal.loads()",
                    "shelve.open()", "yaml.load() without Loader",
                    "jsonpickle.decode()",
                    "jinja2.Template() with user input",
                    "Mako / Tornado template with user input",
                    "hashlib.md5() for passwords", "hashlib.sha1() for passwords",
                    "random.random()/random.randint() for security tokens",
                    "sqlite3.execute() with string formatting",
                    "cursor.execute() with % or .format()",
                    "xml.etree.ElementTree.parse() — XXE risk",
                    "lxml.etree without resolve_entities=False",
                    "urllib.request.urlopen() with user input",
                    "requests.get/post() with user-controlled URL",
                    "open() in write mode with user-controlled path",
                    "tempfile.mktemp() (TOCTOU race condition)",
                ],
            },
            "javascript": {
                'critical_functions': [
                    "eval()", "new Function()", "setTimeout(string)",
                    "setInterval(string)", "execScript()",
                    "innerHTML", "outerHTML", "insertAdjacentHTML()",
                    "document.write()", "document.writeln()",
                    "$.html() (jQuery)", "dangerouslySetInnerHTML (React)",
                    "v-html (Vue)", "bypassSecurityTrust* (Angular)",
                    "window.location = user_input",
                    "location.href = user_input",
                    "Object.assign() with user input",
                    "merge/extend functions with user input",
                    "child_process.exec()", "child_process.execSync()",
                    "child_process.spawn(shell:true)",
                    "require() with user input",
                    "Math.random() for security tokens",
                    "crypto.createHash('md5') for passwords",
                    "localStorage.setItem() with sensitive data",
                    "document.cookie with missing Secure/HttpOnly",
                    "postMessage() without origin validation",
                    "addEventListener('message') without origin check",
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
        if re.search(r'<\?php', code):
            return 'php'
        return None

    def create_enhanced_prompt(self, code: str, language: str = None) -> str:
        lang = language if language else "code"

        category_block = ""
        for category, checks in self.vulnerability_categories.items():
            indicator = self._get_severity_indicator(category)
            category_block += f"\n  {indicator} {category.upper()}: {', '.join(checks)}"

        lang_block = ""
        if language and language.lower() in self.language_specific_checks:
            funcs = self.language_specific_checks[language.lower()]['critical_functions']
            lang_block = f"\n\n{language.upper()} DANGEROUS FUNCTIONS/PATTERNS TO CHECK:\n"
            for f in funcs:
                lang_block += f"  • {f}\n"

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

            cached_result = api_optimizer.get_cached_analysis(code, user_query)
            if cached_result:
                logging.info("Using cached analysis results")
                return cached_result

            language = self._detect_language(code, filename)

            if language == 'php':
                result = analyze_php_security(code, api_type)
            else:
                result = self._analyze_generic(code, user_query, api_type, language)

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
