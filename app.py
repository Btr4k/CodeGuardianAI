import streamlit as st
import openai
import os
from PIL import Image
import requests
from dotenv import load_dotenv
from typing import Dict, List, Tuple
import hashlib
import logging
import time
from datetime import datetime
import socket
import re
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import json
from pathlib import Path
import zipfile
import io

# Setup logging - minimal output
logging.basicConfig(
    level=logging.ERROR,  # Only show errors
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_analyzer.log')
    ]
)

# Load environment variables
load_dotenv()

# Check for required API keys
REQUIRED_KEYS = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
    "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY"),
}

import socket

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


def generate_text_report(analysis_results: str, base_filename: str = "security_analysis_report") -> str:
    """Generate a text report content without saving to file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_filename}_{timestamp}.txt"
    report_content = f"""
==============================================
CodeGuardianAI Security Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==============================================

{analysis_results}
"""
    return report_content, filename

def generate_download_report(analysis_results):
    """Provide download link for text report without auto-saving"""
    try:
        if not analysis_results:
            st.error("No analysis results available to generate report")
            return
            
        # Generate the report content
        report_content, filename = generate_text_report(analysis_results)
        
        # Provide download button
        st.download_button(
            label="⬇️ Download Analysis Report",
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
        """Generate a unique hash of the code."""
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
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f)

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

    def create_completion(self, messages: list, **kwargs) -> dict:
        """Create completion with the chosen API provider."""
        try:
            if self.api_type == "openai":
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=messages,
                    temperature=kwargs.get('temperature', 0.1),
                    max_tokens=kwargs.get('max_tokens', 3000)
                )
                return response

            elif self.api_type == "deepseek":
                payload = {
                    "model": "deepseek-chat",
                    "messages": messages,
                    "temperature": kwargs.get('temperature', 0.1),
                    "max_tokens": kwargs.get('max_tokens', 3000),
                    "stream": False
                }
                response = self.session.post("https://api.deepseek.com/v1/chat/completions", json=payload)
                resp_data = response.json()

                if not resp_data.get('choices'):
                    raise ValueError("No response choices available")
                content = resp_data['choices'][0]['message'].get('content')
                if not content:
                    raise ValueError("No content in API response")

                # Simulate OpenAI response structure for consistency
                return type('Response', (), {
                    'choices': [type('Choice', (), {
                        'message': type('Message', (), {'content': content})
                    })]
                })
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            raise ValueError(f"API request failed: {str(e)}")
        except Exception as e:
            logging.error(f"API error: {str(e)}")
            raise ValueError(f"API error: {str(e)}")


import logging
from datetime import datetime
from typing import Dict

class SecurityAnalyzer:
    def __init__(self):
        # Expanded vulnerability categories
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
                    "echo without htmlspecialchars()"
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

    def create_enhanced_prompt(self, code: str, language: str = None) -> str:
        # Define severity color formatting
        severity_formats = {
            "CRITICAL": "🔴 Critical",
            "HIGH": "🟠 High",
            "MEDIUM": "🟡 Medium",
            "LOW": "🟢 Low",
            "INFO": "🔵 Info",
            "SECURE": "✅ Secure"

        }
        
        # Create severity legend
        severity_legend = "\nSEVERITY LEVELS:\n"
        for severity, formatted in severity_formats.items():
            severity_legend += f"- {formatted}: {self._get_severity_description(severity)}\n"

        lang = language if language else "code"
        base_prompt = f"""You are a security expert. Analyze the following {lang} for vulnerabilities. 
        
        IMPORTANT: Be very careful to avoid false positives. Only report issues that you are confident are actual vulnerabilities with real security impact. If you're uncertain about something, classify it as INFO rather than a vulnerability. If the code appears secure, explicitly state that no vulnerabilities were found.
        
        {severity_legend}
        
        For each confirmed finding, follow this format:
        ## [Severity Indicator] Vulnerability #[N]: [Type]
        Example headers:
        - ## [🔴 Critical] Vulnerability #1: Remote Code Execution
        - ## [🟠 High] Vulnerability #2: SQL Injection
        - ## [🟡 Medium] Vulnerability #3: XSS Vulnerability
        - ## [🟢 Low] Vulnerability #4: Information Disclosure
        - ## [🔵 Info] Note #1: Potential concern (but not confirmed vulnerability)
        
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
        ## [✅ Secure] No Vulnerabilities Detected
        Then explain why the code appears secure and any best practices it follows.

        Analyze the code below:
        {code}
        """
        # List all vulnerability categories with severity indicators
        base_prompt += "\n\nVULNERABILITY CATEGORIES TO CHECK:"
        for category, checks in self.vulnerability_categories.items():
            cat_upper = category.upper()
            checks_str = ", ".join(checks)
            # Add appropriate severity indicator based on category
            severity_indicator = self._get_severity_indicator(category)
            base_prompt += f"\n- {severity_indicator} {cat_upper}: {checks_str}"

        # Add language-specific checks if available
        if language and language.lower() in self.language_specific_checks:
            funcs = self.language_specific_checks[language.lower()]['critical_functions']
            base_prompt += f"\n\n{language.upper()} SPECIFIC CHECKS:"
            base_prompt += f"\n- 🔴 Review dangerous functions: {', '.join(funcs)}"

        base_prompt += "\n\nIMPORTANT: Before reporting any vulnerability, validate that it is exploitable and not just a theoretical concern. It's better to miss a low-severity issue than report a false positive."
        return base_prompt

    def _get_severity_description(self, severity: str) -> str:
        """Return description for each severity level"""
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
        """Return appropriate severity indicator based on vulnerability category"""
        indicators = {
            "injection": "🔴",  # Critical
            "rce": "🔴",       # Critical
            "auth": "🟠",      # High
            "data": "🟡"       # Medium
        }
        return indicators.get(category.lower(), "🟢")  # Default to Low if category not found

    def analyze_code(self, code: str, user_query: str, api_type: str) -> Dict:
        """Analyze code using the selected API with caching."""
        try:
            # Initialize API optimizer for caching
            api_optimizer = APIOptimizer()
            
            # Check cache first
            cached_result = api_optimizer.get_cached_analysis(code, user_query)
            if cached_result:
                logging.info("Using cached analysis results")
                return cached_result

            client = APIClient(api_type)
            analysis_prompt = self.create_enhanced_prompt(code)
            
            if user_query:
                analysis_prompt += f"\n\nFOCUS AREA: {user_query}"

            messages = [
                {"role": "system", "content": "You are a security analyst. Analyze the code thoroughly and report any security vulnerabilities."},
                {"role": "user", "content": analysis_prompt}
            ]

            logging.info(f"Starting analysis with {api_type} API...")
            response = client.create_completion(
                messages=messages,
                temperature=0.1,
                max_tokens=3000,
                presence_penalty=0.2,
                frequency_penalty=0.3
            )
            
            # Validate response structure
            if not hasattr(response, 'choices') or not response.choices:
                raise ValueError("No response choices available")
            if not hasattr(response.choices[0], 'message'):
                raise ValueError("No message in response choice")
            if not hasattr(response.choices[0].message, 'content'):
                raise ValueError("No content in response message")
            
            content = response.choices[0].message.content
            if not content:
                raise ValueError("Empty response content")
            
            # Post-process to filter potential false positives
            processed_content = self._filter_low_confidence_findings(content)
            
            result = {
                "status": "success",
                "analysis": content,
                "metadata": {
                    "api": api_type,
                    "timestamp": datetime.now().isoformat(),
                    "query": user_query
                }
            }
            
            # Cache successful results
            api_optimizer.cache_analysis(code, user_query, result)
            logging.info("Analysis completed successfully")
            return result

        except Exception as e:
            error_msg = str(e)
            logging.error(f"Analysis error: {error_msg}")
            return {
                "status": "error",
                "message": f"Analysis failed: {error_msg}"
            }

    def _filter_low_confidence_findings(self, content: str) -> str:
        """Filter out low confidence findings from the analysis results."""
        import re
        
        # If it explicitly states code is secure, return as is
        if "[✅ Secure] No Vulnerabilities Detected" in content:
            return content
            
        # Add a summary header if not present
        if not content.startswith("## Summary"):
            summary = "\n## Summary\n"
            
            # Count vulnerabilities by severity
            critical = len(re.findall(r"\[🔴 Critical\]", content))
            high = len(re.findall(r"\[🟠 High\]", content))
            medium = len(re.findall(r"\[🟡 Medium\]", content))
            low = len(re.findall(r"\[🟢 Low\]", content))
            info = len(re.findall(r"\[🔵 Info\]", content))
            
            total_vulns = critical + high + medium + low
            
            if total_vulns == 0:
                summary += "✅ No confirmed vulnerabilities detected.\n\n"
                
                if info > 0:
                    summary += f"🔵 {info} informational note(s) provided.\n\n"
                
                # If no vulnerabilities but also no explicit secure statement, add one
                if "[✅ Secure]" not in content:
                    content = "## [✅ Secure] No Vulnerabilities Detected\n\nThe code appears to be secure based on the analysis. No exploitable vulnerabilities were identified.\n\n" + content
            else:
                summary += f"Found {total_vulns} potential security issue(s):\n"
                if critical > 0:
                    summary += f"- 🔴 {critical} Critical\n"
                if high > 0:
                    summary += f"- 🟠 {high} High\n"
                if medium > 0:
                    summary += f"- 🟡 {medium} Medium\n"
                if low > 0:
                    summary += f"- 🟢 {low} Low\n"
                if info > 0:
                    summary += f"- 🔵 {info} Info\n"
                
                summary += "\nPlease review each finding carefully to confirm it's a real vulnerability.\n\n"
            
            # Add summary to beginning of content
            content = summary + content
        
        return content
    
def verify_vulnerability(vulnerability_details: dict, code_snippet: str, api_type: str) -> dict:
    """
    Performs a secondary verification of a reported vulnerability to reduce false positives.
    
    Args:
        vulnerability_details: Dictionary containing vulnerability info
        code_snippet: The code snippet where the vulnerability was found
        api_type: Which API to use for verification
        
    Returns:
        Dictionary with verification results
    """
    try:
        client = APIClient(api_type)
        
        # Create a focused prompt that challenges the vulnerability
        verification_prompt = f"""
You are a security expert tasked with verifying if a reported vulnerability is an actual security issue or a false positive.

REPORTED VULNERABILITY:
Type: {vulnerability_details['type']}
Severity: {vulnerability_details['severity']}
Location: {vulnerability_details['location']}

CODE SNIPPET:
```
{code_snippet}
```

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
            {"role": "system", "content": "You are a security verification expert. Your job is to determine if reported vulnerabilities are real issues or false positives."},
            {"role": "user", "content": verification_prompt}
        ]
        
        response = client.create_completion(
            messages=messages,
            temperature=0,  # Use 0 for most consistent results
            max_tokens=1000
        )
        
        content = response.choices[0].message.content
        
        # Parse the verification results
        import re
        
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
    """
    Extracts individual vulnerabilities from the analysis text
    
    Args:
        analysis_text: The full analysis text
        
    Returns:
        List of dictionaries containing vulnerability details
    """
    import re
    
    # Find all vulnerability sections
    vulnerability_pattern = r"##\s*\[(🔴|🟠|🟡|🟢)\s*(\w+)\]\s*Vulnerability\s*#(\d+):\s*([^\n]+)"
    vulnerability_matches = re.finditer(vulnerability_pattern, analysis_text)
    
    vulnerabilities = []
    
    for match in vulnerability_matches:
        emoji, severity, number, vuln_type = match.groups()
        
        # Find the location
        location_match = re.search(r"\*\*Location:\*\*\s*Lines\s*(\d+-\d+)", analysis_text[match.end():], re.DOTALL)
        location = location_match.group(1) if location_match else "Unknown"
        
        # Find the code snippet
        snippet_match = re.search(r"\*\*Code Snippet:\*\*\s*```[^\n]*\n(.*?)```", analysis_text[match.end():], re.DOTALL)
        code_snippet = snippet_match.group(1).strip() if snippet_match else ""
        
        # Get the end of this vulnerability section (start of next section or end of text)
        next_section = re.search(r"##\s*\[", analysis_text[match.end():])
        end_pos = match.end() + next_section.start() if next_section else len(analysis_text)
        
        vulnerabilities.append({
            "emoji": emoji,
            "severity": severity,
            "number": number,
            "type": vuln_type,
            "location": location,
            "code_snippet": code_snippet,
            "full_content": analysis_text[match.start():end_pos].strip()
        })
    
    return vulnerabilities

def verify_all_vulnerabilities(analysis_text: str, api_type: str, confidence_threshold: str) -> str:
    """
    Verifies all vulnerabilities in the analysis and filters based on confidence threshold
    
    Args:
        analysis_text: The full analysis text
        api_type: Which API to use for verification
        confidence_threshold: User's confidence threshold setting (Low/Medium/High)
        
    Returns:
        Updated analysis text with verification results
    """
    # Extract vulnerabilities
    vulnerabilities = extract_vulnerabilities(analysis_text)
    
    if not vulnerabilities:
        return analysis_text
    
    # Set confidence thresholds based on user preference
    threshold_values = {
        "Low": 30,
        "Medium": 60,
        "High": 80
    }
    threshold = threshold_values.get(confidence_threshold, 60)
    
    # Verify each vulnerability
    verified_vulnerabilities = []
    for vuln in vulnerabilities:
        verification = verify_vulnerability(vuln, vuln["code_snippet"], api_type)
        vuln["verification"] = verification
        
        # Keep only if confidence exceeds threshold
        if verification["verdict"] == "TRUE POSITIVE" and verification["confidence"] >= threshold:
            verified_vulnerabilities.append(vuln)
    
    # If no vulnerabilities passed verification, the code is likely secure
    if not verified_vulnerabilities:
        return "## [✅ Secure] No Verified Vulnerabilities Detected\n\n" + \
               f"The initial analysis identified {len(vulnerabilities)} potential issues, " + \
               f"but none of them passed the verification process with the current confidence threshold ({confidence_threshold}).\n\n" + \
               "### Original Analysis (Not Verified)\n\n" + analysis_text
    
    # Otherwise, build a new analysis with only verified vulnerabilities
    new_analysis = "## Summary\n\n"
    new_analysis += f"Found {len(verified_vulnerabilities)} verified vulnerabilities out of {len(vulnerabilities)} reported issues.\n\n"
    
    # Count by severity
    severity_counts = {}
    for vuln in verified_vulnerabilities:
        severity = vuln["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(severity, "")
        new_analysis += f"- {emoji} {count} {severity}\n"
    
    new_analysis += "\n\n"
    
    # Add each verified vulnerability
    for i, vuln in enumerate(verified_vulnerabilities, 1):
        # Update the vulnerability number
        updated_content = re.sub(
            r"##\s*\[(🔴|🟠|🟡|🟢)\s*(\w+)\]\s*Vulnerability\s*#\d+:", 
            f"## [{vuln['emoji']} {vuln['severity']}] Vulnerability #{i}:", 
            vuln["full_content"]
        )
        
        # Add verification info
        verification_info = f"\n\n**Verification:** Confirmed with {vuln['verification']['confidence']}% confidence\n"
        verification_info += f"**Justification:** {vuln['verification']['explanation']}\n"
        
        # Insert verification info before the end of the vulnerability section
        updated_content += verification_info
        
        new_analysis += updated_content + "\n\n"
    
    # Note about filtered vulnerabilities
    filtered_count = len(vulnerabilities) - len(verified_vulnerabilities)
    if filtered_count > 0:
        new_analysis += f"### Note\n\n{filtered_count} potential issues were filtered out due to insufficient confidence.\n"
    
    return new_analysis

def format_user_friendly_results(analysis_results, st):
    """Format analysis results in a more user-friendly way"""
    import re
    
    # Create tabbed interface for technical vs. simple view
    tab1, tab2 = st.tabs(["Simple View", "Technical View"])
    
    # Technical view - original markdown
    with tab2:
        st.markdown(analysis_results)
    
    # Simple view - more user-friendly presentation
    with tab1:
        # Handle different security states by checking specific text patterns
        if "Original Analysis (Not Verified)" in analysis_results:
            # This means we found issues but they were filtered out during verification
            potential_issues_match = re.search(r"identified (\d+) potential issues", analysis_results)
            issue_count = potential_issues_match.group(1) if potential_issues_match else "some"
            
            # Show warning instead of success
            st.warning(f"⚠️ Potential vulnerabilities detected but not verified")
            st.markdown(f"The initial analysis found **{issue_count} potential security issues**, but they didn't pass verification at your current confidence threshold.")
            
            # Show confidence level advice
            st.info("💡 **Tip:** If you want to see these potential issues, try lowering your confidence threshold to 'Low' in settings.")
        elif "[✅ Secure]" in analysis_results and "Vulnerability #" not in analysis_results:
            # Only truly secure code with no vulnerabilities detected at all
            st.success("✅ Your code appears to be secure! No vulnerabilities were detected.")
            return
        
        # Extract and display summary section
        summary_match = re.search(r"## Summary(.*?)(?=##|\Z)", analysis_results, re.DOTALL)
        if summary_match:
            summary = summary_match.group(1).strip()
            
            # Count vulnerabilities for visual indicator
            critical = len(re.findall(r"🔴", summary))
            high = len(re.findall(r"🟠", summary))
            medium = len(re.findall(r"🟡", summary))
            low = len(re.findall(r"🟢", summary))
            total = critical + high + medium + low
            
            # Create visual security score
            if total > 0:
                st.error(f"⚠️ Found {total} security issues in your code")
                
                # Create a visual progress bar for each severity level
                col1, col2 = st.columns([1, 3])
                with col1:
                    st.markdown("Security Issues:")
                with col2:
                    if critical > 0:
                        st.markdown(f"🔴 Critical: {critical}")
                    if high > 0:
                        st.markdown(f"🟠 High: {high}")
                    if medium > 0:
                        st.markdown(f"🟡 Medium: {medium}")
                    if low > 0:
                        st.markdown(f"🟢 Low: {low}")
            else:
                st.success("No major security issues found")
        
        # Check if we need to show the original unverified vulnerabilities
        if "Original Analysis (Not Verified)" in analysis_results:
            st.markdown("### Original Analysis (Not Verified)")
            st.markdown("*These potential vulnerabilities were detected but didn't meet your confidence threshold requirements:*")
        
        # Extract all vulnerabilities - include both verified and unverified
        vulnerability_pattern = r"##\s*\[(🔴|🟠|🟡|🟢)\s*(\w+)\]\s*Vulnerability\s*#(\d+):\s*([^\n]+)(.*?)(?=##|\Z)"
        vulnerabilities = re.finditer(vulnerability_pattern, analysis_results, re.DOTALL)
        
        # Display vulnerabilities in user-friendly cards
        for match in vulnerabilities:
            emoji, severity, number, vuln_type, details = match.groups()
            
            # Map emoji to color for styling
            severity_colors = {
                "🔴": "#ffebee",  # Light red background
                "🟠": "#fff3e0",  # Light orange background
                "🟡": "#fffde7",  # Light yellow background
                "🟢": "#e8f5e9"   # Light green background
            }
            bg_color = severity_colors.get(emoji, "#f5f5f5")
            
            # Create styled card
            st.markdown(f"""
            <div style="background-color: {bg_color}; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 5px solid {'red' if emoji == '🔴' else 'orange' if emoji == '🟠' else 'gold' if emoji == '🟡' else 'green'};">
                <h3>{emoji} {severity} Issue: {vuln_type}</h3>
            </div>
            """, unsafe_allow_html=True)
            
            # Extract key information
            location_match = re.search(r"\*\*Location:\*\*\s*(.*?)\n", details)
            impact_match = re.search(r"\*\*Impact:\*\*\s*(.*?)(?=\*\*|\n\n)", details, re.DOTALL)
            fix_match = re.search(r"\*\*Fix:\*\*\s*(.*?)(?=\*\*|\n\n|\Z)", details, re.DOTALL)
            
            # Show simplified columns with What/How
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**What's the problem?**")
                if impact_match:
                    st.markdown(impact_match.group(1).strip())
                else:
                    st.markdown("This code has a security vulnerability.")
            
            with col2:
                st.markdown("**How to fix it:**")
                if fix_match:
                    st.markdown(fix_match.group(1).strip())
                else:
                    st.markdown("See technical details for fix information.")
            
            # Show technical details in expandable sections
            with st.expander("Show technical details"):
                # Only show code snippet
                snippet_match = re.search(r"\*\*Code Snippet:\*\*\s*```[^\n]*\n(.*?)```", details, re.DOTALL)
                if snippet_match and location_match:
                    st.markdown(f"**Vulnerable code at {location_match.group(1).strip()}:**")
                    st.code(snippet_match.group(1).strip())
                
                # Show verification info if present
                verification_match = re.search(r"\*\*Verification:\*\*\s*(.*?)(?=\*\*|\Z)", details, re.DOTALL)
                if verification_match:
                    st.markdown(f"**Verification:** {verification_match.group(1).strip()}")
                    
 
def process_single_file(uploaded_file):
    """Process a single uploaded file"""
    try:
        file_content = uploaded_file.getvalue().decode("utf-8")
        if len(file_content) > 100 * 1024:  # 100KB limit
            st.error("File is too large. Please upload a file smaller than 100KB.")
            return False
        
        st.session_state.user_code = file_content
        st.success("Code uploaded successfully!")
        with st.expander("View Uploaded Code"):
            st.code(st.session_state.user_code, language=uploaded_file.name.split('.')[-1])
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
                        'extension': filename.split('.')[-1],
                        'scanned': False,
                        'last_scan': None
                    }
                    if size_kb <= 100:  # Limit file size to 100KB
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
    """Add enhanced UI elements to Streamlit with cross-platform compatibility"""
    st.markdown("""
        <style>
        /* Base styles for the entire app */
        .stApp {
            background-color: #f8f9fa !important; /* Light gray for light mode */
        }
        
        /* Header section */
        .main-header {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            padding: 2rem 0 !important;
            background: linear-gradient(to right, #1a1f2c, #2c3e50) !important; /* Dark gradient */
            border-radius: 10px !important;
            margin-bottom: 2rem !important;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1) !important;
        }
        
        /* Logo and title container */
        .logo-title-container {
            display: flex !important;
            align-items: center !important;
            gap: 20px !important;
        }
        
        .logo-image {
            width: 120px !important;
            height: auto !important;
        }
        
        .title-text {
            color: #ffffff !important; /* White text for contrast */
            font-size: 2.5rem !important;
            font-weight: bold !important;
            margin: 0 !important;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3) !important;
        }
        
        /* Feature card styles */
        .feature-card {
            background-color: #ffffff !important; /* White background for light mode */
            padding: 1.5rem !important;
            border-radius: 10px !important;
            margin: 1rem 0 !important;
            border: 1px solid #e9ecef !important;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05) !important;
            transition: transform 0.2s !important;
            color: #1a1f2c !important; /* Dark blue text */
        }
        
        .feature-card:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1) !important;
        }
        
        /* Icon and title alignment */
        .icon-title {
            display: flex !important;
            align-items: center !important;
            gap: 10px !important;
            margin-bottom: 1rem !important;
            color: #1a1f2c !important;
        }
        
        /* Severity indicators */
        .severity-indicator {
            display: inline-flex !important;
            align-items: center !important;
            gap: 8px !important;
            padding: 4px 8px !important;
            border-radius: 4px !important;
            margin: 4px 0 !important;
            font-weight: 500 !important;
        }
        
        .severity-critical { 
            background-color: #ff4444 !important; /* Red for critical */
            color: #ffffff !important;
        }
        
        .severity-high { 
            background-color: #ffbb33 !important; /* Orange for high */
            color: #000000 !important;
        }
        
        .severity-medium { 
            background-color: #ffeb3b !important; /* Yellow for medium */
            color: #333333 !important; /* Darker gray for better contrast */
        }
        
        .severity-low { 
            background-color: #00C851 !important; /* Green for low */
            color: #ffffff !important;
        }
        
        /* Button styles */
        .stButton>button {
            background: linear-gradient(to right, #4CAF50, #45a049) !important; /* Green gradient */
            color: #ffffff !important;
            border-radius: 5px !important;
            border: none !important;
            padding: 10px 24px !important;
            font-weight: 500 !important;
            transition: all 0.3s !important;
        }
        
        .stButton>button:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1) !important;
        }
        
        /* Upload section */
        .upload-section {
            background-color: #ffffff !important;
            padding: 2rem !important;
            border-radius: 10px !important;
            border: 2px dashed #cccccc !important; /* Gray dashed border */
            text-align: center !important;
        }
        
        /* Icon text alignment */
        .icon-text {
            display: flex !important;
            align-items: center !important;
            gap: 8px !important;
            margin: 8px 0 !important;
            color: #1a1f2c !important;
        }
        
        /* General text visibility */
        .stMarkdown, p, li {
            color: #1a1f2c !important; /* Dark blue for readability */
        }
        
        h1, h2, h3, h4, h5, h6 {
            color: #1a1f2c !important;
        }
        
        /* Ensure checkmarks are visible */
        .icon-text span:first-child {
            color: #00C851 !important; /* Green for icons */
            font-weight: bold !important;
        }
        
        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            .stApp {
                background-color: #1a1f2c !important; /* Dark blue for dark mode */
            }
            
            .feature-card {
                background-color: #2c3e50 !important; /* Medium blue for cards */
                color: #ffffff !important; /* White text */
            }
            
            .upload-section {
                background-color: #2c3e50 !important; /* Match card color */
                border-color: #666666 !important; /* Darker gray border */
            }
            
            .stMarkdown, p, li {
                color: #ffffff !important;
            }
            
            h1, h2, h3, h4, h5, h6 {
                color: #ffffff !important;
            }
            
            .icon-title, .icon-text {
                color: #ffffff !important;
            }
        }
        </style>
    """, unsafe_allow_html=True)

def initialize_session_state():
    """Initialize all session state variables"""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "user_code" not in st.session_state:
        st.session_state.user_code = ""
    if "analysis_cache" not in st.session_state:
        st.session_state.analysis_cache = {}
    if "last_analysis_time" not in st.session_state:
        st.session_state.last_analysis_time = None
    if "connection_status" not in st.session_state:
        st.session_state.connection_status = None
    if "folder_contents" not in st.session_state:
        st.session_state.folder_contents = {}
    if "file_metadata" not in st.session_state:
        st.session_state.file_metadata = {}
    if "selected_api" not in st.session_state:
        st.session_state.selected_api = "OpenAI"
    if "current_file" not in st.session_state:
        st.session_state.current_file = None
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = {}
    if "confidence_level" not in st.session_state:  # New setting for false positive control
        st.session_state.confidence_level = "Medium"
    if "verify_vulnerabilities" not in st.session_state:  # New toggle for verification
        st.session_state.verify_vulnerabilities = True

def get_base64_img(image_path):
    import base64
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

def main():
    st.set_page_config(
        page_title="CodeGuardianAI v2",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            'Get Help': None,
            'Report a bug': None,
            'About': None
        }
    )

    initialize_session_state()
    analyzer = SecurityAnalyzer()
    enhance_streamlit_ui()

    # Header with Logo and Title
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
    except Exception as e:
        # If image loading fails, show title without image
        st.markdown("""
            <div class="main-header">
                <div class="logo-title-container">
                    <h1 class="title-text">CodeGuardianAI</h1>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # Feature Cards in a cleaner layout
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
            <div class="feature-card">
                <div class="icon-title">
                    <span style="font-size: 24px;">🔍</span>
                    <h3>What This Tool Does:</h3>
                </div>
                <div class="icon-text">
                    <span>✓</span>
                    <span>Scans Your Code: Checks every line for security problems</span>
                </div>
                <div class="icon-text">
                    <span>✓</span>
                    <span>Simple Explanations: Describes issues in easy-to-understand terms</span>
                </div>
                <div class="icon-text">
                    <span>✓</span>
                    <span>Shows Exact Problems: Highlights exactly where the issues are</span>
                </div>
                <div class="icon-text">
                    <span>✓</span>
                    <span>Provides Solutions: Gives step-by-step instructions to fix each issue</span>
                </div>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <div class="feature-card">
                <div class="icon-title">
                    <span style="font-size: 24px;">⚠️</span>
                    <h3>Severity Levels:</h3>
                </div>
                <div class="severity-indicator severity-critical">
                    <span>●</span>
                    <span>Critical Risk: Needs immediate attention</span>
                </div>
                <div class="severity-indicator severity-high">
                    <span>●</span>
                    <span>High Risk: Should be fixed soon</span>
                </div>
                <div class="severity-indicator severity-medium">
                    <span>●</span>
                    <span>Medium Risk: Plan to address</span>
                </div>
                <div class="severity-indicator severity-low">
                    <span>●</span>
                    <span>Low Risk: Good to fix when possible</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

    # Check and display connection status
    if st.session_state.connection_status is None:
        with st.spinner("Checking connection..."):
            has_connection = check_internet_connection()
            can_reach_api = True
            try:
                socket.gethostbyname('api.openai.com')
            except socket.gaierror:
                can_reach_api = False
            
            st.session_state.connection_status = {
                'internet': has_connection,
                'api': can_reach_api
            }



    # Add this to your main() function in the Settings section of the sidebar
    with st.sidebar:
        st.header("Settings")
        
        # API Selection
        api_choice = st.selectbox(
            "Choose API Provider",
            ["OpenAI", "Deepseek"],
            help="Select which AI provider to use for analysis"
        )
        st.session_state.selected_api = api_choice
        
        # False positive control settings
        st.subheader("False Positive Control")
        confidence_level = st.select_slider(
            "Confidence Threshold",
            options=["Low", "Medium", "High"],
            value="Medium",
            help="Higher settings reduce false positives but might miss some issues"
        )
        st.session_state.confidence_level = confidence_level
        
        # Explanation of confidence levels
        with st.expander("About Confidence Levels"):
            st.markdown("""
            - **Low**: Shows all potential issues, may include false positives
            - **Medium**: Balanced approach, filters some uncertain findings
            - **High**: Only shows issues with high confidence, minimizes false positives
            """)

        # File Upload Options
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
                        st.text(f"📄 {filename} ({metadata['size_kb']}KB)")

    # Main content area
    if st.session_state.folder_contents:
        st.markdown("### 📁 Project Files")
        
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
                    st.markdown(f"**{filename}**  \n"
                              f"_{metadata['size_kb']}KB, {metadata['lines']} lines_")
                
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
        
        # Analysis section for selected file
        if st.session_state.current_file and st.session_state.user_code:
            st.markdown("---")
            st.markdown(f"### 🔍 Analyzing: {st.session_state.current_file}")
            
            # Show file preview
            with st.expander("View File Content"):
                st.code(st.session_state.user_code, 
                       language=st.session_state.current_file.split('.')[-1])
            
            # Analysis options
            analysis_type = st.radio(
                "Choose what to focus on:",
                ["Full Security Scan", "Custom Query"],
                horizontal=True,
                help="Full Scan checks everything, Custom Query lets you ask specific questions"
            )
            
            # Handle analysis request
            query = None
            if analysis_type == "Custom Query":
                query = st.text_input("Type your specific security question here...")
            elif analysis_type == "Full Security Scan":
                query = "Perform a complete security analysis of the code."
            
            # For single file mode
            if query:
                with st.spinner(f"Analyzing code using {st.session_state.selected_api}..."):
                    result = analyzer.analyze_code(
                        st.session_state.user_code,
                        query,
                        st.session_state.selected_api.lower()
                    )
                    
                    if result["status"] == "success":
                        analysis_results = result["analysis"]
                        
                        # Apply verification if enabled
                        if st.session_state.verify_vulnerabilities:
                            with st.spinner("Verifying analysis results to reduce false positives..."):
                                analysis_results = verify_all_vulnerabilities(
                                    analysis_results,
                                    st.session_state.selected_api.lower(),
                                    st.session_state.confidence_level
                                )
                        
                        # Store analysis result in history
                        if st.session_state.current_file:
                            current_file = st.session_state.current_file or "uploaded_file"  # Use a default key if None
                            if current_file not in st.session_state.scan_history:
                                st.session_state.scan_history[current_file] = []
                            
                            st.session_state.scan_history[st.session_state.current_file].append({
                                'timestamp': datetime.now().isoformat(),
                                'analysis': analysis_results,
                                'api': st.session_state.selected_api,
                                'confidence_level': st.session_state.confidence_level,
                                'verification_used': st.session_state.verify_vulnerabilities
                            })
                        
                        st.markdown("### Analysis Results")
                        format_user_friendly_results(analysis_results, st)

                        # Generate and show download button for text report
                        generate_download_report(analysis_results)
                        
                        # Rest of your code for scan history display...
                    else:
                        st.error(f"Analysis failed: {result['message']}")
    
    elif st.session_state.user_code:  # Single file mode
        st.markdown("### 🔍 Analysis Options")
        analysis_type = st.radio(
            "Choose what to focus on:",
            ["Full Security Scan", "Custom Query"],
            horizontal=True,
            help="Full Scan checks everything, Custom Query lets you ask specific questions"
        )
        
        # Handle analysis request
        query = None
        if analysis_type == "Custom Query":
            query = st.text_input("Type your specific security question here...")
        elif analysis_type == "Full Security Scan":
            query = "Perform a complete security analysis of the code."
        
        if query:
            with st.spinner(f"Analyzing code using {st.session_state.selected_api}..."):
                result = analyzer.analyze_code(
                    st.session_state.user_code,
                    query,
                    st.session_state.selected_api.lower()
                )
                
                if result["status"] == "success":
                    # Get analysis results
                    analysis_results = result["analysis"]
                    
                    # Apply verification if enabled
                    if st.session_state.verify_vulnerabilities:
                        with st.spinner("Verifying analysis results to reduce false positives..."):
                            analysis_results = verify_all_vulnerabilities(
                                analysis_results,
                                st.session_state.selected_api.lower(),
                                st.session_state.confidence_level
                            )
                    
                    # Store analysis result in history
                    if st.session_state.current_file not in st.session_state.scan_history:
                        st.session_state.scan_history[st.session_state.current_file] = []
                    
                    st.session_state.scan_history[st.session_state.current_file].append({
                        'timestamp': datetime.now().isoformat(),
                        'analysis': analysis_results,
                        'api': st.session_state.selected_api,
                        'confidence_level': st.session_state.confidence_level,
                        'verification_used': st.session_state.verify_vulnerabilities
                    })
                    
                    # Update file metadata if available
                    if st.session_state.current_file and st.session_state.current_file in st.session_state.file_metadata:
                        st.session_state.file_metadata[st.session_state.current_file]['scanned'] = True
                        st.session_state.file_metadata[st.session_state.current_file]['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M")
                    
                    st.markdown("### Analysis Results")
                    format_user_friendly_results(analysis_results, st)

                    # Generate and show download button for text report
                    generate_download_report(analysis_results)
                    
                    # Show scan history
                    if len(st.session_state.scan_history[st.session_state.current_file]) > 1:
                        with st.expander("View Scan History"):
                            for idx, scan in enumerate(reversed(st.session_state.scan_history[st.session_state.current_file])):
                                st.markdown(f"**Scan {idx + 1}** - {scan['timestamp']}")
                                st.markdown(f"API: {scan['api']}")
                                if 'confidence_level' in scan:
                                    st.markdown(f"Confidence: {scan['confidence_level']}")
                                if st.button(f"Show Results", key=f"history_{idx}"):
                                    st.markdown(scan['analysis'])
                else:
                    st.error(f"Analysis failed: {result['message']}")
    else:
        st.info("👈 Please upload your code using the sidebar to begin analysis")

if __name__ == "__main__":
    main()
