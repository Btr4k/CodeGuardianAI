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
    """Generate a text report with a header and timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{base_filename}_{timestamp}.txt"
    report_content = f"""
==============================================
CodeGuardianAI Security Analysis Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==============================================

{analysis_results}
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_content)
    st.info(f"Report saved to: {os.path.abspath(filename)}")
    return filename


def generate_download_report(analysis_results):
    """Generate and provide download link for text report"""
    try:
        if not analysis_results:
            st.error("No analysis results available to generate report")
            return
            
        # Generate the text file
        report_file = generate_text_report(analysis_results)
        
        # Provide download button
        with open(report_file, "r", encoding="utf-8") as f:
            report_data = f.read()
            st.download_button(
                label="⬇️ Download Analysis Report",
                data=report_data,
                file_name=report_file,
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
            "low": 2
        }

    def create_enhanced_prompt(self, code: str, language: str = None) -> str:
        # Define severity color formatting
        severity_formats = {
            "CRITICAL": "🔴 Critical",
            "HIGH": "🟠 High",
            "MEDIUM": "🟡 Medium",
            "LOW": "🟢 Low"
        }
        
        # Create severity legend
        severity_legend = "\nSEVERITY LEVELS:\n"
        for severity, formatted in severity_formats.items():
            severity_legend += f"- {formatted}: {self._get_severity_description(severity)}\n"

        lang = language if language else "code"
        base_prompt = f"""You are a security expert. Analyze the following {lang} for vulnerabilities. Report every issue from low to critical with a strong, technical POC.

    {severity_legend}
    For each finding, follow this format:
    ## [Severity Indicator] Vulnerability #[N]: [Type]
    Example headers:
    - ## [🔴 Critical] Vulnerability #1: Remote Code Execution
    - ## [🟠 High] Vulnerability #2: SQL Injection
    - ## [🟡 Medium] Vulnerability #3: XSS Vulnerability
    - ## [🟢 Low] Vulnerability #4: Information Disclosure

    Required sections for each finding:
    - **Location:** Lines [exact_start-exact_end]
    - **Code Snippet:**
    [Exact vulnerable code snippet]
    - **CWE:** [specific_id] - [name]
    - **OWASP:** [exact_category]
    - **POC:**
    [Concise, technical exploit demonstrating the vulnerability]
    - **Impact:**
    [Brief description of consequences]
    - **Fix:**
    [Minimal code change to resolve the issue]

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

        base_prompt += "\n\nIMPORTANT: Do not limit analysis to just these examples. Report ANY vulnerability found."
        return base_prompt

    def _get_severity_description(self, severity: str) -> str:
        """Return description for each severity level"""
        descriptions = {
            "CRITICAL": "Needs immediate attention - Direct system/data compromise",
            "HIGH": "Should be fixed soon - Significant security impact",
            "MEDIUM": "Plan to address - Moderate security impact",
            "LOW": "Good to fix when possible - Limited security impact"
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
    """Add the enhanced UI elements to Streamlit"""
    st.markdown("""
        <style>
        .stApp {
            background-color: #f8f9fa;
        }
        .main-header {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem 0;
            background: linear-gradient(to right, #1a1f2c, #2c3e50);
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .logo-title-container {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .logo-image {
            width: 120px;
            height: auto;
        }
        .title-text {
            color: white;
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0;
        }
        .feature-card {
            background-color: white;
            padding: 1.5rem;
            border-radius: 10px;
            margin: 1rem 0;
            border: 1px solid #e9ecef;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: transform 0.2s;
        }
        .feature-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .icon-title {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 1rem;
        }
        .severity-indicator {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 8px;
            border-radius: 4px;
            margin: 4px 0;
        }
        .severity-critical { background-color: #ff4444; color: white; }
        .severity-high { background-color: #ffbb33; color: black; }
        .severity-medium { background-color: #ffeb3b; color: black; }
        .severity-low { background-color: #00C851; color: white; }
        .stButton>button {
            background: linear-gradient(to right, #4CAF50, #45a049);
            color: white;
            border-radius: 5px;
            border: none;
            padding: 10px 24px;
            font-weight: 500;
            transition: all 0.3s;
        }
        .stButton>button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .upload-section {
            background-color: white;
            padding: 2rem;
            border-radius: 10px;
            border: 2px dashed #ccc;
            text-align: center;
        }
        .icon-text {
            display: flex;
            align-items: center;
            gap: 8px;
            margin: 8px 0;
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

def get_base64_img(image_path):
    import base64
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

def main():
    st.set_page_config(
        page_title="CodeGuardianAI v2",
        layout="wide",
        initial_sidebar_state="expanded"
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



    # Sidebar
    with st.sidebar:
        st.header("Settings")
        
        # API Selection
        api_choice = st.selectbox(
            "Choose API Provider",
            ["OpenAI", "Deepseek"],
            help="Select which AI provider to use for analysis"
        )
        st.session_state.selected_api = api_choice
        
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
            
            if query:
                with st.spinner(f"Analyzing code using {st.session_state.selected_api}..."):
                    result = analyzer.analyze_code(
                        st.session_state.user_code,
                        query,
                        st.session_state.selected_api.lower()
                    )
                    
                    if result["status"] == "success":
                        # Store analysis result in history
                        if st.session_state.current_file not in st.session_state.scan_history:
                            st.session_state.scan_history[st.session_state.current_file] = []
                        
                        st.session_state.scan_history[st.session_state.current_file].append({
                            'timestamp': datetime.now().isoformat(),
                            'analysis': result["analysis"],
                            'api': st.session_state.selected_api
                        })
                        
                        st.markdown("### Analysis Results")
                        st.markdown(result["analysis"])
                        
                        # Generate and show download button for text report
                        generate_download_report(result["analysis"])
                        
                        # Show scan history
                        if len(st.session_state.scan_history[st.session_state.current_file]) > 1:
                            with st.expander("View Scan History"):
                                for idx, scan in enumerate(reversed(st.session_state.scan_history[st.session_state.current_file])):
                                    st.markdown(f"**Scan {idx + 1}** - {scan['timestamp']}")
                                    st.markdown(f"API: {scan['api']}")
                                    if st.button(f"Show Results", key=f"history_{idx}"):
                                        st.markdown(scan['analysis'])
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
                    st.markdown("### Analysis Results")
                    st.markdown(result["analysis"])
                    
                    # Generate and show download button for text report
                    generate_download_report(result["analysis"])
                else:
                    st.error(f"Analysis failed: {result['message']}")
    else:
        st.info("👈 Please upload your code using the sidebar to begin analysis")

if __name__ == "__main__":
    main()