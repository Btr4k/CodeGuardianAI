import streamlit as st
import openai
import os
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

# Setup logging with more detailed network information
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_analyzer.log'),
        logging.StreamHandler()
    ]
)

# Load environment variables
load_dotenv()

# Check for required API key
REQUIRED_KEYS = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
}

# Configure OpenAI
openai.api_key = REQUIRED_KEYS["OPENAI_API_KEY"]

def check_internet_connection(host="8.8.8.8", port=53, timeout=3):
    """Check if there is an active internet connection"""
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        return False

def setup_openai_client():
    """Configure OpenAI client with retry mechanism"""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.5,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    openai.requestssession = session

# Initialize session state
def initialize_session_state():
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "php_code" not in st.session_state:
        st.session_state.php_code = ""
    if "analysis_cache" not in st.session_state:
        st.session_state.analysis_cache = {}
    if "last_analysis_time" not in st.session_state:
        st.session_state.last_analysis_time = None
    if "connection_status" not in st.session_state:
        st.session_state.connection_status = None

class SecurityAnalyzer:
    def __init__(self):
        self.vulnerability_categories = {
            "injection": [
                "SQL Injection",
                "Command Injection",
                "Code Injection",
                "LDAP Injection",
                "XPath Injection"
            ],
            "xss": [
                "Reflected XSS",
                "Stored XSS",
                "DOM-based XSS"
            ],
            "authentication": [
                "Weak Password Policy",
                "Insecure Session Management",
                "Missing Authentication",
                "Broken Authentication"
            ],
            "authorization": [
                "Missing Authorization",
                "Insecure Direct Object References",
                "Privilege Escalation"
            ],
            "cryptographic": [
                "Weak Encryption",
                "Insecure Random Numbers",
                "Hard-coded Credentials"
            ],
            "configuration": [
                "Security Misconfigurations",
                "Sensitive Data Exposure",
                "Default Credentials"
            ],
            "input_validation": [
                "Missing Input Validation",
                "Insufficient Input Sanitization",
                "File Upload Vulnerabilities"
            ]
        }
        
    def create_enhanced_prompt(self, code: str) -> str:
        """Create an enhanced security analysis prompt focused on clear explanations"""
        return f"""You are a security expert who specializes in explaining security issues to non-technical users. Analyze the following code and identify security vulnerabilities.

When you find a vulnerability:

🔍 Location:
- Show the exact line number
- Quote the vulnerable code snippet
- Use markdown code blocks with line highlights

⚠️ Simple Explanation:
- Explain the issue in simple, non-technical terms
- Use real-world analogies when possible
- Explain why this is dangerous

💡 Example Risk Scenario:
- Provide a real-world example of how this could be exploited
- Explain what a malicious user could do
- Keep it understandable for non-technical users

✅ Fix Instructions:
- Provide step-by-step instructions to fix the issue
- Explain why the fix works
- Show the corrected code in a code block

Code to analyze:

{code}

Format each vulnerability like this:

## 🚨 Vulnerability #[number]: [Simple Name of Issue]
**Line [number]:**
```php
[vulnerable code here]
```

**In Simple Terms:**
[Clear, non-technical explanation]

**Real-World Risk:**
[Simple scenario explanation]

**How to Fix:**
[Step-by-step instructions]
```php
[corrected code]
```

**Why This Fix Works:**
[Simple explanation of why the fix prevents the issue]"""

    def analyze_code_openai(self, code: str, user_query: str) -> Dict:
        """Analyze code using OpenAI with enhanced error handling and retry logic"""
        try:
            if not REQUIRED_KEYS["OPENAI_API_KEY"]:
                raise ValueError("OpenAI API key is missing")

            # Check internet connection first
            if not check_internet_connection():
                return {
                    "status": "error",
                    "message": "No internet connection detected. Please check your network connection.",
                    "timestamp": datetime.now().isoformat()
                }

            # Try to resolve OpenAI's API domain
            try:
                socket.gethostbyname('api.openai.com')
            except socket.gaierror:
                return {
                    "status": "error",
                    "message": "Unable to resolve OpenAI API domain. This might be due to DNS issues or network restrictions.",
                    "timestamp": datetime.now().isoformat()
                }

            messages = [
                {"role": "system", "content": self.create_enhanced_prompt(code)},
                {"role": "user", "content": f"Focus on: {user_query}"}
            ]

            # Add retry mechanism with exponential backoff
            max_retries = 3
            retry_delay = 1
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    response = openai.ChatCompletion.create(
                        model="gpt-4",
                        messages=messages,
                        temperature=0.1,
                        max_tokens=2000,
                        presence_penalty=0.2,
                        frequency_penalty=0.3,
                        request_timeout=30
                    )
                    return {
                        "status": "success",
                        "analysis": response.choices[0].message.content,
                        "timestamp": datetime.now().isoformat()
                    }
                except (openai.error.APIConnectionError, openai.error.Timeout, requests.exceptions.ConnectionError) as e:
                    last_error = e
                    if attempt == max_retries - 1:
                        break
                    logging.warning(f"API connection attempt {attempt + 1} failed. Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2

            # If we get here, all retries failed
            error_message = self._get_user_friendly_error_message(last_error)
            return {
                "status": "error",
                "message": error_message,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logging.error(f"OpenAI analysis error: {str(e)}")
            return {
                "status": "error",
                "message": self._get_user_friendly_error_message(e),
                "timestamp": datetime.now().isoformat()
            }

    def _get_user_friendly_error_message(self, error):
        """Convert technical error messages into user-friendly ones"""
        if isinstance(error, socket.gaierror):
            return "Unable to connect to the API service. Please check your internet connection or DNS settings."
        elif isinstance(error, requests.exceptions.ConnectionError):
            return "Connection failed. Please check your internet connection and try again."
        elif isinstance(error, openai.APIError):
            return "The API service is temporarily unavailable. Please try again in a few minutes."
        elif isinstance(error, openai.APITimeoutError):
            return "The request timed out. Please try again."
        elif isinstance(error, openai.RateLimitError):
            return "Rate limit exceeded. Please wait a moment before trying again."
        elif isinstance(error, openai.APIConnectionError):
            return "Connection to OpenAI failed. Please check your internet connection."
        else:
            return f"An unexpected error occurred: {str(error)}"

def process_analysis_request(analyzer: SecurityAnalyzer, code: str, query: str, provider: str) -> Tuple[str, str]:
    """Process the analysis request and return the cache key and result"""
    cache_key = hashlib.md5(
        f"{code}{query}{provider}".encode()
    ).hexdigest()
    
    if cache_key in st.session_state.analysis_cache:
        return cache_key, st.session_state.analysis_cache[cache_key]
    
    result = analyzer.analyze_code_openai(code, query)
    if result["status"] == "success":
        st.session_state.analysis_cache[cache_key] = result["analysis"]
        return cache_key, result["analysis"]
    else:
        return cache_key, f"Error: {result['message']}"

def main():
    st.set_page_config(
        page_title="CodeGuardianAI",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize OpenAI client with retry mechanism
    setup_openai_client()

    initialize_session_state()
    analyzer = SecurityAnalyzer()

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

    if not st.session_state.connection_status['internet']:
        st.error("⚠️ No internet connection detected. Please check your network connection.")
    elif not st.session_state.connection_status['api']:
        st.error("⚠️ Cannot reach OpenAI API. This might be due to DNS issues or network restrictions.")

    # UI Design
    st.title("CodeGuardianAI")
    
    col1, col2 = st.columns([2,1])
    with col1:
        st.markdown("""
        ### What This Tool Does:
        1. 🔍 **Scans Your Code:** Checks every line of your code for security problems
        2. 📝 **Simple Explanations:** Describes issues in easy-to-understand terms
        3. 🎯 **Shows Exact Problems:** Highlights exactly where the issues are in your code
        4. 🛠️ **Provides Solutions:** Gives you step-by-step instructions to fix each issue
        """)
    
    with col2:
        st.markdown("""
        ### Severity Levels:
        - 🔴 **High Risk:** Needs immediate attention
        - 🟡 **Medium Risk:** Should be fixed soon
        - 🟢 **Low Risk:** Good to fix when possible
        """)
        
    st.markdown("---")

    # Sidebar
    with st.sidebar:
        st.header("Settings")
        
        uploaded_file = st.file_uploader(
            "Upload Code File",
            type=["php", "txt", "py", "js", "java", "cpp", "cs"],
            help="Maximum file size: 100KB"
        )

        if uploaded_file:
            try:
                file_content = uploaded_file.getvalue().decode("utf-8")
                if len(file_content) > 100 * 1024:
                    st.error("File is too large. Please upload a file smaller than 100KB.")
                else:
                    st.session_state.php_code = file_content
                    st.success("Code uploaded successfully!")
                    with st.expander("View Uploaded Code"):
                        st.code(st.session_state.php_code, language=uploaded_file.name.split('.')[-1])
            except Exception as e:
                st.error(f"Error reading file: {str(e)}")

    # Display conversation history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Analysis options and chat input
    if st.session_state.php_code:
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
            query = st.chat_input("Type your specific security question here...")
        elif analysis_type:
            query = f"Analyze the code focusing on {analysis_type.lower()} issues. Pay special attention to common vulnerabilities in this area."
        
        if query:
            st.session_state.messages.append({"role": "user", "content": query})
            with st.chat_message("user"):
                st.markdown(f"Analyzing for: {analysis_type}")

            with st.chat_message("assistant"):
                with st.spinner("Analyzing code..."):
                    try:
                        cache_key, result = process_analysis_request(
                            analyzer,
                            st.session_state.php_code,
                            query,
                            "OpenAI"
                        )
                        st.markdown(result)
                    except Exception as e:
                        st.error(f"Error during analysis: {str(e)}")
    else:
        st.warning("⬅️ Please upload your code using the sidebar to begin analysis")

if __name__ == "__main__":
    main()