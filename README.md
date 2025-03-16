# CodeGuardianAI V2

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.2.0-FF4B4B.svg)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enhanced AI-powered code security analyzer that detects and helps fix vulnerabilities with improved accuracy.


### ✨ Features
- **Advanced PHP Security Analysis** - Better detection of SQL injection, XSS, and file uploads
- **False Positive Control** - Adjustable confidence thresholds (Low/Medium/High)
- **Multiple AI Providers** - Support for both OpenAI and Deepseek APIs
- **Directory Analysis** - Scan entire projects by uploading zipped folders
- **Enhanced Reporting** - Clear severity indicators (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

## Prerequisites
- Python 3.9 or higher
- Git
- OpenAI API key or Deepseek API key

## Installation

### 1. Clone the repository:
```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI
```

### 2. Run the setup script:
```bash
python setup.py
```
This will:
- Create a virtual environment
- Install all dependencies
- Set up the configuration file

### 3. Activate the virtual environment:
```bash
# For Windows
venv\Scripts\activate

# For Linux/Mac
source venv/bin/activate
```

### 4. Configure your OpenAI API key:
Edit the `.env` file and add your OpenAI API key:
```env
OPENAI_API_KEY=your_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
```

### 5. Run the application:
```bash
streamlit run app.py
```

### 📝 Usage

1- Start the application

2- Upload your code file or directory (zip)

3- Choose API provider and confidence level

4- Run Full Security Scan or Custom Query

5- Review color-coded vulnerabilities and implement fixes

### 🔒 Supported Languages

- PHP
- Python
- JavaScript
- Java
- C++

### Common Issues & Solutions

If you encounter: `module 'openai' has no attribute 'error'`
```bash
pip uninstall openai
pip install openai==0.28.0
```

### ⚙️ Configuration

Maximum file size: 100KB

Supported file extensions: .php, .py, .js, .java, .cpp, .cs, .txt

### 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.