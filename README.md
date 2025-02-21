# CodeGuardianAI v2

An advanced AI-powered code security analyzer that helps identify and fix security vulnerabilities in your code. Now with support for multiple AI providers and directory analysis.

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- Git
- OpenAI API key (primary)
- Deepseek API key (optional)

### Installation Steps

1. **Clone the repository:**
```bash
git clone https://github.com/Btr4k/CodeGuardianAI.git
cd CodeGuardianAI
```

2. **Run the setup script:**
```bash
python setup.py
```
This will:
- Create a virtual environment
- Install all dependencies
- Set up the configuration files
- Create necessary project directories

3. **Activate the virtual environment:**
```bash
# For Windows
venv\Scripts\activate
# For Linux/Mac
source venv/bin/activate
```

4. **Configure your API keys:**
Edit the `.env` file and add your API keys:
```env
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here  # Optional
```

5. **Run the application:**
```bash
streamlit run app.py
```

### Common Issues & Solutions

If you encounter dependency issues:
```bash
pip install -r requirements.txt --upgrade
```

For OpenAI API issues:
```bash
pip uninstall openai
pip install openai==0.28.0
```

## 🌟 New Features in V2

- **Multiple AI Provider Support**
  - OpenAI integration
  - Deepseek integration
  - Easy provider switching

- **Enhanced File Analysis**
  - Single file analysis
  - Directory analysis via ZIP upload
  - File metadata tracking
  - Analysis history

- **Improved Security Checks**
  - Color-coded severity levels
  - Expanded vulnerability categories
  - Language-specific security patterns
  - Compliance checks (GDPR, HIPAA, PCI DSS)

- **Advanced Reporting**
  - Downloadable analysis reports
  - Scan history comparison
  - Detailed vulnerability descriptions
  - Clear POC examples

## 🛠️ Features

- Deep code analysis for security vulnerabilities
- Support for multiple programming languages
- Clear, non-technical explanations of issues
- Step-by-step fix instructions
- Code examples for secure implementations
- Project-wide security analysis
- Scan history tracking
- Exportable security reports

## 📝 Usage

1. Start the application
2. Choose upload type:
   - Single File
   - Directory (ZIP)
3. Select AI provider:
   - OpenAI
   - Deepseek
4. Choose analysis type:
   - Full Security Scan
   - Custom Query
5. Review results and implement fixes

## ⚙️ Configuration

- Maximum file size: 100KB per file
- Maximum ZIP size: 10MB
- Supported file extensions: .php, .py, .js, .java, .cpp, .cs, .txt
- Cache duration: 24 hours
- Analysis history retention: 30 days

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔄 Version History

- v2.0.0 - Multiple API support, directory analysis, enhanced reporting
- v1.0.0 - Initial release with basic analysis features
