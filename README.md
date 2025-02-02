# CodeGuardianAI

An AI-powered code security analyzer that helps identify and fix security vulnerabilities in your code.

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- Git
- OpenAI API key

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
- Set up the configuration file

3. **Activate the virtual environment:**
```bash
# For Windows
venv\Scripts\activate

# For Linux/Mac
source venv/bin/activate
```

4. **Configure your OpenAI API key:**
Edit the `.env` file and add your OpenAI API key:
```env
OPENAI_API_KEY=your_api_key_here
```

5. **Run the application:**
```bash
streamlit run app.py
```

### Common Issues & Solutions

If you encounter: `module 'openai' has no attribute 'error'`
```bash
pip uninstall openai
pip install openai==0.28.0
```

## 🛠️ Features

- Deep code analysis for security vulnerabilities
- Support for multiple programming languages
- Clear, non-technical explanations of issues
- Step-by-step fix instructions
- Code examples for secure implementations

## 📝 Usage

1. Start the application
2. Upload your code file
3. Choose analysis type:
   - Full Security Scan
   - Custom Query
4. Review results and implement fixes

## 🔒 Supported Languages

- PHP
- Python
- JavaScript
- Java
- C++
- C#
- Text files

## ⚙️ Configuration

Maximum file size: 200MB
Supported file extensions: .php, .py, .js, .java, .cpp, .cs, .txt

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.