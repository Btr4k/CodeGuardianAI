# PHP Security Code Analyzer

A powerful and user-friendly tool that analyzes PHP code for security vulnerabilities using OpenAI's GPT-4. The tool provides detailed explanations and fixes for identified security issues in plain language.

## Features

- 🔍 **Comprehensive Security Analysis**: Scans PHP code for various security vulnerabilities
- 💡 **User-Friendly Explanations**: Provides clear, non-technical explanations of security issues
- 🎯 **Precise Problem Location**: Highlights exact lines where vulnerabilities exist
- 🛠️ **Solution-Oriented**: Offers step-by-step fixes with example code
- 💾 **Result Caching**: Saves analysis results to prevent redundant API calls
- 🔄 **Retry Mechanism**: Handles network issues gracefully with automatic retries

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/php-security-analyzer.git
cd php-security-analyzer
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root and add your OpenAI API key:
```env
OPENAI_API_KEY=your_openai_api_key_here
```

## Usage

1. Start the application:
```bash
streamlit run app.py
```

2. Upload your PHP file using the sidebar interface

3. Choose your analysis type:
   - **Full Security Scan**: Comprehensive analysis of all security aspects
   - **Custom Query**: Ask specific security-related questions about your code

4. View the results with:
   - Vulnerability descriptions in plain language
   - Line-by-line problem identification
   - Practical fix suggestions
   - Working code examples

## Requirements

- Python 3.9+
- OpenAI API key
- Internet connection
- Required Python packages (see requirements.txt)

## Vulnerability Categories Detected

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- File Upload Vulnerabilities
- Authentication Issues
- Authorization Problems
- Input Validation Weaknesses
- And more...

## Error Handling

The tool includes robust error handling for:
- Network connectivity issues
- API timeouts
- DNS resolution problems
- File size limitations
- Invalid input detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenAI for providing the GPT-4 API
- Streamlit for the wonderful web framework
- Python community for the excellent packages

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.