import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print("❌ Error: Python 3.9 or higher is required")
        print(f"Current version: Python {sys.version_info.major}.{sys.version_info.minor}")
        sys.exit(1)
    print("✅ Python version check passed")

def create_virtual_environment():
    """Create a virtual environment"""
    if os.path.exists('venv'):
        print("🔄 Removing existing virtual environment...")
        shutil.rmtree('venv')
    print("🔨 Creating new virtual environment...")
    subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
    print("✅ Virtual environment created")

def install_dependencies():
    """Install required packages"""
    pip_cmd = 'venv\\Scripts\\pip.exe' if platform.system() == 'Windows' else 'venv/bin/pip'
    
    # Upgrade pip first
    print("🔄 Upgrading pip...")
    subprocess.run([pip_cmd, 'install', '--upgrade', 'pip'])
    
    # Core dependencies
    core_packages = [
        'streamlit',
        'openai',
        'python-dotenv',
        'requests',
        'Pillow',
        'urllib3'
    ]
    
    # Additional packages for V2 features
    v2_packages = [
        'zipfile36',  # For ZIP file handling
        'numpy',      # For data processing
        'pandas',     # For data analysis
        'logging',    # For enhanced logging
    ]
    
    print("\n📦 Installing core packages...")
    subprocess.run([pip_cmd, 'install'] + core_packages)
    
    print("\n📦 Installing V2 feature packages...")
    subprocess.run([pip_cmd, 'install'] + v2_packages)
    
    # Save requirements
    with open('requirements.txt', 'w') as f:
        subprocess.run([pip_cmd, 'freeze'], stdout=f)
    
    print("✅ All dependencies installed")

def create_env_file():
    """Create .env file if it doesn't exist"""
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write("""# API Keys
OPENAI_API_KEY=your_openai_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Configuration
MAX_FILE_SIZE=102400  # 100KB in bytes
CACHE_DURATION=86400  # 24 hours in seconds
LOG_LEVEL=INFO

# API Settings
OPENAI_MODEL=gpt-3.5-turbo
DEEPSEEK_MODEL=deepseek-chat
""")
        print("\n⚠️ Please edit .env file and add your API keys:")
        print("  - OpenAI API key")
        print("  - Deepseek API key (optional)")

def create_project_structure():
    """Create the project directory structure"""
    directories = [
        'logs',
        'cache',
        'uploads',
        'reports'
    ]
    
    print("\n📁 Creating project structure...")
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")

def setup_logging():
    """Create logging configuration file"""
    log_config = """
{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        }
    },
    "handlers": {
        "file": {
            "level": "INFO",
            "class": "logging.FileHandler",
            "filename": "logs/security_analyzer.log",
            "formatter": "standard"
        }
    },
    "loggers": {
        "": {
            "handlers": ["file"],
            "level": "INFO"
        }
    }
}
"""
    with open('logging_config.json', 'w') as f:
        f.write(log_config)
    print("✅ Logging configuration created")

def main():
    print("""
╔══════════════════════════════════════╗
║       CodeGuardianAI Setup v2        ║
╚══════════════════════════════════════╝
    """)
    
    try:
        print("1️⃣  Checking Python version...")
        check_python_version()
        
        print("\n2️⃣  Creating virtual environment...")
        create_virtual_environment()
        
        print("\n3️⃣  Installing dependencies...")
        install_dependencies()
        
        print("\n4️⃣  Creating project structure...")
        create_project_structure()
        
        print("\n5️⃣  Setting up logging...")
        setup_logging()
        
        print("\n6️⃣  Creating configuration file...")
        create_env_file()
        
        print("\n✅ Setup complete!")
        print("\n🚀 To run the application:")
        if platform.system() == 'Windows':
            print("1. venv\\Scripts\\activate")
        else:
            print("1. source venv/bin/activate")
        print("2. streamlit run app.py")
        print("\n⚠️ Don't forget to update your API keys in the .env file!")
        
    except Exception as e:
        print(f"\n❌ Error during setup: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()