import os
import sys
import subprocess
import platform

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 9):
        print("Error: Python 3.9 or higher is required")
        sys.exit(1)

def create_virtual_environment():
    """Create a virtual environment"""
    if not os.path.exists('venv'):
        subprocess.run([sys.executable, '-m', 'venv', 'venv'])

def install_dependencies():
    """Install required packages"""
    pip_cmd = 'venv\\Scripts\\pip.exe' if platform.system() == 'Windows' else 'venv/bin/pip'
    subprocess.run([pip_cmd, 'install', '-r', 'requirements.txt'])

def create_env_file():
    """Create .env file if it doesn't exist"""
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write('OPENAI_API_KEY=your_api_key_here\n')
        print("\n⚠️ Please edit .env file and add your OpenAI API key")

def main():
    print("🚀 Setting up CodeGuardianAI...")
    
    print("\n1. Checking Python version...")
    check_python_version()
    
    print("\n2. Creating virtual environment...")
    create_virtual_environment()
    
    print("\n3. Installing dependencies...")
    install_dependencies()
    
    print("\n4. Setting up configuration...")
    create_env_file()
    
    print("\n✅ Setup complete!")
    print("\nTo run the application:")
    if platform.system() == 'Windows':
        print("1. venv\\Scripts\\activate")
    else:
        print("1. source venv/bin/activate")
    print("2. streamlit run app.py")

if __name__ == "__main__":
    main()