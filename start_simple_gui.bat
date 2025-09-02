@echo off
echo 🛡️ Starting Cybersecurity Bot Simple GUI...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo 🔧 Activating virtual environment...
    call venv\Scripts\activate.bat
)

REM Install dependencies if needed
echo 📦 Checking dependencies...
pip install -r requirements.txt >nul 2>&1

REM Start the simple GUI
echo 🚀 Launching Simple GUI...
python run_simple_gui.py

pause
