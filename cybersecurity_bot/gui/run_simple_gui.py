#!/usr/bin/env python3
"""
Simple GUI Launcher for Cybersecurity Bot
"""

import sys
import os

# Ensure project root is on sys.path so `cybersecurity_bot` package resolves
_this_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_this_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# If a local venv exists, relaunch using it to ensure dependencies are available
try:
    if not os.environ.get("VIRTUAL_ENV"):
        venv_python = os.path.join(_project_root, ".venv", "Scripts", "python.exe")
        if os.path.exists(venv_python) and os.path.abspath(sys.executable) != os.path.abspath(venv_python):
            import subprocess
            subprocess.call([venv_python, __file__] + sys.argv[1:])
            sys.exit(0)
except Exception:
    pass

try:
    from cybersecurity_bot.gui.simple_gui import main
    
    if __name__ == "__main__":
        print("🛡️ Starting Cybersecurity Bot Simple GUI...")
        main()
        
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure all required dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting GUI: {e}")
    sys.exit(1)