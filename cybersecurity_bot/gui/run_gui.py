#!/usr/bin/env python3
"""
Cybersecurity Bot GUI Launcher
Simple script to launch the GUI interface
"""

import sys
import os

# Add current directory to path to import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from cybersecurity_bot.gui.gui import main
    
    if __name__ == "__main__":
        print("🛡️ Starting Cybersecurity Bot GUI...")
        main()
        
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure all required dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error starting GUI: {e}")
    sys.exit(1)