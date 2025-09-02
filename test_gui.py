#!/usr/bin/env python3
"""
Test script to verify GUI functionality
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    try:
        import tkinter as tk
        print("✅ tkinter imported successfully")
        
        import psutil
        print("✅ psutil imported successfully")
        
        from detector import scan_for_malware
        print("✅ detector module imported successfully")
        
        from predictor import predict_process_risk
        print("✅ predictor module imported successfully")
        
        from killer import kill_process
        print("✅ killer module imported successfully")
        
        from emailer import send_email_alert
        print("✅ emailer module imported successfully")
        
        from vt_scanner import get_file_hash, check_virustotal
        print("✅ vt_scanner module imported successfully")
        
        from notifier import send_alert
        print("✅ notifier module imported successfully")
        
        from logger import log_detection
        print("✅ logger module imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_gui_creation():
    """Test if GUI can be created without errors"""
    try:
        from gui import CybersecurityBotGUI
        import tkinter as tk
        
        root = tk.Tk()
        root.withdraw()  # Hide the window for testing
        
        app = CybersecurityBotGUI(root)
        print("✅ GUI created successfully")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"❌ GUI creation error: {e}")
        return False

def main():
    print("🛡️ Testing Cybersecurity Bot GUI...")
    print("=" * 50)
    
    # Test imports
    print("\n📦 Testing module imports...")
    if not test_imports():
        print("❌ Import tests failed!")
        return False
    
    # Test GUI creation
    print("\n🖥️ Testing GUI creation...")
    if not test_gui_creation():
        print("❌ GUI creation test failed!")
        return False
    
    print("\n🎉 All tests passed! GUI is ready to use.")
    print("\n🚀 To launch the GUI, run:")
    print("   python gui.py")
    print("   or")
    print("   start_gui.bat")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
