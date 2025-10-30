"""
Test suite for GUI functionality of the cybersecurity bot.
"""
import pytest
import tkinter as tk
from unittest.mock import Mock, patch
from pathlib import Path

from cybersecurity_bot.gui.simple_gui import SimpleCybersecurityBotGUI

@pytest.fixture
def mock_root():
    """Create a mock Tk root for testing"""
    root = tk.Tk()
    yield root
    root.destroy()

@pytest.fixture
def gui(mock_root):
    """Create a GUI instance for testing"""
    return SimpleCybersecurityBotGUI(mock_root)

def test_gui_initialization(gui):
    """Test GUI initialization"""
    assert isinstance(gui.root, tk.Tk)
    assert gui.is_monitoring == False
    assert gui.monitor_thread is None
    assert gui.threat_count == 0

def test_config_loading(gui):
    """Test configuration loading"""
    assert isinstance(gui.config, dict)
    assert 'monitor_interval' in gui.config
    assert 'risk_threshold' in gui.config
    assert 'email_alerts' in gui.config
    assert 'popup_alerts' in gui.config

def test_start_stop_monitoring(gui):
    """Test monitoring start/stop functionality"""
    # Start monitoring
    gui.start_monitoring()
    assert gui.is_monitoring == True
    assert gui.monitor_thread is not None
    assert gui.monitor_thread.is_alive()
    
    # Stop monitoring
    gui.stop_monitoring()
    assert gui.is_monitoring == False
    assert not gui.monitor_thread.is_alive()

@patch('cybersecurity_bot.core.detector.scan_for_malware')
def test_quick_scan(mock_scan, gui):
    """Test quick scan functionality"""
    mock_scan.return_value = []
    gui.quick_scan()
    mock_scan.assert_called_once()

@patch('cybersecurity_bot.utils.emailer.send_email_alert')
@patch('cybersecurity_bot.utils.notifier.send_alert')
def test_alert_systems(mock_send_alert, mock_send_email, gui):
    """Test alert systems"""
    # Create a mock process
    mock_process = Mock()
    mock_process.name.return_value = "test_process.exe"
    mock_process.pid = 12345
    mock_process.cpu_percent.return_value = 90.0
    mock_process.memory_percent.return_value = 80.0
    mock_process.num_threads.return_value = 50
    mock_process.connections.return_value = []
    
    # Handle the threat
    gui.handle_threat_detected(mock_process)
    
    # Check if alerts were sent
    if gui.config['email_alerts']:
        mock_send_email.assert_called()
    if gui.config['popup_alerts']:
        mock_send_alert.assert_called()

def test_config_saving(gui, tmp_path):
    """Test configuration saving"""
    # Modify config values
    gui.interval_var.set("10")
    gui.threshold_var.set("0.8")
    gui.email_var.set(True)
    gui.popup_var.set(False)
    
    # Save config
    with patch('pathlib.Path.open'):
        gui.save_config()
        
    # Verify config values were updated
    assert gui.config['monitor_interval'] == 10
    assert gui.config['risk_threshold'] == 0.8
    assert gui.config['email_alerts'] == True
    assert gui.config['popup_alerts'] == False

def test_gui_error_handling(gui):
    """Test GUI error handling"""
    # Test invalid monitor interval
    gui.interval_var.set("-1")
    with patch('tkinter.messagebox.showerror') as mock_error:
        gui.save_config()
        mock_error.assert_called()
    
    # Test invalid risk threshold
    gui.interval_var.set("5")  # Reset to valid value
    gui.threshold_var.set("2.0")
    with patch('tkinter.messagebox.showerror') as mock_error:
        gui.save_config()
        mock_error.assert_called()