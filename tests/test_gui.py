"""
Test suite for GUI functionality of the cybersecurity bot.
"""
import pytest
import tkinter as tk
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from cybersecurity_bot.gui.simple_gui import SimpleCybersecurityBotGUI

# Mock the entire tkinter.Tk class
class MockTk:
    def __init__(self):
        self.calls = []
        self.protocol_handlers = {}
        
    def title(self, *args):
        self.calls.append(('title', args))
        
    def geometry(self, *args):
        self.calls.append(('geometry', args))
        
    def protocol(self, name, handler):
        self.protocol_handlers[name] = handler
        
    def destroy(self):
        self.calls.append(('destroy', None))
        
    def mainloop(self):
        pass

@pytest.fixture
def mock_root():
    """Create a mock Tk root for testing"""
    with patch('tkinter.Tk', MockTk):
        root = tk.Tk()
        yield root

@pytest.fixture
def gui(mock_root):
    """Create a GUI instance for testing"""
    with patch('tkinter.Frame'), \
         patch('tkinter.Label'), \
         patch('tkinter.Button'), \
         patch('tkinter.Entry'), \
         patch('tkinter.Checkbutton'), \
         patch('tkinter.StringVar'), \
         patch('tkinter.BooleanVar'), \
         patch('tkinter.scrolledtext.ScrolledText'):
        return SimpleCybersecurityBotGUI(mock_root)

def test_gui_initialization(gui):
    """Test GUI initialization"""
    assert hasattr(gui, 'root')
    assert gui.is_monitoring == False
    assert gui.monitor_thread is None
    assert gui.threat_count == 0

def test_config_loading(gui):
    """Test configuration loading"""
    with patch('pathlib.Path.open', create=True) as mock_open, \
         patch('yaml.safe_load') as mock_yaml:
        # Mock the config data
        mock_yaml.return_value = {
            'monitor_interval': 5,
            'risk_threshold': 0.7,
            'email_alerts': True,
            'popup_alerts': True
        }
        gui._load_config()
        assert isinstance(gui.config, dict)
        assert gui.config.get('monitor_interval') == 5
        assert gui.config.get('risk_threshold') == 0.7
        assert gui.config.get('email_alerts') is True
        assert gui.config.get('popup_alerts') is True

@patch('threading.Thread')
def test_start_stop_monitoring(mock_thread, gui):
    """Test monitoring start/stop functionality"""
    # Mock the thread
    mock_thread_instance = MagicMock()
    mock_thread.return_value = mock_thread_instance
    
    # Start monitoring
    gui.start_monitoring()
    assert gui.is_monitoring == True
    assert gui.monitor_thread is not None
    mock_thread_instance.start.assert_called_once()
    
    # Stop monitoring
    gui.stop_monitoring()
    assert gui.is_monitoring == False
    
@patch('cybersecurity_bot.core.detector.scan_for_malware')
@patch('tkinter.messagebox.showinfo')
def test_quick_scan(mock_showinfo, mock_scan, gui):
    """Test quick scan functionality"""
    mock_scan.return_value = []
    gui.quick_scan()
    mock_scan.assert_called_once()
    mock_showinfo.assert_called_once()

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

@patch('yaml.safe_dump')
def test_config_saving(mock_yaml_dump, gui):
    """Test configuration saving"""
    with patch('pathlib.Path.open', create=True), \
         patch('tkinter.StringVar') as mock_string_var, \
         patch('tkinter.BooleanVar') as mock_bool_var:
        
        # Setup mock variables
        mock_interval = MagicMock()
        mock_interval.get.return_value = "10"
        mock_threshold = MagicMock()
        mock_threshold.get.return_value = "0.8"
        mock_email = MagicMock()
        mock_email.get.return_value = True
        mock_popup = MagicMock()
        mock_popup.get.return_value = False
        
        gui.interval_var = mock_interval
        gui.threshold_var = mock_threshold
        gui.email_var = mock_email
        gui.popup_var = mock_popup
        
        # Save config
        gui.save_config()
        
        # Verify yaml.safe_dump was called with correct config
        mock_yaml_dump.assert_called_once()
        config_arg = mock_yaml_dump.call_args[0][0]
        assert config_arg['monitor_interval'] == 10
        assert config_arg['risk_threshold'] == 0.8
        assert config_arg['email_alerts'] is True
        assert config_arg['popup_alerts'] is False

@patch('tkinter.messagebox.showerror')
def test_gui_error_handling(mock_error, gui):
    """Test GUI error handling"""
    with patch('tkinter.StringVar') as mock_string_var:
        # Setup mock variables
        mock_interval = MagicMock()
        mock_interval.get.return_value = "-1"
        mock_threshold = MagicMock()
        mock_threshold.get.return_value = "0.7"
        
        gui.interval_var = mock_interval
        gui.threshold_var = mock_threshold
        
        # Test invalid monitor interval
        gui.save_config()
        mock_error.assert_called()
        mock_error.reset_mock()
        
        # Test invalid risk threshold
        mock_interval.get.return_value = "5"
        mock_threshold.get.return_value = "2.0"
        gui.save_config()
        mock_error.assert_called()