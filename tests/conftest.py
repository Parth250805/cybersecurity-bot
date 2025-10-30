"""
Shared test configuration and fixtures.
"""
import pytest
import psutil
from unittest.mock import Mock
import os
import tempfile
from pathlib import Path

@pytest.fixture
def temp_config_path():
    """Create a temporary config file"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.yaml') as f:
        f.write("""
monitor_interval_seconds: 5
cpu_high_threshold: 50
memory_high_threshold: 30
risk_score_kill_threshold: 0.7
email_alerts: true
popups: true
whitelist:
  - system
  - explorer.exe
blacklist:
  - malware.exe
  - virus.exe
""")
        path = Path(f.name)
    yield path
    os.unlink(path)

@pytest.fixture
def mock_process():
    """Create a mock process for testing"""
    process = Mock(spec=psutil.Process)
    process.name.return_value = "test_process.exe"
    process.pid = 12345
    process.cpu_percent.return_value = 20.0
    process.memory_percent.return_value = 15.0
    process.num_threads.return_value = 5
    process.connections.return_value = []
    process.exe.return_value = "/path/to/test_process.exe"
    return process

@pytest.fixture
def sample_threat_data():
    """Sample threat data for testing"""
    return {
        'name': 'suspicious_process.exe',
        'pid': 12345,
        'cpu_percent': 90.0,
        'memory_percent': 80.0,
        'num_threads': 50,
        'num_connections': 20,
        'risk_score': 0.85,
        'status': '🚨 High Risk'
    }