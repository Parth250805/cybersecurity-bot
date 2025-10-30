"""
Test suite for core functionality of the cybersecurity bot.
"""
import pytest
import psutil
import numpy as np
from unittest.mock import Mock, patch
from pathlib import Path

from cybersecurity_bot.core.predictor import predict_process_risk
from cybersecurity_bot.core.detector import scan_for_malware
from cybersecurity_bot.core.threat_handler import assess_process_risk, handle_threat

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

def test_predict_process_risk():
    """Test process risk prediction"""
    # Test with benign-looking process
    benign_features = [[10.0, 5.0, 3, 1]]
    risk_score = predict_process_risk(benign_features)
    assert 0 <= risk_score <= 1
    assert risk_score < 0.5  # Should be considered low risk

    # Test with suspicious-looking process
    suspicious_features = [[90.0, 80.0, 50, 20]]
    risk_score = predict_process_risk(suspicious_features)
    assert 0 <= risk_score <= 1
    assert risk_score > 0.5  # Should be considered high risk

def test_assess_process_risk(mock_process):
    """Test process risk assessment"""
    risk_score, metrics = assess_process_risk(mock_process)
    
    assert 0 <= risk_score <= 1
    assert isinstance(metrics, dict)
    assert metrics['name'] == "test_process.exe"
    assert metrics['pid'] == 12345
    assert metrics['cpu_percent'] == 20.0
    assert metrics['memory_percent'] == 15.0
    assert metrics['num_threads'] == 5
    assert metrics['num_connections'] == 0

@patch('cybersecurity_bot.utils.emailer.send_email_alert')
@patch('cybersecurity_bot.utils.notifier.send_alert')
def test_handle_threat(mock_send_alert, mock_send_email, mock_process):
    """Test threat handling functionality"""
    config = {
        'risk_threshold': 0.7,
        'email_alerts': True,
        'popup_alerts': True
    }
    
    def callback(event_type, data):
        assert event_type in ['alert_sent', 'alert_failed', 'process_terminated']
        
    result = handle_threat(mock_process, config, callback)
    
    assert isinstance(result, dict)
    assert 'name' in result
    assert 'pid' in result
    assert 'risk_score' in result
    assert 'status' in result

def test_scan_for_malware():
    """Test malware scanning functionality"""
    stop_event = Mock()
    stop_event.is_set.return_value = False
    
    suspicious_processes = scan_for_malware(stop_event)
    assert isinstance(suspicious_processes, list)

@pytest.mark.parametrize("cpu,mem,threads,connections,expected_high_risk", [
    (10, 5, 3, 1, False),    # Low resource usage - should be low risk
    (90, 80, 50, 20, True),  # High resource usage - should be high risk
    (50, 50, 10, 5, None),   # Medium resource usage - risk could vary
])
def test_risk_assessment_scenarios(cpu, mem, threads, connections, expected_high_risk):
    """Test risk assessment with different scenarios"""
    features = [[cpu, mem, threads, connections]]
    risk_score = predict_process_risk(features)
    
    assert 0 <= risk_score <= 1
    
    if expected_high_risk is not None:
        if expected_high_risk:
            assert risk_score > 0.5, "Expected high risk score"
        else:
            assert risk_score < 0.5, "Expected low risk score"