"""
Core functionality for handling detected threats including risk assessment,
alert generation, and process termination.
"""
import psutil
from datetime import datetime
from typing import Dict, Any, Optional

from ..utils.emailer import send_email_alert
from ..utils.notifier import send_alert
from ..utils.killer import kill_process
from .predictor import predict_process_risk

def assess_process_risk(process: psutil.Process) -> tuple[float, Dict[str, Any]]:
    """
    Assess the risk level of a process and gather its metrics.
    
    Args:
        process: psutil.Process object to analyze
        
    Returns:
        Tuple of (risk_score, process_metrics)
    """
    try:
        cpu = process.cpu_percent(interval=0.1)
        memory = process.memory_percent()
        num_threads = process.num_threads()
        num_connections = len(process.connections())
        
        # Calculate risk score
        risk_score = predict_process_risk([[cpu, memory, num_threads, num_connections]])
        
        metrics = {
            'name': process.name(),
            'pid': process.pid,
            'cpu_percent': cpu,
            'memory_percent': memory,
            'num_threads': num_threads,
            'num_connections': num_connections,
            'exe_path': process.exe(),
            'risk_score': risk_score
        }
        
        return risk_score, metrics
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        raise ProcessLookupError(f"Could not assess process: {str(e)}")

def handle_threat(process: psutil.Process, config: Dict[str, Any], callback: Optional[callable] = None) -> Dict[str, Any]:
    """
    Handle a detected threat by assessing risk, sending alerts, and potentially terminating.
    
    Args:
        process: psutil.Process object representing the threat
        config: Dictionary containing alert configuration and thresholds
        callback: Optional callback function for status updates
    
    Returns:
        Dictionary containing threat handling results
    """
    try:
        # Assess risk and get process metrics
        risk_score, metrics = assess_process_risk(process)
        
        # Determine status based on risk score
        if risk_score > config.get('risk_threshold', 0.7):
            status = "🚨 High Risk"
        else:
            status = "⚠️ Suspicious"
            
        metrics['status'] = status
        
        # Prepare alert message
        alert_message = (
            f"Suspicious process detected:\n"
            f"Name: {metrics['name']}\n"
            f"PID: {metrics['pid']}\n"
            f"Path: {metrics['exe_path']}\n"
            f"CPU: {metrics['cpu_percent']:.1f}%\n"
            f"Memory: {metrics['memory_percent']:.1f}%\n"
            f"Threads: {metrics['num_threads']}\n"
            f"Network Connections: {metrics['num_connections']}\n"
            f"Risk Score: {risk_score:.2f}\n"
            f"Status: {status}\n\n"
            f"Actions Taken: {'Process will be terminated' if risk_score > config.get('risk_threshold', 0.7) else 'Process is being monitored'}"
        )
        
        # Send email alert if enabled
        if config.get('email_alerts', True):
            try:
                send_email_alert(
                    subject=f"⚠️ Security Alert: {status} Process Detected",
                    body=alert_message
                )
                if callback:
                    callback("alert_sent", "email")
            except Exception as e:
                if callback:
                    callback("alert_failed", {"type": "email", "error": str(e)})
        
        # Show popup alert if enabled
        if config.get('popup_alerts', True):
            try:
                send_alert(metrics['name'], metrics['pid'])
                if callback:
                    callback("alert_sent", "popup")
            except Exception as e:
                if callback:
                    callback("alert_failed", {"type": "popup", "error": str(e)})
        
        # Auto-kill if high risk
        if risk_score > config.get('risk_threshold', 0.7):
            try:
                kill_process(metrics['pid'])
                metrics['terminated'] = True
                if callback:
                    callback("process_terminated", metrics['pid'])
            except Exception as e:
                metrics['terminated'] = False
                if callback:
                    callback("termination_failed", {"pid": metrics['pid'], "error": str(e)})
        
        return metrics
        
    except ProcessLookupError as e:
        if callback:
            callback("process_error", str(e))
        return {"error": str(e)}
    except Exception as e:
        if callback:
            callback("error", str(e))
        return {"error": str(e)}