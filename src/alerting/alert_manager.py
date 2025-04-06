"""
Alert Manager Module.

This module provides functionality for managing and sending alerts when suspicious
activities are detected.
"""

import logging
import json
import time
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Callable

from src.utils.config import load_config

logger = logging.getLogger(__name__)

class AlertManager:
    """
    Manages alerts for suspicious activities detected in the system.
    
    This class is responsible for:
    1. Evaluating alert conditions based on collected traces
    2. Generating alerts for suspicious activities
    3. Sending notifications through various channels (console, file, email, etc.)
    4. Managing alert severity levels and thresholds
    """
    
    SEVERITY_LEVELS = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }
    
    def __init__(self):
        """Initialize the AlertManager."""
        self.config = load_config().get("alerting", {})
        self.alert_history = []
        self.alert_handlers = {}
        self.alert_queue = queue.Queue()
        self.alert_thread = None
        self.running = False
        self.alert_dir = Path(self.config.get("alert_dir", "data/alerts"))
        self.alert_dir.mkdir(parents=True, exist_ok=True)
        
        # Register default alert handlers
        self.register_alert_handler("console", self._console_alert_handler)
        self.register_alert_handler("file", self._file_alert_handler)
        
        # Initialize alert processors
        self._init_alert_processors()
    
    def _init_alert_processors(self):
        """Initialize alert processors."""
        self.alert_processors = {
            "process": self._process_alert_processor,
            "network": self._network_alert_processor,
            "file": self._file_alert_processor,
            "registry": self._registry_alert_processor,
            "system": self._system_alert_processor,
            "malware": self._malware_alert_processor,
            "technique": self._technique_alert_processor
        }
    
    def register_alert_handler(self, handler_name: str, handler_func: Callable):
        """
        Register an alert handler function.
        
        Args:
            handler_name: Name of the handler
            handler_func: Handler function that takes an alert dict as input
        """
        self.alert_handlers[handler_name] = handler_func
        logger.info(f"Registered alert handler: {handler_name}")
    
    def start(self):
        """Start the alert processing thread."""
        if self.alert_thread is not None and self.alert_thread.is_alive():
            logger.warning("Alert thread is already running")
            return
        
        self.running = True
        self.alert_thread = threading.Thread(target=self._process_alert_queue)
        self.alert_thread.daemon = True
        self.alert_thread.start()
        logger.info("Alert manager started")
    
    def stop(self):
        """Stop the alert processing thread."""
        self.running = False
        if self.alert_thread is not None:
            self.alert_thread.join(timeout=5.0)
        logger.info("Alert manager stopped")
    
    def _process_alert_queue(self):
        """Process alerts from the queue."""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1.0)
                self._handle_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {str(e)}")
    
    def _handle_alert(self, alert: Dict[str, Any]):
        """
        Handle an alert by sending it to all registered handlers.
        
        Args:
            alert: Alert dictionary
        """
        # Add to history
        self.alert_history.append(alert)
        
        # Trim history if needed
        max_history = self.config.get("max_history", 1000)
        if len(self.alert_history) > max_history:
            self.alert_history = self.alert_history[-max_history:]
        
        # Send to all handlers
        enabled_handlers = self.config.get("enabled_handlers", ["console", "file"])
        for handler_name in enabled_handlers:
            if handler_name in self.alert_handlers:
                try:
                    self.alert_handlers[handler_name](alert)
                except Exception as e:
                    logger.error(f"Error in alert handler {handler_name}: {str(e)}")
    
    def _console_alert_handler(self, alert):
        """
        Handle an alert by printing to console.
        
        Args:
            alert: Alert dictionary or object
        """
        if isinstance(alert, dict):
            severity = alert.get("severity", "INFO")
            timestamp = alert.get("timestamp", datetime.now().isoformat())
            message = alert.get("message", "")
            details = alert.get("details", {})
        else:
            severity = getattr(alert, "severity", "INFO")
            timestamp = getattr(alert, "timestamp", datetime.now().isoformat())
            message = getattr(alert, "message", "")
            details = getattr(alert, "details", {})
        
        console_format = self.config.get("console_format", "standard")
        if console_format == "standard":
            logger.warning(f"[{severity}] {timestamp} - {message}")
        else:
            if isinstance(alert, dict):
                logger.warning(f"ALERT: {json.dumps(alert, indent=2)}")
            else:
                logger.warning(f"ALERT: {severity} - {message}")
    
    def _file_alert_handler(self, alert):
        """
        Handle an alert by writing to a file.
        
        Args:
            alert: Alert dictionary or object
        """
        try:
            if isinstance(alert, dict):
                timestamp_str = alert.get("timestamp", datetime.now().isoformat())
                alert_dict = alert
            else:
                timestamp_str = getattr(alert, "timestamp", datetime.now().isoformat())
                
                severity = getattr(alert, "severity", "INFO")
                if hasattr(severity, "name"):
                    severity = severity.name
                
                alert_type = getattr(alert, "type", "")
                if hasattr(alert_type, "name"):
                    alert_type = alert_type.name
                
                alert_dict = {
                    "timestamp": timestamp_str,
                    "severity": severity,
                    "type": alert_type,
                    "message": getattr(alert, "message", ""),
                    "details": getattr(alert, "details", {})
                }
            
            timestamp = datetime.fromisoformat(timestamp_str) if isinstance(timestamp_str, str) else datetime.now()
            date_str = timestamp.strftime("%Y%m%d")
            alert_file = self.alert_dir / f"alerts_{date_str}.json"
            
            # Create file if it doesn't exist
            if not alert_file.exists():
                with open(alert_file, "w") as f:
                    json.dump([], f)
            
            # Read existing alerts
            try:
                with open(alert_file, "r") as f:
                    alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
            
            if "details" in alert_dict and isinstance(alert_dict["details"], dict):
                for key, value in alert_dict["details"].items():
                    if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                        alert_dict["details"][key] = str(value)
            
            # Add new alert
            alerts.append(alert_dict)
            
            # Write back to file
            with open(alert_file, "w") as f:
                json.dump(alerts, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error writing alert to file: {str(e)}")
    
    def evaluate_traces(self, traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate traces and generate alerts if suspicious activities are detected.
        
        Args:
            traces: Collected system traces
            
        Returns:
            List of generated alerts
        """
        generated_alerts = []
        
        # Process different types of traces
        for trace_type, processor in self.alert_processors.items():
            if trace_type in traces:
                alerts = processor(traces[trace_type], traces)
                if alerts:
                    generated_alerts.extend(alerts)
        
        # Add alerts to queue
        for alert in generated_alerts:
            self.alert_queue.put(alert)
        
        return generated_alerts
    
    def _process_alert_processor(self, processes: List[Dict[str, Any]], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for suspicious processes.
        
        Args:
            processes: List of process traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        suspicious_processes = self.config.get("suspicious_processes", [
            "mimikatz", "psexec", "netcat", "nc.exe", "powershell.exe -nop -w hidden"
        ])
        
        for process in processes:
            process_name = process.get("name", "").lower()
            cmdline = process.get("cmdline", "").lower()
            
            # Check for suspicious process names or command lines
            for suspicious in suspicious_processes:
                if suspicious.lower() in process_name or suspicious.lower() in cmdline:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "process",
                        "severity": "HIGH",
                        "message": f"Suspicious process detected: {process_name}",
                        "details": {
                            "process": process,
                            "matched_pattern": suspicious
                        }
                    })
            
            # Check for unusual process behavior
            if process.get("cpu_usage", 0) > self.config.get("high_cpu_threshold", 90):
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "process",
                    "severity": "MEDIUM",
                    "message": f"High CPU usage detected in process: {process_name}",
                    "details": {
                        "process": process,
                        "cpu_usage": process.get("cpu_usage")
                    }
                })
        
        return alerts
    
    def _network_alert_processor(self, connections: List[Dict[str, Any]], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for suspicious network connections.
        
        Args:
            connections: List of network connection traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        suspicious_ports = self.config.get("suspicious_ports", [4444, 8080, 9001, 31337])
        suspicious_ips = self.config.get("suspicious_ips", [])
        
        for connection in connections:
            remote_address = connection.get("remote_address", {})
            remote_ip = remote_address.get("ip", "")
            remote_port = remote_address.get("port", 0)
            
            # Check for suspicious ports
            if remote_port in suspicious_ports:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "network",
                    "severity": "MEDIUM",
                    "message": f"Connection to suspicious port detected: {remote_ip}:{remote_port}",
                    "details": {
                        "connection": connection
                    }
                })
            
            # Check for suspicious IPs
            if remote_ip in suspicious_ips:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "network",
                    "severity": "HIGH",
                    "message": f"Connection to suspicious IP detected: {remote_ip}",
                    "details": {
                        "connection": connection
                    }
                })
            
            # Check for suspicious payloads
            payload = connection.get("payload", "")
            if payload and ("MZ" in payload[:10] or "shell" in payload.lower() or "exec" in payload.lower()):
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "network",
                    "severity": "CRITICAL",
                    "message": "Suspicious network payload detected",
                    "details": {
                        "connection": connection,
                        "payload_excerpt": payload[:100] if len(payload) > 100 else payload
                    }
                })
        
        return alerts
    
    def _file_alert_processor(self, files: List[Dict[str, Any]], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for suspicious files.
        
        Args:
            files: List of file traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        suspicious_extensions = self.config.get("suspicious_extensions", [".exe", ".dll", ".ps1", ".bat", ".vbs"])
        suspicious_paths = self.config.get("suspicious_paths", ["temp", "windows\\temp", "appdata\\local\\temp"])
        
        for file in files:
            file_path = file.get("path", "").lower()
            
            # Check for suspicious extensions in suspicious locations
            for ext in suspicious_extensions:
                if file_path.endswith(ext):
                    for path in suspicious_paths:
                        if path.lower() in file_path:
                            alerts.append({
                                "timestamp": datetime.now().isoformat(),
                                "type": "file",
                                "severity": "HIGH",
                                "message": f"Suspicious file detected: {file_path}",
                                "details": {
                                    "file": file
                                }
                            })
                            break
        
        return alerts
    
    def _registry_alert_processor(self, registry: List[Dict[str, Any]], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for suspicious registry changes.
        
        Args:
            registry: List of registry traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        suspicious_keys = self.config.get("suspicious_registry_keys", [
            "run", "runonce", "winlogon", "userinit", "shell", "startup"
        ])
        
        for reg in registry:
            key = reg.get("key", "").lower()
            
            # Check for suspicious registry keys
            for suspicious in suspicious_keys:
                if suspicious.lower() in key:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "registry",
                        "severity": "HIGH",
                        "message": f"Suspicious registry key modified: {key}",
                        "details": {
                            "registry": reg
                        }
                    })
                    break
        
        return alerts
    
    def _system_alert_processor(self, system: Dict[str, Any], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for suspicious system behavior.
        
        Args:
            system: System resource traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        # Check for high CPU usage
        cpu_percent = system.get("cpu_percent", 0)
        if cpu_percent > self.config.get("system_cpu_threshold", 95):
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "type": "system",
                "severity": "MEDIUM",
                "message": f"High system CPU usage detected: {cpu_percent}%",
                "details": {
                    "system": system
                }
            })
        
        # Check for high memory usage
        memory_percent = system.get("memory_percent", 0)
        if memory_percent > self.config.get("system_memory_threshold", 95):
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "type": "system",
                "severity": "MEDIUM",
                "message": f"High system memory usage detected: {memory_percent}%",
                "details": {
                    "system": system
                }
            })
        
        return alerts
    
    def _malware_alert_processor(self, malware: Dict[str, Any], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for detected malware.
        
        Args:
            malware: Malware analysis traces
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        if malware.get("detected", False):
            severity = "CRITICAL" if malware.get("confidence", 0) > 0.8 else "HIGH"
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "type": "malware",
                "severity": severity,
                "message": f"Malware detected: {malware.get('name', 'Unknown')}",
                "details": {
                    "malware": malware
                }
            })
        
        return alerts
    
    def _technique_alert_processor(self, techniques: List[Dict[str, Any]], traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process alerts for detected attack techniques.
        
        Args:
            techniques: List of detected techniques
            traces: Complete traces dictionary
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        for technique in techniques:
            technique_id = technique.get("technique_id", "")
            technique_name = technique.get("technique_name", "")
            confidence = technique.get("confidence", 0)
            
            if confidence > self.config.get("technique_confidence_threshold", 0.7):
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "technique",
                    "severity": "HIGH",
                    "message": f"Attack technique detected: {technique_id} ({technique_name})",
                    "details": {
                        "technique": technique
                    }
                })
        
        return alerts
    
    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, 
                  alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts with optional filtering.
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity level
            alert_type: Filter by alert type
            
        Returns:
            List of alerts
        """
        filtered_alerts = self.alert_history
        
        # Filter by severity
        if severity:
            severity_level = self.SEVERITY_LEVELS.get(severity.upper(), 0)
            filtered_alerts = [
                alert for alert in filtered_alerts 
                if self.SEVERITY_LEVELS.get(alert.get("severity", "INFO").upper(), 0) >= severity_level
            ]
        
        # Filter by type
        if alert_type:
            filtered_alerts = [
                alert for alert in filtered_alerts
                if alert.get("type", "") == alert_type
            ]
        
        # Sort by timestamp (newest first)
        filtered_alerts = sorted(
            filtered_alerts,
            key=lambda x: x.timestamp if hasattr(x, "timestamp") else (x.get("timestamp", "") if isinstance(x, dict) else ""),
            reverse=True
        )
        
        # Limit results
        return filtered_alerts[:limit]
    
    def clear_alerts(self):
        """Clear all alerts from history."""
        self.alert_history = []
        logger.info("Alert history cleared")
