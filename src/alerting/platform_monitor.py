"""
Platform-specific Monitoring Module.

This module provides platform-specific implementations for real-time monitoring
of system activities on Windows and Mac environments.
"""

import logging
import os
import time
import threading
import psutil
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path

from src.utils.platform_detector import PlatformDetector
from src.trace_collector.windows_collector import WindowsTraceCollector
from src.trace_collector.mac_collector import MacTraceCollector

logger = logging.getLogger(__name__)

class PlatformMonitor:
    """
    Platform-specific monitoring implementation for real-time system monitoring.
    
    This class provides specialized monitoring capabilities for different platforms,
    with specific implementations for Windows and Mac environments.
    """
    
    def __init__(self):
        """Initialize the platform-specific monitor."""
        self.platform_detector = PlatformDetector()
        self.platform = self.platform_detector.get_platform()
        
        # Initialize platform-specific collectors
        if self.platform_detector.is_windows():
            self.collector = WindowsTraceCollector()
            logger.info("Initialized Windows-specific monitoring")
        elif self.platform_detector.is_mac():
            self.collector = MacTraceCollector()
            logger.info("Initialized Mac-specific monitoring")
        else:
            logger.warning(f"Unsupported platform: {self.platform}. Some features may not work.")
            self.collector = None
            
        # Initialize monitoring state
        self.baseline_processes = set()
        self.baseline_network = set()
        self.baseline_established = False
        self.suspicious_processes = set()
        self.suspicious_connections = set()
        self.monitored_directories = []
        self.file_change_history = {}
        
    def establish_baseline(self) -> bool:
        """
        Establish a baseline of normal system activity.
        
        Returns:
            True if baseline was successfully established, False otherwise
        """
        try:
            if not self.collector:
                logger.error("Cannot establish baseline: No platform-specific collector available")
                return False
                
            # Collect baseline process information
            process_info = self.collector.collect_processes()
            self.baseline_processes = {
                (p.get("pid"), p.get("name")) 
                for p in process_info.get("processes", [])
            }
            
            # Collect baseline network information
            network_info = self.collector.collect_network_connections()
            self.baseline_network = {
                (conn.get("local_address", {}).get("ip"), 
                 conn.get("local_address", {}).get("port"),
                 conn.get("remote_address", {}).get("ip"), 
                 conn.get("remote_address", {}).get("port"),
                 conn.get("status"))
                for conn in network_info.get("network_connections", [])
            }
            
            self.baseline_established = True
            logger.info(f"Baseline established: {len(self.baseline_processes)} processes, "
                       f"{len(self.baseline_network)} network connections")
            return True
            
        except Exception as e:
            logger.error(f"Error establishing baseline: {str(e)}")
            return False
            
    def collect_and_analyze(self) -> Dict[str, Any]:
        """
        Collect and analyze system traces using platform-specific collectors.
        
        Returns:
            Dictionary containing collected traces and analysis results
        """
        if not self.collector:
            logger.warning("No platform-specific collector available")
            return {"error": "Unsupported platform"}
            
        try:
            # Collect all traces
            processes = self.collector.collect_processes()
            network_connections = self.collector.collect_network_connections()
            file_system_events = self.collector.collect_file_system_events()
            registry_events = self.collector.collect_registry_events()
            system_resources = self.collector.collect_system_resources()
            
            # Combine into a single traces dictionary
            traces = {
                "timestamp": datetime.now().isoformat(),
                "platform": self.platform,
                "processes": processes.get("processes", []),
                "network_connections": network_connections.get("network_connections", []),
                "file_system_events": file_system_events.get("file_system_events", []),
                "registry_events": registry_events.get("registry_events", []),
                "system_resources": system_resources.get("system_resources", {})
            }
            
            # Perform platform-specific analysis
            analysis_results = self._analyze_platform_specific(traces)
            traces["platform_analysis"] = analysis_results
            
            return traces
            
        except Exception as e:
            logger.error(f"Error in platform-specific monitoring: {str(e)}")
            return {"error": str(e)}
            
    def _analyze_platform_specific(self, traces: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform platform-specific analysis on collected traces.
        
        Args:
            traces: Dictionary containing collected system traces
            
        Returns:
            Dictionary containing analysis results
        """
        analysis = {
            "suspicious_processes": [],
            "suspicious_connections": [],
            "suspicious_file_activities": [],
            "suspicious_registry_activities": [],
            "resource_anomalies": []
        }
        
        # Analyze processes
        if self.baseline_established:
            current_processes = {
                (p.get("pid"), p.get("name")) 
                for p in traces.get("processes", [])
            }
            
            # Find new processes since baseline
            new_processes = current_processes - self.baseline_processes
            for pid, name in new_processes:
                # Check if process is suspicious
                if self._is_suspicious_process(pid, name, traces):
                    process_details = next(
                        (p for p in traces.get("processes", []) 
                         if p.get("pid") == pid and p.get("name") == name),
                        {}
                    )
                    analysis["suspicious_processes"].append({
                        "pid": pid,
                        "name": name,
                        "details": process_details,
                        "reason": "New process with suspicious characteristics"
                    })
        
        # Analyze network connections
        current_connections = {
            (conn.get("local_address", {}).get("ip"), 
             conn.get("local_address", {}).get("port"),
             conn.get("remote_address", {}).get("ip"), 
             conn.get("remote_address", {}).get("port"),
             conn.get("status"))
            for conn in traces.get("network_connections", [])
        }
        
        if self.baseline_established:
            # Find new connections since baseline
            new_connections = current_connections - self.baseline_network
            for conn in new_connections:
                local_ip, local_port, remote_ip, remote_port, status = conn
                
                # Check if connection is suspicious
                if self._is_suspicious_connection(local_ip, local_port, remote_ip, remote_port, status, traces):
                    conn_details = next(
                        (c for c in traces.get("network_connections", [])
                         if c.get("local_address", {}).get("ip") == local_ip and
                         c.get("local_address", {}).get("port") == local_port and
                         c.get("remote_address", {}).get("ip") == remote_ip and
                         c.get("remote_address", {}).get("port") == remote_port),
                        {}
                    )
                    analysis["suspicious_connections"].append({
                        "local_address": {"ip": local_ip, "port": local_port},
                        "remote_address": {"ip": remote_ip, "port": remote_port},
                        "status": status,
                        "details": conn_details,
                        "reason": "Suspicious network connection detected"
                    })
        
        # Analyze file system events
        for event in traces.get("file_system_events", []):
            if self._is_suspicious_file_activity(event):
                analysis["suspicious_file_activities"].append({
                    "path": event.get("path"),
                    "operation": event.get("operation"),
                    "timestamp": event.get("timestamp"),
                    "process": event.get("process"),
                    "reason": "Suspicious file system activity detected"
                })
        
        # Analyze registry events (Windows-specific)
        if self.platform_detector.is_windows():
            for event in traces.get("registry_events", []):
                if self._is_suspicious_registry_activity(event):
                    analysis["suspicious_registry_activities"].append({
                        "key": event.get("key"),
                        "operation": event.get("operation"),
                        "value": event.get("value"),
                        "timestamp": event.get("timestamp"),
                        "process": event.get("process"),
                        "reason": "Suspicious registry activity detected"
                    })
        
        # Analyze system resources
        resources = traces.get("system_resources", {})
        if resources:
            # Check for resource anomalies
            if resources.get("cpu_percent", 0) > 90:
                analysis["resource_anomalies"].append({
                    "resource": "CPU",
                    "value": resources.get("cpu_percent"),
                    "threshold": 90,
                    "reason": "Abnormally high CPU usage"
                })
                
            if resources.get("memory_percent", 0) > 90:
                analysis["resource_anomalies"].append({
                    "resource": "Memory",
                    "value": resources.get("memory_percent"),
                    "threshold": 90,
                    "reason": "Abnormally high memory usage"
                })
        
        return analysis
    
    def _is_suspicious_process(self, pid: int, name: str, traces: Dict[str, Any]) -> bool:
        """
        Check if a process is suspicious.
        
        Args:
            pid: Process ID
            name: Process name
            traces: Dictionary containing collected system traces
            
        Returns:
            True if process is suspicious, False otherwise
        """
        # Get process details
        process_details = next(
            (p for p in traces.get("processes", []) 
             if p.get("pid") == pid and p.get("name") == name),
            {}
        )
        
        # Check for suspicious characteristics
        suspicious = False
        
        # Check for obfuscated or random-looking names
        if len(name) > 10 and sum(c.isdigit() for c in name) > len(name) / 3:
            suspicious = True
            
        # Check for unusual paths
        path = process_details.get("path", "")
        suspicious_paths = ["temp", "tmp", "appdata\\local\\temp"]
        if any(p in path.lower() for p in suspicious_paths):
            suspicious = True
            
        # Check for high resource usage
        if process_details.get("cpu_percent", 0) > 80 or process_details.get("memory_percent", 0) > 80:
            suspicious = True
            
        # Check for unusual command line arguments
        cmdline = process_details.get("cmdline", "")
        suspicious_args = ["-e", "powershell -enc", "cmd /c", "rundll32", "regsvr32"]
        if any(arg in cmdline.lower() for arg in suspicious_args):
            suspicious = True
            
        return suspicious
    
    def _is_suspicious_connection(self, local_ip: str, local_port: int, 
                                 remote_ip: str, remote_port: int, 
                                 status: str, traces: Dict[str, Any]) -> bool:
        """
        Check if a network connection is suspicious.
        
        Args:
            local_ip: Local IP address
            local_port: Local port
            remote_ip: Remote IP address
            remote_port: Remote port
            status: Connection status
            traces: Dictionary containing collected system traces
            
        Returns:
            True if connection is suspicious, False otherwise
        """
        # Check for suspicious characteristics
        suspicious = False
        
        # Check for unusual ports
        suspicious_ports = [4444, 1337, 31337, 8080, 6666, 6667, 6668, 6669]
        if remote_port in suspicious_ports:
            suspicious = True
            
        # Check for unusual connection status
        if status == "LISTEN" and local_port not in [80, 443, 8080, 8443, 22, 21, 25, 110, 143, 3389]:
            suspicious = True
            
        # Check for connections to known malicious IPs
        # This would typically involve checking against a threat intelligence feed
        # For demonstration, we'll use a simple check
        suspicious_ips = ["185.130.44.", "91.121.", "185.159."]
        if any(remote_ip.startswith(ip) for ip in suspicious_ips):
            suspicious = True
            
        return suspicious
    
    def _is_suspicious_file_activity(self, event: Dict[str, Any]) -> bool:
        """
        Check if a file system event is suspicious.
        
        Args:
            event: File system event details
            
        Returns:
            True if event is suspicious, False otherwise
        """
        # Check for suspicious characteristics
        suspicious = False
        
        path = event.get("path", "")
        operation = event.get("operation", "")
        
        # Check for operations on sensitive files
        sensitive_paths = [
            "system32", "drivers", "boot", 
            "windows\\security", "program files", 
            "hosts", "lsass.exe"
        ]
        
        if any(p in path.lower() for p in sensitive_paths) and operation in ["WRITE", "DELETE", "MODIFY"]:
            suspicious = True
            
        # Check for suspicious file extensions
        suspicious_extensions = [".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js"]
        if operation == "CREATE" and any(path.lower().endswith(ext) for ext in suspicious_extensions):
            suspicious = True
            
        # Check for operations in suspicious directories
        suspicious_dirs = ["temp", "tmp", "appdata\\local\\temp", "downloads"]
        if operation == "CREATE" and any(d in path.lower() for d in suspicious_dirs):
            suspicious = True
            
        return suspicious
    
    def _is_suspicious_registry_activity(self, event: Dict[str, Any]) -> bool:
        """
        Check if a registry event is suspicious.
        
        Args:
            event: Registry event details
            
        Returns:
            True if event is suspicious, False otherwise
        """
        # Check for suspicious characteristics
        suspicious = False
        
        key = event.get("key", "")
        operation = event.get("operation", "")
        value = event.get("value", "")
        
        # Check for operations on sensitive registry keys
        sensitive_keys = [
            "run", "runonce", "userinit", "shell", "winlogon",
            "currentversion\\image file execution options",
            "policies\\explorer\\run", "windows\\system\\scripts",
            "currentcontrolset\\services"
        ]
        
        if any(k in key.lower() for k in sensitive_keys) and operation in ["SET", "CREATE"]:
            suspicious = True
            
        # Check for suspicious values
        suspicious_values = [".exe", "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe"]
        if operation in ["SET", "CREATE"] and any(v in str(value).lower() for v in suspicious_values):
            suspicious = True
            
        return suspicious
    
    def add_directory_to_monitor(self, directory: str) -> bool:
        """
        Add a directory to be monitored for file system changes.
        
        Args:
            directory: Path to directory to monitor
            
        Returns:
            True if directory was added successfully, False otherwise
        """
        try:
            if not os.path.isdir(directory):
                logger.error(f"Cannot monitor {directory}: Not a directory")
                return False
                
            if directory not in self.monitored_directories:
                self.monitored_directories.append(directory)
                logger.info(f"Added directory to monitor: {directory}")
                return True
            else:
                logger.info(f"Directory already being monitored: {directory}")
                return True
                
        except Exception as e:
            logger.error(f"Error adding directory to monitor: {str(e)}")
            return False
    
    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get platform-specific information.
        
        Returns:
            Dictionary containing platform information
        """
        info = {
            "platform": self.platform,
            "platform_details": {},
            "monitoring_capabilities": []
        }
        
        # Add platform-specific details
        if self.platform_detector.is_windows():
            import platform as plt
            info["platform_details"] = {
                "version": plt.version(),
                "win32_edition": plt.win32_edition() if hasattr(plt, "win32_edition") else "Unknown",
                "win32_is_iot": plt.win32_is_iot() if hasattr(plt, "win32_is_iot") else False,
                "architecture": plt.architecture()[0]
            }
            info["monitoring_capabilities"] = [
                "process_monitoring",
                "network_monitoring",
                "file_system_monitoring",
                "registry_monitoring",
                "resource_monitoring"
            ]
        elif self.platform_detector.is_mac():
            import platform as plt
            info["platform_details"] = {
                "version": plt.version(),
                "mac_ver": plt.mac_ver()[0],
                "architecture": plt.architecture()[0]
            }
            info["monitoring_capabilities"] = [
                "process_monitoring",
                "network_monitoring",
                "file_system_monitoring",
                "resource_monitoring"
            ]
        
        return info
