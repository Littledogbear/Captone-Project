"""
Enhanced Real-time Monitor Module.

This module provides an enhanced implementation of the real-time monitoring system
with platform-specific capabilities for Windows and Mac environments.
"""

import logging
import time
import threading
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set, Tuple

from src.utils.platform_detector import PlatformDetector
from src.alerting.platform_monitor import PlatformMonitor
from src.alerting.alert_manager import AlertManager
from src.alerting.alert_types import Alert, AlertType, AlertSeverity
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.technique_identifier import TechniqueIdentifier
from src.analysis_engine.analyzer import TraceAnalyzer
from src.utils.config import load_config

logger = logging.getLogger(__name__)

class EnhancedRealTimeMonitor:
    """
    Enhanced real-time monitoring system with platform-specific capabilities.
    
    This class extends the basic real-time monitoring functionality with:
    1. Platform-specific monitoring for Windows and Mac
    2. Enhanced detection capabilities
    3. Improved alert management
    4. Resource-efficient monitoring
    5. Configurable monitoring parameters
    """
    
    def __init__(self):
        """Initialize the EnhancedRealTimeMonitor."""
        self.config = load_config().get("real_time_monitor", {})
        self.platform_detector = PlatformDetector()
        self.platform = self.platform_detector.get_platform()
        
        # Initialize components
        self.platform_monitor = PlatformMonitor()
        self.trace_analyzer = TraceAnalyzer()
        self.alert_manager = AlertManager()
        self.knowledge_graph_builder = KnowledgeGraphBuilder()
        self.technique_identifier = TechniqueIdentifier()
        
        # Initialize monitoring state
        self.monitoring_thread = None
        self.running = False
        self.monitoring_interval = self.config.get("monitoring_interval", 30)  # seconds
        self.trace_history = []
        self.max_history = self.config.get("max_history", 100)
        self.baseline_established = False
        
        # Initialize alert manager
        self.alert_manager.start()
        
        # Initialize monitoring parameters
        self.cpu_threshold = self.config.get("cpu_threshold", 90)
        self.memory_threshold = self.config.get("memory_threshold", 90)
        self.disk_threshold = self.config.get("disk_threshold", 90)
        self.network_threshold = self.config.get("network_threshold", 90)
        
        # Initialize monitored directories
        self.monitored_directories = self.config.get("monitored_directories", [])
        for directory in self.monitored_directories:
            self.platform_monitor.add_directory_to_monitor(directory)
            
        # Initialize adaptive monitoring
        self.adaptive_monitoring = self.config.get("adaptive_monitoring", True)
        self.min_interval = self.config.get("min_interval", 5)
        self.max_interval = self.config.get("max_interval", 60)
        self.threat_level = 0  # 0-10 scale, higher means more threats detected
        
        logger.info(f"Enhanced real-time monitor initialized for {self.platform} platform")
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        if self.monitoring_thread is not None and self.monitoring_thread.is_alive():
            logger.warning("Monitoring thread is already running")
            return
        
        # Establish baseline if not already done
        if not self.baseline_established:
            logger.info("Establishing baseline before starting monitoring")
            self.baseline_established = self.platform_monitor.establish_baseline()
        
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        logger.info(f"Enhanced real-time monitoring started on {self.platform} platform")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.running = False
        if self.monitoring_thread is not None:
            self.monitoring_thread.join(timeout=5.0)
        self.alert_manager.stop()
        logger.info("Enhanced real-time monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        consecutive_errors = 0
        
        while self.running:
            try:
                # Adjust monitoring interval based on threat level if adaptive monitoring is enabled
                if self.adaptive_monitoring:
                    self._adjust_monitoring_interval()
                
                # Collect and analyze platform-specific traces
                traces = self.platform_monitor.collect_and_analyze()
                
                # Skip processing if error occurred during collection
                if "error" in traces:
                    logger.error(f"Error during trace collection: {traces['error']}")
                    consecutive_errors += 1
                    
                    # If too many consecutive errors, increase monitoring interval
                    if consecutive_errors > 3:
                        self.monitoring_interval = min(self.monitoring_interval * 2, self.max_interval)
                        logger.warning(f"Increasing monitoring interval to {self.monitoring_interval} due to consecutive errors")
                    
                    time.sleep(self.monitoring_interval)
                    continue
                
                # Reset consecutive errors counter
                consecutive_errors = 0
                
                # Add timestamp if not already present
                if "timestamp" not in traces:
                    traces["timestamp"] = datetime.now().isoformat()
                
                # Add to history
                self.trace_history.append(traces)
                
                # Trim history if needed
                if len(self.trace_history) > self.max_history:
                    self.trace_history = self.trace_history[-self.max_history:]
                
                # Perform additional analysis
                self._analyze_traces(traces)
                
                # Generate alerts based on platform-specific analysis
                self._generate_alerts(traces)
                
                # Update threat level based on detected issues
                self._update_threat_level(traces)
                
                # Sleep until next interval
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                consecutive_errors += 1
                time.sleep(max(5, self.monitoring_interval // 2))  # Sleep a bit before retrying
    
    def _analyze_traces(self, traces: Dict[str, Any]):
        """
        Perform additional analysis on collected traces.
        
        Args:
            traces: Dictionary containing collected system traces
        """
        try:
            # Analyze with trace analyzer
            analysis = self.trace_analyzer.analyze_traces(traces)
            
            # Add analysis to traces
            traces["analysis"] = analysis
            
            # Build knowledge graph
            graph = self.knowledge_graph_builder.build_graph_from_traces(traces)
            
            # Identify techniques
            techniques = self.technique_identifier.identify_techniques(graph)
            
            # Add techniques to traces
            traces["techniques"] = techniques
            
            # Add graph to traces for visualization
            traces["graph"] = {
                "nodes": len(graph.nodes()),
                "edges": len(graph.edges())
            }
            
        except Exception as e:
            logger.error(f"Error analyzing traces: {str(e)}")
            traces["analysis_error"] = str(e)
    
    def _generate_alerts(self, traces: Dict[str, Any]):
        """
        Generate alerts based on platform-specific analysis.
        
        Args:
            traces: Dictionary containing collected system traces and analysis
        """
        try:
            # Process platform-specific analysis
            platform_analysis = traces.get("platform_analysis", {})
            
            # Generate alerts for suspicious processes
            for process in platform_analysis.get("suspicious_processes", []):
                alert = Alert(
                    alert_type=AlertType.SUSPICIOUS_PROCESS,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Suspicious Process: {process.get('name')}",
                    description=f"Suspicious process detected: {process.get('name')} (PID: {process.get('pid')}). "
                               f"Reason: {process.get('reason')}",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=process
                )
                self.alert_manager.add_alert(alert)
            
            # Generate alerts for suspicious network connections
            for connection in platform_analysis.get("suspicious_connections", []):
                local_addr = connection.get("local_address", {})
                remote_addr = connection.get("remote_address", {})
                alert = Alert(
                    alert_type=AlertType.SUSPICIOUS_NETWORK,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Suspicious Network Connection",
                    description=f"Suspicious network connection detected: "
                               f"{local_addr.get('ip')}:{local_addr.get('port')} -> "
                               f"{remote_addr.get('ip')}:{remote_addr.get('port')}. "
                               f"Reason: {connection.get('reason')}",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=connection
                )
                self.alert_manager.add_alert(alert)
            
            # Generate alerts for suspicious file activities
            for file_activity in platform_analysis.get("suspicious_file_activities", []):
                alert = Alert(
                    alert_type=AlertType.SUSPICIOUS_FILE,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Suspicious File Activity: {file_activity.get('operation')}",
                    description=f"Suspicious file activity detected: {file_activity.get('operation')} on "
                               f"{file_activity.get('path')}. "
                               f"Reason: {file_activity.get('reason')}",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=file_activity
                )
                self.alert_manager.add_alert(alert)
            
            # Generate alerts for suspicious registry activities (Windows-specific)
            for registry_activity in platform_analysis.get("suspicious_registry_activities", []):
                alert = Alert(
                    alert_type=AlertType.SUSPICIOUS_REGISTRY,
                    severity=AlertSeverity.MEDIUM,
                    title=f"Suspicious Registry Activity: {registry_activity.get('operation')}",
                    description=f"Suspicious registry activity detected: {registry_activity.get('operation')} on "
                               f"{registry_activity.get('key')}. "
                               f"Reason: {registry_activity.get('reason')}",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=registry_activity
                )
                self.alert_manager.add_alert(alert)
            
            # Generate alerts for resource anomalies
            for anomaly in platform_analysis.get("resource_anomalies", []):
                alert = Alert(
                    alert_type=AlertType.RESOURCE_ANOMALY,
                    severity=AlertSeverity.LOW,
                    title=f"Resource Anomaly: {anomaly.get('resource')}",
                    description=f"Resource anomaly detected: {anomaly.get('resource')} usage at "
                               f"{anomaly.get('value')}% (threshold: {anomaly.get('threshold')}%). "
                               f"Reason: {anomaly.get('reason')}",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=anomaly
                )
                self.alert_manager.add_alert(alert)
            
            # Generate alerts for attack techniques
            for technique in traces.get("techniques", []):
                alert = Alert(
                    alert_type=AlertType.ATTACK_TECHNIQUE,
                    severity=AlertSeverity.HIGH,
                    title=f"Attack Technique Detected: {technique.get('name')}",
                    description=f"Attack technique detected: {technique.get('technique_id')} - {technique.get('name')}. "
                               f"This technique is associated with {technique.get('tactic')}.",
                    timestamp=traces.get("timestamp"),
                    source="enhanced_real_time_monitor",
                    data=technique
                )
                self.alert_manager.add_alert(alert)
            
        except Exception as e:
            logger.error(f"Error generating alerts: {str(e)}")
    
    def _update_threat_level(self, traces: Dict[str, Any]):
        """
        Update the current threat level based on detected issues.
        
        Args:
            traces: Dictionary containing collected system traces and analysis
        """
        try:
            # Get platform-specific analysis
            platform_analysis = traces.get("platform_analysis", {})
            
            # Count suspicious activities
            suspicious_count = (
                len(platform_analysis.get("suspicious_processes", [])) +
                len(platform_analysis.get("suspicious_connections", [])) +
                len(platform_analysis.get("suspicious_file_activities", [])) +
                len(platform_analysis.get("suspicious_registry_activities", []))
            )
            
            # Count attack techniques
            technique_count = len(traces.get("techniques", []))
            
            # Calculate new threat level (0-10 scale)
            new_threat_level = min(10, suspicious_count + technique_count * 2)
            
            # Smooth the transition to avoid rapid changes
            self.threat_level = (self.threat_level * 0.7) + (new_threat_level * 0.3)
            
            logger.debug(f"Updated threat level: {self.threat_level:.2f}")
            
        except Exception as e:
            logger.error(f"Error updating threat level: {str(e)}")
    
    def _adjust_monitoring_interval(self):
        """Adjust monitoring interval based on current threat level."""
        try:
            if not self.adaptive_monitoring:
                return
                
            # Calculate new interval based on threat level
            # Higher threat level = lower interval (more frequent monitoring)
            threat_factor = max(0.1, 1.0 - (self.threat_level / 10.0))
            new_interval = self.min_interval + (self.max_interval - self.min_interval) * threat_factor
            
            # Round to nearest second
            new_interval = round(new_interval)
            
            # Only update if significant change
            if abs(new_interval - self.monitoring_interval) >= 5:
                logger.info(f"Adjusting monitoring interval from {self.monitoring_interval}s to {new_interval}s "
                           f"(threat level: {self.threat_level:.2f})")
                self.monitoring_interval = new_interval
                
        except Exception as e:
            logger.error(f"Error adjusting monitoring interval: {str(e)}")
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """
        Get the current monitoring status.
        
        Returns:
            Dictionary with monitoring status information
        """
        return {
            "running": self.running,
            "platform": self.platform,
            "monitoring_interval": self.monitoring_interval,
            "trace_history_count": len(self.trace_history),
            "last_trace_time": self.trace_history[-1]["timestamp"] if self.trace_history else None,
            "alert_count": len(self.alert_manager.alert_history),
            "threat_level": round(self.threat_level, 2),
            "adaptive_monitoring": self.adaptive_monitoring,
            "baseline_established": self.baseline_established
        }
    
    def get_recent_traces(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent traces.
        
        Args:
            limit: Maximum number of traces to return
            
        Returns:
            List of recent traces
        """
        return sorted(
            self.trace_history[-limit:],
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
    
    def get_recent_alerts(self, limit: int = 10, 
                         severity: Optional[str] = None,
                         alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recent alerts.
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity level
            alert_type: Filter by alert type
            
        Returns:
            List of recent alerts
        """
        return self.alert_manager.get_alerts(limit, severity, alert_type)
    
    def set_monitoring_interval(self, interval: int):
        """
        Set the monitoring interval.
        
        Args:
            interval: Monitoring interval in seconds
        """
        if interval < self.min_interval:
            logger.warning(f"Monitoring interval too small: {interval}. "
                          f"Setting to minimum: {self.min_interval} seconds.")
            interval = self.min_interval
        
        if interval > self.max_interval:
            logger.warning(f"Monitoring interval too large: {interval}. "
                          f"Setting to maximum: {self.max_interval} seconds.")
            interval = self.max_interval
        
        self.monitoring_interval = interval
        logger.info(f"Monitoring interval set to {interval} seconds")
    
    def set_adaptive_monitoring(self, enabled: bool):
        """
        Enable or disable adaptive monitoring.
        
        Args:
            enabled: Whether adaptive monitoring should be enabled
        """
        self.adaptive_monitoring = enabled
        logger.info(f"Adaptive monitoring {'enabled' if enabled else 'disabled'}")
    
    def add_directory_to_monitor(self, directory: str) -> bool:
        """
        Add a directory to be monitored for file system changes.
        
        Args:
            directory: Path to directory to monitor
            
        Returns:
            True if directory was added successfully, False otherwise
        """
        return self.platform_monitor.add_directory_to_monitor(directory)
    
    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get platform-specific information.
        
        Returns:
            Dictionary containing platform information
        """
        return self.platform_monitor.get_platform_info()
