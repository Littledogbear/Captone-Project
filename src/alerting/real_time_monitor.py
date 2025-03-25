"""
Real-time Monitor Module.

This module provides functionality for continuous monitoring of system activities
and real-time detection of suspicious behaviors.
"""

import logging
import time
import threading
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

from src.trace_collector.collector import TraceCollector
from src.analysis_engine.analyzer import TraceAnalyzer
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.technique_identifier import TechniqueIdentifier
from src.alerting.alert_manager import AlertManager
from src.utils.config import load_config

logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """
    Provides real-time monitoring of system activities and detection of suspicious behaviors.
    
    This class is responsible for:
    1. Continuously collecting system traces
    2. Analyzing traces in real-time
    3. Detecting suspicious activities
    4. Generating alerts for detected threats
    5. Building knowledge graphs of attack patterns
    """
    
    def __init__(self):
        """Initialize the RealTimeMonitor."""
        self.config = load_config().get("real_time_monitor", {})
        self.trace_collector = TraceCollector()
        self.trace_analyzer = TraceAnalyzer()
        self.alert_manager = AlertManager()
        self.knowledge_graph_builder = KnowledgeGraphBuilder()
        self.technique_identifier = TechniqueIdentifier()
        
        self.monitoring_thread = None
        self.running = False
        self.monitoring_interval = self.config.get("monitoring_interval", 30)  # seconds
        self.trace_history = []
        self.max_history = self.config.get("max_history", 100)
        
        # Initialize alert manager
        self.alert_manager.start()
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        if self.monitoring_thread is not None and self.monitoring_thread.is_alive():
            logger.warning("Monitoring thread is already running")
            return
        
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.running = False
        if self.monitoring_thread is not None:
            self.monitoring_thread.join(timeout=5.0)
        self.alert_manager.stop()
        logger.info("Real-time monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Collect traces
                traces = self.trace_collector.collect_system_traces()
                
                # Add timestamp
                traces["timestamp"] = datetime.now().isoformat()
                
                # Add to history
                self.trace_history.append(traces)
                
                # Trim history if needed
                if len(self.trace_history) > self.max_history:
                    self.trace_history = self.trace_history[-self.max_history:]
                
                # Analyze traces
                analysis = self.trace_analyzer.analyze_traces(traces)
                
                # Add analysis to traces
                traces["analysis"] = analysis
                
                # Build knowledge graph
                graph = self.knowledge_graph_builder.build_graph_from_traces(traces)
                
                # Identify techniques
                techniques = self.technique_identifier.identify_techniques(graph)
                
                # Add techniques to traces
                traces["techniques"] = techniques
                
                # Generate alerts
                self.alert_manager.evaluate_traces(traces)
                
                # Sleep until next interval
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5)  # Sleep a bit before retrying
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """
        Get the current monitoring status.
        
        Returns:
            Dictionary with monitoring status information
        """
        return {
            "running": self.running,
            "monitoring_interval": self.monitoring_interval,
            "trace_history_count": len(self.trace_history),
            "last_trace_time": self.trace_history[-1]["timestamp"] if self.trace_history else None,
            "alert_count": len(self.alert_manager.alert_history)
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
        if interval < 5:
            logger.warning(f"Monitoring interval too small: {interval}. Setting to 5 seconds.")
            interval = 5
        
        self.monitoring_interval = interval
        logger.info(f"Monitoring interval set to {interval} seconds")
