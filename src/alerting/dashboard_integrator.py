"""
Dashboard Integrator Module.

This module provides integration between the monitoring dashboard and the main application.
"""

import logging
import threading
import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

import networkx as nx

from src.alerting.monitoring_dashboard import MonitoringDashboard
from src.utils.config import load_config
from src.knowledge_graph.enhanced_graph_builder import EnhancedGraphBuilder

logger = logging.getLogger(__name__)

class DashboardIntegrator:
    """Integrates the monitoring dashboard with the main application."""
    
    def __init__(self):
        """Initialize the DashboardIntegrator."""
        self.config = load_config().get("monitoring_dashboard", {})
        self.dashboard = None
        self.dashboard_thread = None
        self.running = False
        
        os.makedirs("logs", exist_ok=True)
        os.makedirs("output/dashboard_graphs", exist_ok=True)
        os.makedirs("output/dashboard_reports", exist_ok=True)
        
        static_dir = Path(__file__).parent / "static"
        static_dir.mkdir(exist_ok=True)
        
        logger.info("Dashboard integrator initialized")
    
    def start_dashboard(self, host: str = "127.0.0.1", port: int = 8081):
        """
        Start the monitoring dashboard.
        
        Args:
            host: Host to bind the dashboard server to
            port: Port to bind the dashboard server to
        """
        if self.dashboard_thread is not None and self.dashboard_thread.is_alive():
            logger.warning("Dashboard is already running")
            return
        
        try:
            self.dashboard = MonitoringDashboard()
            self.dashboard.host = host
            self.dashboard.port = port
            
            self.running = True
            self.dashboard_thread = threading.Thread(target=self._run_dashboard)
            self.dashboard_thread.daemon = True
            self.dashboard_thread.start()
            
            logger.info(f"Dashboard started at http://{host}:{port}")
            
            return {
                "status": "running",
                "url": f"http://{host}:{port}"
            }
        except Exception as e:
            logger.error(f"Error starting dashboard: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def stop_dashboard(self):
        """Stop the monitoring dashboard."""
        if not self.running or self.dashboard is None:
            logger.warning("Dashboard is not running")
            return {
                "status": "not_running"
            }
        
        try:
            self.running = False
            self.dashboard.stop()
            
            if self.dashboard_thread:
                self.dashboard_thread.join(timeout=5.0)
            
            logger.info("Dashboard stopped")
            
            return {
                "status": "stopped"
            }
        except Exception as e:
            logger.error(f"Error stopping dashboard: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _run_dashboard(self):
        """Run the dashboard."""
        try:
            self.dashboard.start()
        except Exception as e:
            logger.error(f"Error running dashboard: {str(e)}")
            self.running = False
    
    def get_dashboard_status(self) -> Dict[str, Any]:
        """
        Get the current dashboard status.
        
        Returns:
            Dictionary with dashboard status information
        """
        if not self.dashboard:
            return {
                "status": "not_initialized"
            }
        
        try:
            return {
                "status": "running" if self.running else "stopped",
                "url": f"http://{self.dashboard.host}:{self.dashboard.port}" if self.running else None
            }
        except Exception as e:
            logger.error(f"Error getting dashboard status: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def add_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Add an alert to the dashboard.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if successful, False otherwise
        """
        if not self.running or self.dashboard is None:
            logger.warning("Dashboard is not running")
            return False
        
        try:
            self.dashboard.add_alert(alert)
            return True
        except Exception as e:
            logger.error(f"Error adding alert to dashboard: {str(e)}")
            return False
    
    def add_knowledge_graph(self, graph: Union[nx.DiGraph, Dict[str, Any], str]) -> bool:
        """
        Add a knowledge graph to the dashboard.
        
        Args:
            graph: NetworkX DiGraph, dictionary representation of a graph, or path to a graph file
            
        Returns:
            True if successful, False otherwise
        """
        if not self.running or self.dashboard is None:
            logger.warning("Dashboard is not running")
            return False
        
        try:
            if isinstance(graph, str) and os.path.exists(graph):
                with open(graph, 'r') as f:
                    graph_data = json.load(f)
                
                static_dir = Path(__file__).parent / "static"
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                static_graph_path = static_dir / f"knowledge_graph_{timestamp}.json"
                
                shutil.copy(graph, static_graph_path)
                
                graph_builder = EnhancedGraphBuilder()
                graph_obj = graph_builder.build_graph(graph_data)
                
                self.dashboard.add_knowledge_graph(graph_obj, f"/static/knowledge_graph_{timestamp}.json")
                return True
            
            elif isinstance(graph, dict):
                graph_builder = EnhancedGraphBuilder()
                graph_obj = graph_builder.build_graph(graph)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = Path("output/dashboard_graphs")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"knowledge_graph_{timestamp}.json"
                
                with open(output_path, 'w') as f:
                    json.dump(graph, f, indent=2)
                
                static_dir = Path(__file__).parent / "static"
                static_graph_path = static_dir / f"knowledge_graph_{timestamp}.json"
                
                shutil.copy(output_path, static_graph_path)
                
                self.dashboard.add_knowledge_graph(graph_obj, f"/static/knowledge_graph_{timestamp}.json")
                return True
            
            elif isinstance(graph, nx.DiGraph):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = Path("output/dashboard_graphs")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"knowledge_graph_{timestamp}.json"
                
                graph_dict = nx.node_link_data(graph)
                
                with open(output_path, 'w') as f:
                    json.dump(graph_dict, f, indent=2)
                
                static_dir = Path(__file__).parent / "static"
                static_graph_path = static_dir / f"knowledge_graph_{timestamp}.json"
                
                shutil.copy(output_path, static_graph_path)
                
                self.dashboard.add_knowledge_graph(graph, f"/static/knowledge_graph_{timestamp}.json")
                return True
            
            else:
                logger.error(f"Unsupported graph type: {type(graph)}")
                return False
        except Exception as e:
            logger.error(f"Error adding knowledge graph to dashboard: {str(e)}")
            return False
    
    def add_report(self, report: Union[str, Dict[str, Any]]) -> bool:
        """
        Add a report to the dashboard.
        
        Args:
            report: Path to a report file or report content dictionary
            
        Returns:
            True if successful, False otherwise
        """
        if not self.running or self.dashboard is None:
            logger.warning("Dashboard is not running")
            return False
        
        try:
            if isinstance(report, str) and os.path.exists(report):
                static_dir = Path(__file__).parent / "static"
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                static_report_path = static_dir / f"report_{timestamp}.html"
                
                shutil.copy(report, static_report_path)
                
                self.dashboard.add_report(f"/static/report_{timestamp}.html")
                return True
            
            elif isinstance(report, dict):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = Path("output/dashboard_reports")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"report_{timestamp}.html"
                
                from src.reporting.report_generator import ReportGenerator
                report_generator = ReportGenerator()
                report_html = report_generator.generate_report(report, "html")
                
                with open(output_path, 'w') as f:
                    f.write(report_html)
                
                static_dir = Path(__file__).parent / "static"
                static_report_path = static_dir / f"report_{timestamp}.html"
                
                shutil.copy(output_path, static_report_path)
                
                self.dashboard.add_report(f"/static/report_{timestamp}.html")
                return True
            
            else:
                logger.error(f"Unsupported report type: {type(report)}")
                return False
        except Exception as e:
            logger.error(f"Error adding report to dashboard: {str(e)}")
            return False
