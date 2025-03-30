"""
Dashboard Integrator Module.

This module provides integration between the monitoring dashboard and the main application.
"""

import logging
import threading
import os
from pathlib import Path
from typing import Dict, Any, Optional

from src.alerting.monitoring_dashboard import MonitoringDashboard
from src.utils.config import load_config

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
