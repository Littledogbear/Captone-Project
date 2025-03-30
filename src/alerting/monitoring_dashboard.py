"""
Real-time Monitoring Dashboard Module.

This module provides a web-based dashboard for real-time system monitoring,
including CPU usage, memory usage, and suspicious activity detection.
"""

import logging
import json
import time
import threading
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.utils.system_monitor import SystemMonitor
from src.alerting.enhanced_real_time_monitor import EnhancedRealTimeMonitor
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.graph_visualizer import GraphVisualizer
from src.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class MonitoringDashboard:
    """Provides a web-based dashboard for real-time system monitoring."""
    
    def __init__(self):
        """Initialize the MonitoringDashboard."""
        self.host = "127.0.0.1"
        self.port = 8081
        self.server = None
        self.server_thread = None
        self.running = False
        
        self.system_monitor = SystemMonitor()
        self.real_time_monitor = EnhancedRealTimeMonitor()
        self.knowledge_graph_builder = KnowledgeGraphBuilder()
        self.graph_visualizer = GraphVisualizer()
        self.report_generator = ReportGenerator()
        
        self.app = FastAPI(title="Cyber Attack Tracer - Monitoring Dashboard")
        
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        
        self.static_dir = Path(__file__).parent / "static"
        self.static_dir.mkdir(exist_ok=True)
        
        self._create_dashboard_template()
        
        self.active_connections: List[WebSocket] = []
        self._setup_routes()
    
    def start(self):
        """Start the dashboard server."""
        if self.server_thread is not None and self.server_thread.is_alive():
            logger.warning("Monitoring dashboard server is already running")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        logger.info(f"Monitoring dashboard started at http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop the dashboard server."""
        self.running = False
        if self.server:
            self.server.should_exit = True
        if self.server_thread:
            self.server_thread.join(timeout=5.0)
        logger.info("Monitoring dashboard stopped")
    
    def _run_server(self):
        """Run the dashboard server."""
        try:
            uvicorn.run(self.app, host=self.host, port=self.port)
        except Exception as e:
            logger.error(f"Error running monitoring dashboard server: {str(e)}")
    
    def _setup_routes(self):
        """Setup dashboard routes."""
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
        
        templates = Jinja2Templates(directory=str(self.templates_dir))
        
        @self.app.get("/", response_class=HTMLResponse)
        async def get_dashboard(request: Request):
            """Get the dashboard HTML."""
            return templates.TemplateResponse("monitoring_dashboard.html", {"request": request})
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            await websocket.accept()
            self.active_connections.append(websocket)
            try:
                while True:
                    await websocket.receive_text()
            except WebSocketDisconnect:
                self.active_connections.remove(websocket)
        
        @self.app.get("/monitoring/status")
        async def get_monitoring_status():
            """Get real-time monitoring status."""
            status = self.real_time_monitor.get_monitoring_status()
            system_status = self.system_monitor.get_system_status()
            
            combined_status = {
                **status,
                **system_status,
                "monitoring_status": "Running" if status.get("running", False) else "Stopped"
            }
            
            return combined_status
        
        @self.app.post("/monitoring/start")
        async def start_monitoring():
            """Start real-time monitoring."""
            self.real_time_monitor.start_monitoring()
            return {"status": "monitoring_started"}
        
        @self.app.post("/monitoring/stop")
        async def stop_monitoring():
            """Stop real-time monitoring."""
            self.real_time_monitor.stop_monitoring()
            return {"status": "monitoring_stopped"}
        
        @self.app.get("/alerts")
        async def get_alerts(limit: int = 100):
            """Get recent alerts."""
            alerts = self.real_time_monitor.get_recent_alerts(limit)
            return alerts
        
        @self.app.post("/knowledge/generate")
        async def generate_knowledge_graph():
            """Generate a knowledge graph from recent traces."""
            try:
                traces = self.real_time_monitor.get_recent_traces(limit=20)
                
                if not traces:
                    return {"error": "No traces available"}
                
                graph = self.knowledge_graph_builder.build_graph_from_traces(traces[-1])
                
                output_dir = Path("output/dashboard_graphs")
                output_dir.mkdir(parents=True, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_dir / f"knowledge_graph_{timestamp}.png"
                
                self.graph_visualizer.visualize_graph(graph, str(output_path))
                
                static_graph_path = self.static_dir / f"knowledge_graph_{timestamp}.png"
                os.system(f"cp {output_path} {static_graph_path}")
                
                graph_url = f"/static/knowledge_graph_{timestamp}.png"
                self._broadcast_message({
                    "type": "knowledge_graph",
                    "graph_url": graph_url
                })
                
                return {
                    "graph_url": graph_url,
                    "nodes": len(graph.nodes()),
                    "edges": len(graph.edges())
                }
            except Exception as e:
                logger.error(f"Error generating knowledge graph: {str(e)}")
                return {"error": str(e)}
        
        @self.app.post("/reports/generate")
        async def generate_report():
            """Generate a report from recent traces."""
            try:
                traces = self.real_time_monitor.get_recent_traces(limit=20)
                
                if not traces:
                    return {"error": "No traces available"}
                
                analysis_data = {
                    "timestamp": datetime.now().isoformat(),
                    "system_activity": traces[-1],
                    "analysis_result": {
                        "severity": "medium",
                        "confidence": 0.8,
                        "malware_type": "Unknown"
                    }
                }
                
                report_content = self.report_generator.generate_report(analysis_data, "html")
                
                output_dir = Path("output/dashboard_reports")
                output_dir.mkdir(parents=True, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_dir / f"report_{timestamp}.html"
                
                with open(output_path, "w") as f:
                    f.write(report_content)
                
                static_report_path = self.static_dir / f"report_{timestamp}.html"
                os.system(f"cp {output_path} {static_report_path}")
                
                report_url = f"/static/report_{timestamp}.html"
                self._broadcast_message({
                    "type": "report",
                    "report": {
                        "report_url": report_url,
                        "timestamp": datetime.now().isoformat()
                    }
                })
                
                return {
                    "report_url": report_url,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                logger.error(f"Error generating report: {str(e)}")
                return {"error": str(e)}
    
    async def _broadcast_message(self, message: Dict[str, Any]):
        """Broadcast a message to all connected WebSocket clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {str(e)}")
    
    def _create_dashboard_template(self):
        """Create the dashboard HTML template."""
        dashboard_template = self.templates_dir / "monitoring_dashboard.html"
        if dashboard_template.exists():
            return
