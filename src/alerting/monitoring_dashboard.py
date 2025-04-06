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
        self.host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
        self.port = int(os.environ.get("DASHBOARD_PORT", "8083"))
        self.server = None
        self.server_thread = None
        self.background_thread = None
        self.running = False
        
        self.system_monitor = SystemMonitor()
        self.real_time_monitor = EnhancedRealTimeMonitor()
        self.knowledge_graph_builder = KnowledgeGraphBuilder()
        self.graph_visualizer = GraphVisualizer()
        self.report_generator = ReportGenerator()
        
        self.app = FastAPI(title="Cyber Attack Tracer - Real-time Monitoring Dashboard")
        
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
        
        self.background_thread = threading.Thread(target=self.start_background_tasks)
        self.background_thread.daemon = True
        self.background_thread.start()
        
        logger.info(f"Monitoring dashboard started at http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop the dashboard server."""
        self.running = False
        if self.server:
            self.server.should_exit = True
        if self.server_thread:
            self.server_thread.join(timeout=5.0)
        if hasattr(self, 'background_thread') and self.background_thread:
            self.background_thread.join(timeout=5.0)
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
                status = self.real_time_monitor.get_monitoring_status()
                system_status = self.system_monitor.get_system_status()
                
                combined_status = {
                    **status,
                    **system_status,
                    "type": "system_status",
                    "monitoring_status": "Running" if status.get("running", False) else "Stopped"
                }
                
                await websocket.send_json(combined_status)
                
                alerts = self.real_time_monitor.get_recent_alerts(10)
                if alerts:
                    for alert in alerts:
                        await websocket.send_json({
                            "type": "alert",
                            "alert": alert if isinstance(alert, dict) else alert.to_dict()
                        })
            except Exception as e:
                logger.error(f"Error sending initial data: {str(e)}")
            
            try:
                while True:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                self.active_connections.remove(websocket)
            except Exception as e:
                logger.error(f"WebSocket error: {str(e)}")
                if websocket in self.active_connections:
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
                        "confidence": 80,
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
    
    def add_alert(self, alert: Dict[str, Any]):
        """
        Add an alert to the dashboard.
        
        Args:
            alert: Alert dictionary
        """
        try:
            if isinstance(alert, dict) and "type" not in alert and "alert_type" in alert:
                alert["type"] = "alert"
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self._broadcast_message({
                    "type": "alert",
                    "alert": alert
                }))
            finally:
                loop.close()
                
            logger.info(f"Alert added to dashboard: {alert.get('title', '')}")
        except Exception as e:
            logger.error(f"Error adding alert to dashboard: {str(e)}")
    
    def add_knowledge_graph(self, graph, graph_url: str = None):
        """
        Add a knowledge graph to the dashboard.
        
        Args:
            graph: NetworkX DiGraph object
            graph_url: URL to the graph visualization
        """
        try:
            if graph_url is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                graph_url = f"/static/knowledge_graph_{timestamp}.png"
            
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self._broadcast_message({
                    "type": "knowledge_graph",
                    "graph_url": graph_url,
                    "nodes": len(graph.nodes()),
                    "edges": len(graph.edges()),
                    "timestamp": datetime.now().isoformat()
                }))
            finally:
                loop.close()
                
            logger.info(f"Knowledge graph added to dashboard: {graph_url}")
        except Exception as e:
            logger.error(f"Error adding knowledge graph to dashboard: {str(e)}")
    
    def add_report(self, report_url: str):
        """
        Add a report to the dashboard.
        
        Args:
            report_url: URL to the report
        """
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                loop.run_until_complete(self._broadcast_message({
                    "type": "report",
                    "report": {
                        "report_url": report_url,
                        "timestamp": datetime.now().isoformat()
                    }
                }))
            finally:
                loop.close()
                
            logger.info(f"Report added to dashboard: {report_url}")
        except Exception as e:
            logger.error(f"Error adding report to dashboard: {str(e)}")
    
    def _create_dashboard_template(self):
        """Create the dashboard HTML template."""
        dashboard_template = self.templates_dir / "monitoring_dashboard.html"
        if dashboard_template.exists():
            return
            
    def start_background_tasks(self):
        """Start background tasks for sending updates to WebSocket clients."""
        import asyncio
        
        async def send_system_status():
            """Send system status updates to WebSocket clients."""
            while self.running:
                try:
                    status = self.real_time_monitor.get_monitoring_status()
                    system_status = self.system_monitor.get_system_status()
                    
                    combined_status = {
                        **status,
                        **system_status,
                        "type": "system_status",
                        "monitoring_status": "Running" if status.get("running", False) else "Stopped"
                    }
                    
                    await self._broadcast_message(combined_status)
                except Exception as e:
                    logger.error(f"Error sending system status: {str(e)}")
                
                await asyncio.sleep(2)  # Send updates every 2 seconds
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.create_task(send_system_status())
            loop.run_forever()
        except Exception as e:
            logger.error(f"Error starting background tasks: {str(e)}")
        finally:
            loop.close()
