"""
Alert Dashboard Module.

This module provides a web-based dashboard for viewing and managing alerts.
"""

import logging
import json
import time
import threading
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from src.utils.config import load_config

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Cyber Attack Tracer - Alert Dashboard")

# Initialize templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)

# Create templates directory if it doesn't exist
if not templates_dir.exists():
    templates_dir.mkdir(parents=True)

# Create dashboard template if it doesn't exist
dashboard_template = templates_dir / "dashboard.html"
if not dashboard_template.exists():
    dashboard_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cyber Attack Tracer - Alert Dashboard</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #333;
                color: white;
                padding: 20px;
                text-align: center;
            }
            .alert-container {
                margin-top: 20px;
            }
            .alert {
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                margin-bottom: 10px;
                padding: 15px;
                transition: all 0.3s ease;
            }
            .alert:hover {
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            }
            .alert-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 10px;
            }
            .alert-severity {
                font-weight: bold;
                padding: 5px 10px;
                border-radius: 3px;
                color: white;
            }
            .alert-severity-INFO {
                background-color: #2196F3;
            }
            .alert-severity-LOW {
                background-color: #4CAF50;
            }
            .alert-severity-MEDIUM {
                background-color: #FF9800;
            }
            .alert-severity-HIGH {
                background-color: #F44336;
            }
            .alert-severity-CRITICAL {
                background-color: #9C27B0;
            }
            .alert-timestamp {
                color: #666;
                font-size: 0.9em;
            }
            .alert-message {
                font-size: 1.1em;
                margin-bottom: 10px;
            }
            .alert-details {
                background-color: #f9f9f9;
                border-radius: 3px;
                padding: 10px;
                font-family: monospace;
                white-space: pre-wrap;
                overflow-x: auto;
            }
            .alert-type {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                background-color: #e0e0e0;
                margin-right: 10px;
            }
            .filters {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            .filter {
                padding: 8px 15px;
                border: none;
                border-radius: 3px;
                background-color: #e0e0e0;
                cursor: pointer;
                transition: background-color 0.3s ease;
            }
            .filter:hover, .filter.active {
                background-color: #333;
                color: white;
            }
            .status-bar {
                background-color: #333;
                color: white;
                padding: 10px;
                position: fixed;
                bottom: 0;
                width: 100%;
                display: flex;
                justify-content: space-between;
                z-index: 1000;
            }
            .status-indicator {
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 5px;
            }
            .status-connected {
                background-color: #4CAF50;
            }
            .status-disconnected {
                background-color: #F44336;
            }
            .no-alerts {
                text-align: center;
                padding: 50px;
                color: #666;
            }
            .tabs {
                display: flex;
                border-bottom: 1px solid #ddd;
                margin-bottom: 20px;
            }
            .tab {
                padding: 10px 20px;
                cursor: pointer;
                border: 1px solid transparent;
                border-bottom: none;
                margin-right: 5px;
                border-radius: 3px 3px 0 0;
                background-color: #f0f0f0;
            }
            .tab.active {
                border-color: #ddd;
                background-color: white;
                margin-bottom: -1px;
            }
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
            .action-buttons {
                margin: 20px 0;
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
            }
            .action-button {
                padding: 10px 15px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                display: flex;
                align-items: center;
            }
            .action-button:hover {
                background-color: #45a049;
            }
            .action-button img {
                margin-right: 8px;
                width: 20px;
                height: 20px;
            }
            .visualization-container {
                margin-top: 20px;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 20px;
                min-height: 400px;
                background-color: white;
            }
            @media (max-width: 768px) {
                .container {
                    padding: 10px;
                }
                .header {
                    padding: 15px;
                }
                .alert {
                    padding: 10px;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Cyber Attack Tracer - Alert Dashboard</h1>
        </div>
        <div class="container">
            <div class="tabs">
                <div class="tab active" data-tab="alerts">Alerts</div>
                <div class="tab" data-tab="knowledge-graph">Knowledge Graph</div>
                <div class="tab" data-tab="reports">Security Reports</div>
                <div class="tab" data-tab="system-monitoring">System Monitoring</div>
            </div>
            
            <div id="alerts" class="tab-content active">
                <h2>Alert Management</h2>
                <div class="filters">
                    <button class="filter active" data-severity="all">All</button>
                    <button class="filter" data-severity="CRITICAL">Critical</button>
                    <button class="filter" data-severity="HIGH">High</button>
                    <button class="filter" data-severity="MEDIUM">Medium</button>
                    <button class="filter" data-severity="LOW">Low</button>
                    <button class="filter" data-severity="INFO">Info</button>
                </div>
                <div class="alert-container" id="alertContainer">
                    <div class="no-alerts" id="noAlerts">
                        <h2>No alerts to display</h2>
                        <p>Waiting for new alerts...</p>
                    </div>
                </div>
            </div>
            
            <div id="knowledge-graph" class="tab-content">
                <h2>Knowledge Graph Visualization</h2>
                <div class="action-buttons">
                    <button id="generate-graph" class="action-button">
                        <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiIHdpZHRoPSIxOHB4IiBoZWlnaHQ9IjE4cHgiPjxwYXRoIGQ9Ik0wIDBoMjR2MjRIMHoiIGZpbGw9Im5vbmUiLz48cGF0aCBkPSJNMTQgM3YyaDMuNTlsLTkuODMgOS44My0xLjQxLTEuNDFMNi4xNyAxM2gtNHYyaDZ6TTUgM2gtMnYySDN2NGgyVjVoNFYzSDV6bTE2IDE0aC02djJoNHYtNGgydjRoMnYtNmgtMnYyeiIvPjwvc3ZnPg==" alt="Generate">
                        Generate Knowledge Graph
                    </button>
                </div>
                <div id="graph-visualization" class="visualization-container">
                    <p>Click the button above to generate a knowledge graph.</p>
                </div>
            </div>
            
            <div id="reports" class="tab-content">
                <h2>Security Reports</h2>
                <div class="action-buttons">
                    <button id="generate-report" class="action-button">
                        <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiIHdpZHRoPSIxOHB4IiBoZWlnaHQ9IjE4cHgiPjxwYXRoIGQ9Ik0wIDBoMjR2MjRIMHoiIGZpbGw9Im5vbmUiLz48cGF0aCBkPSJNMTkgM0g1Yy0xLjEgMC0yIC45LTIgMnYxNGMwIDEuMS45IDIgMiAyaDE0YzEuMSAwIDItLjkgMi0yVjVjMC0xLjEtLjktMi0yLTJ6bTAgMTZINVY1aDE0djE0ek0xNyA4SDdWN2gxMHYxem0wIDNIN3YtMWgxMHYxem0wIDNIN3YtMWgxMHYxeiIvPjwvc3ZnPg==" alt="Report">
                        Generate Security Report
                    </button>
                </div>
                <div id="report-content" class="visualization-container">
                    <p>Click the button above to generate a security report.</p>
                </div>
            </div>
            
            <div id="system-monitoring" class="tab-content">
                <h2>System Monitoring</h2>
                <div id="system-resources">
                    <h3>System Resources</h3>
                    <div id="resource-charts">Loading system resources...</div>
                </div>
            </div>
        </div>
        <div class="status-bar">
            <div>
                <span class="status-indicator" id="statusIndicator"></span>
                <span id="statusText">Disconnected</span>
            </div>
            <div>
                <span id="alertCount">0</span> alerts
            </div>
        </div>

        <script>
            // WebSocket connection
            let socket;
            let reconnectInterval = 1000;
            let maxReconnectInterval = 30000;
            let reconnectTimer;
            let alerts = [];
            let currentFilter = 'all';

            function connectWebSocket() {
                socket = new WebSocket(`ws://${window.location.host}/ws`);
                
                socket.onopen = function(e) {
                    console.log("WebSocket connection established");
                    document.getElementById('statusIndicator').className = 'status-indicator status-connected';
                    document.getElementById('statusText').textContent = 'Connected';
                    reconnectInterval = 1000; // Reset reconnect interval
                };
                
                socket.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    if (data.type === 'alert') {
                        addAlert(data.alert);
                    } else if (data.type === 'alerts') {
                        alerts = data.alerts;
                        renderAlerts();
                    } else if (data.type === 'system_resources') {
                        updateSystemResources(data.resources);
                    }
                };
                
                socket.onclose = function(event) {
                    document.getElementById('statusIndicator').className = 'status-indicator status-disconnected';
                    document.getElementById('statusText').textContent = 'Disconnected';
                    console.log("WebSocket connection closed. Reconnecting...");
                    
                    // Exponential backoff for reconnection
                    reconnectTimer = setTimeout(function() {
                        reconnectInterval = Math.min(reconnectInterval * 1.5, maxReconnectInterval);
                        connectWebSocket();
                    }, reconnectInterval);
                };
                
                socket.onerror = function(error) {
                    console.error("WebSocket error:", error);
                };
            }

            function addAlert(alert) {
                // Add alert to the beginning of the array
                alerts.unshift(alert);
                
                // Limit the number of alerts to display
                if (alerts.length > 100) {
                    alerts.pop();
                }
                
                renderAlerts();
            }

            function renderAlerts() {
                const container = document.getElementById('alertContainer');
                const noAlerts = document.getElementById('noAlerts');
                const alertCount = document.getElementById('alertCount');
                
                // Filter alerts based on current filter
                const filteredAlerts = currentFilter === 'all' 
                    ? alerts 
                    : alerts.filter(alert => alert.severity === currentFilter);
                
                // Update alert count
                alertCount.textContent = alerts.length;
                
                // Show/hide no alerts message
                if (filteredAlerts.length === 0) {
                    noAlerts.style.display = 'block';
                    container.innerHTML = '';
                    container.appendChild(noAlerts);
                    return;
                } else {
                    noAlerts.style.display = 'none';
                }
                
                // Clear container
                container.innerHTML = '';
                
                // Add alerts to container
                filteredAlerts.forEach(alert => {
                    const alertElement = document.createElement('div');
                    alertElement.className = 'alert';
                    
                    const timestamp = new Date(alert.timestamp).toLocaleString();
                    
                    alertElement.innerHTML = `
                        <div class="alert-header">
                            <div>
                                <span class="alert-severity alert-severity-${alert.severity}">${alert.severity}</span>
                                <span class="alert-type">${alert.type}</span>
                            </div>
                            <span class="alert-timestamp">${timestamp}</span>
                        </div>
                        <div class="alert-message">${alert.message}</div>
                        <div class="alert-details">${JSON.stringify(alert.details, null, 2)}</div>
                    `;
                    
                    container.appendChild(alertElement);
                });
            }
            
            // Update system resources
            function updateSystemResources(resources) {
                const resourceCharts = document.getElementById('resource-charts');
                resourceCharts.innerHTML = `
                    <div>CPU Usage: ${resources.cpu_percent}%</div>
                    <div>Memory Usage: ${resources.memory_percent}%</div>
                    <div>Disk I/O: Read ${resources.disk_io.read_bytes} bytes, Write ${resources.disk_io.write_bytes} bytes</div>
                `;
            }

            // Initialize filters
            document.querySelectorAll('.filter').forEach(filter => {
                filter.addEventListener('click', function() {
                    // Remove active class from all filters
                    document.querySelectorAll('.filter').forEach(f => f.classList.remove('active'));
                    
                    // Add active class to clicked filter
                    this.classList.add('active');
                    
                    // Update current filter
                    currentFilter = this.dataset.severity;
                    
                    // Render alerts with new filter
                    renderAlerts();
                });
            });
            
            // Tab functionality
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    // Update active tab
                    document.querySelectorAll('.tab').forEach(t => {
                        t.classList.remove('active');
                    });
                    tab.classList.add('active');
                    
                    // Update active content
                    const tabId = tab.dataset.tab;
                    document.querySelectorAll('.tab-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    document.getElementById(tabId).classList.add('active');
                });
            });
            
            // Handle generate knowledge graph button
            document.getElementById('generate-graph').addEventListener('click', () => {
                const graphVisualization = document.getElementById('graph-visualization');
                graphVisualization.innerHTML = '<p>Generating knowledge graph...</p>';
                
                fetch('/api/generate-knowledge-graph')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            graphVisualization.innerHTML = `
                                <iframe src="${data.graph_url}" width="100%" height="600" frameborder="0"></iframe>
                            `;
                        } else {
                            graphVisualization.innerHTML = `<p>Error generating knowledge graph: ${data.error}</p>`;
                        }
                    })
                    .catch(error => {
                        graphVisualization.innerHTML = `<p>Error: ${error.message}</p>`;
                    });
            });
            
            // Handle generate report button
            document.getElementById('generate-report').addEventListener('click', () => {
                const reportContent = document.getElementById('report-content');
                reportContent.innerHTML = '<p>Generating security report...</p>';
                
                fetch('/api/generate-report')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            reportContent.innerHTML = `
                                <iframe src="${data.report_url}" width="100%" height="600" frameborder="0"></iframe>
                                <a href="${data.report_url}" download="security_report.html" 
                                   style="display: block; margin-top: 10px; text-align: center;">
                                   Download Report
                                </a>
                            `;
                        } else {
                            reportContent.innerHTML = `<p>Error generating report: ${data.error}</p>`;
                        }
                    })
                    .catch(error => {
                        reportContent.innerHTML = `<p>Error: ${error.message}</p>`;
                    });
            });

            // Connect to WebSocket
            connectWebSocket();

            // Clean up on page unload
            window.addEventListener('beforeunload', function() {
                if (socket) {
                    socket.close();
                }
                if (reconnectTimer) {
                    clearTimeout(reconnectTimer);
                }
            });
        </script>
    </body>
    </html>
    """
    with open(dashboard_template, "w") as f:
        f.write(dashboard_html)

templates = Jinja2Templates(directory=str(templates_dir))

# Initialize static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# WebSocket connections
active_connections: List[WebSocket] = []

class AlertDashboard:
    """
    Provides a web-based dashboard for viewing and managing alerts.
    
    This class is responsible for:
    1. Providing a web interface for viewing alerts
    2. Sending real-time updates to connected clients
    3. Filtering and searching alerts
    4. Managing alert lifecycle (acknowledge, resolve, etc.)
    """
    
    def __init__(self, host=None, port=None):
        """Initialize the AlertDashboard."""
        self.config = load_config().get("alert_dashboard", {})
        self.enabled = self.config.get("enabled", True)
        self.host = host or self.config.get("host", "127.0.0.1")
        self.port = port or self.config.get("port", 8080)
        self.server = None
        self.server_thread = None
        self.running = False
        self.report_generator = None
        self.knowledge_graph_builder = None
        self.ui_integrator = None
        self.dashboard_title = "Cyber Attack Tracer - Alert Dashboard"
    
    def start(self):
        """Start the dashboard server."""
        if not self.enabled:
            logger.info("Alert dashboard is disabled")
            return
        
        if self.server_thread is not None and self.server_thread.is_alive():
            logger.warning("Alert dashboard server is already running")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        logger.info(f"Alert dashboard started at http://{self.host}:{self.port}")
    
    def stop(self):
        """Stop the dashboard server."""
        self.running = False
        if self.server:
            self.server.should_exit = True
        if self.server_thread:
            self.server_thread.join(timeout=5.0)
        logger.info("Alert dashboard stopped")
    
    def _run_server(self):
        """Run the dashboard server."""
        try:
            uvicorn.run(app, host=self.host, port=self.port)
        except Exception as e:
            logger.error(f"Error running alert dashboard server: {str(e)}")
    
    def register_report_generator(self, report_generator):
        """Register a report generator for use with the dashboard."""
        self.report_generator = report_generator
        logger.info("Report generator registered with dashboard")
        
    def register_knowledge_graph_builder(self, graph_builder, ui_integrator=None):
        """Register a knowledge graph builder for use with the dashboard."""
        self.knowledge_graph_builder = graph_builder
        self.ui_integrator = ui_integrator
        logger.info("Knowledge graph builder registered with dashboard")
        
    def _convert_alerts_to_traces(self):
        """Convert alerts to traces for knowledge graph generation."""
        traces = []
        return traces
        
    def _convert_alerts_to_analysis_data(self):
        """Convert alerts to analysis data for report generation."""
        analysis_data = {
            "processes": [],
            "network_connections": [],
            "techniques": [],
            "malware_samples": []
        }
        return analysis_data
    
    def send_alert(self, alert: Dict[str, Any]):
        """
        Send an alert to all connected clients.
        
        Args:
            alert: Alert dictionary
        """
        if not self.enabled or not self.running:
            return
        
        # Send alert to all connected clients
        for connection in active_connections:
            try:
                connection.send_json({
                    "type": "alert",
                    "alert": alert
                })
            except Exception as e:
                logger.error(f"Error sending alert to client: {str(e)}")

# Initialize dashboard
dashboard = AlertDashboard()

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Get the dashboard HTML."""
    return templates.TemplateResponse("dashboard.html", {"request": {}})

@app.get("/api/generate-knowledge-graph")
async def generate_knowledge_graph():
    """Generate a knowledge graph visualization."""
    if not dashboard.knowledge_graph_builder:
        return JSONResponse(content={
            "success": False,
            "error": "Knowledge graph builder not registered with dashboard"
        })
        
    try:
        traces = dashboard._convert_alerts_to_traces()
        
        graph = dashboard.knowledge_graph_builder.build_graph_from_traces(traces)
        
        if dashboard.ui_integrator:
            timestamp = int(datetime.now().timestamp())
            result = dashboard.ui_integrator.create_dashboard(
                graph=graph,
                filename=f"knowledge_graph_{timestamp}.html",
                title="Cyber Attack Knowledge Graph"
            )
            
            if "main_graph" in result:
                graph_path = result.get("main_graph", "")
                graph_filename = os.path.basename(graph_path)
                graph_url = f"/visualizations/{graph_filename}"
                
                vis_dir = Path(static_dir) / "visualizations"
                vis_dir.mkdir(exist_ok=True)
                
                target_path = Path(vis_dir) / graph_filename
                if not target_path.exists():
                    os.symlink(graph_path, target_path)
                
                return JSONResponse(content={
                    "success": True,
                    "graph_url": graph_url
                })
            else:
                return JSONResponse(content={
                    "success": False,
                    "error": "Failed to create visualization"
                })
        else:
            return JSONResponse(content={
                "success": True,
                "nodes": len(graph.nodes()),
                "edges": len(graph.edges()),
                "message": "Graph generated, but UI integrator not available for visualization"
            })
    except Exception as e:
        logger.error(f"Error generating knowledge graph: {str(e)}")
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        })

@app.get("/api/generate-report")
async def generate_report():
    """Generate a security report."""
    if not dashboard.report_generator:
        return JSONResponse(content={
            "success": False,
            "error": "Report generator not registered with dashboard"
        })
        
    try:
        analysis_data = dashboard._convert_alerts_to_analysis_data()
        
        report_html = dashboard.report_generator.generate_report(analysis_data, report_type="html")
        
        timestamp = int(datetime.now().timestamp())
        reports_dir = Path(static_dir) / "reports"
        reports_dir.mkdir(exist_ok=True)
        
        report_filename = f"security_report_{timestamp}.html"
        report_path = reports_dir / report_filename
        
        with open(report_path, "w") as f:
            f.write(report_html)
        
        report_url = f"/static/reports/{report_filename}"
        
        return JSONResponse(content={
            "success": True,
            "report_url": report_url
        })
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        })

@app.get("/visualizations/{filename}")
async def get_visualization(filename: str):
    """Serve visualization files."""
    vis_dir = Path(static_dir) / "visualizations"
    file_path = vis_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Visualization not found")
    return FileResponse(file_path)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@app.on_event("startup")
async def startup_event():
    """Startup event handler."""
    logger.info("Alert dashboard API started")

@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler."""
    logger.info("Alert dashboard API stopped")
