"""
Alert Dashboard Module.

This module provides a web-based dashboard for viewing and managing alerts.
"""

import logging
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
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
    
    def __init__(self):
        """Initialize the AlertDashboard."""
        self.config = load_config().get("alert_dashboard", {})
        self.enabled = self.config.get("enabled", False)
        self.host = self.config.get("host", "127.0.0.1")
        self.port = self.config.get("port", 8080)
        self.server = None
        self.server_thread = None
        self.running = False
    
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
