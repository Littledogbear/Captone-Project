# Cyber Attack Tracer - Dashboard Startup Process

This document explains the code-level interconnection between components during the dashboard startup process.

## Overview

The dashboard startup process in `run_monitoring_dashboard.py` initializes and connects multiple components:

1. FastAPI application
2. WebSocket connections
3. Database tables
4. Uvicorn server
5. AI models and MITRE mappings
6. System monitoring

## Code-Level Interconnection

### 1. FastAPI Application Initialization

```python
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Cyber Attack Tracer API")

# Mount static files
app.mount("/static", StaticFiles(directory="src/alerting/static"), name="static")

# Initialize templates
templates = Jinja2Templates(directory="src/alerting/templates")
```

The FastAPI application serves as the central hub connecting all components. It:
- Provides HTTP endpoints for the dashboard UI
- Handles WebSocket connections for real-time updates
- Serves static files (CSS, JavaScript)
- Renders HTML templates

### 2. Component Initialization

```python
from src.alerting.monitoring_dashboard import MonitoringDashboard
from src.trace_collector.ai_trace_analyzer import AITraceAnalyzer
from src.knowledge_graph.enhanced_graph_builder import EnhancedGraphBuilder
from src.reporting.report_generator import ReportGenerator

# Initialize components
dashboard = MonitoringDashboard()
ai_analyzer = AITraceAnalyzer()
graph_builder = EnhancedGraphBuilder()
report_generator = ReportGenerator()
```

Each component is initialized with its dependencies:
- `MonitoringDashboard`: Manages the UI and real-time monitoring
- `AITraceAnalyzer`: Analyzes system traces using AI models
- `EnhancedGraphBuilder`: Builds knowledge graphs from analysis data
- `ReportGenerator`: Creates HTML reports from analysis results

### 3. Database Setup

```python
from src.utils.database import Database

# Initialize database
db = Database("sqlite:///cyber_attack_tracer.db")

# Create tables
@app.on_event("startup")
async def create_tables():
    await db.create_tables()
```

The database is initialized and tables are created during the FastAPI startup event. This ensures data persistence for:
- Alert history
- System metrics
- Analysis results
- Knowledge graphs

### 4. WebSocket Connection Setup

```python
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    dashboard.register_client(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            await dashboard.handle_message(websocket, data)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        dashboard.remove_client(websocket)
```

WebSocket connections enable real-time communication between:
- Dashboard UI (browser)
- Monitoring system (server)
- Alert manager
- System metrics collector

### 5. AI Model and MITRE Mapping Loading

```python
from src.analysis_engine.ai_analysis_integrator import AIAnalysisIntegrator

# Initialize AI components
@app.on_event("startup")
async def load_ai_models():
    # Load zero-shot classifier
    ai_analyzer.load_models()
    
    # Load MITRE ATT&CK mappings
    with open("src/knowledge_graph/attack_kg_mapping.json", "r") as f:
        attack_mappings = json.load(f)
    
    ai_integrator = AIAnalysisIntegrator()
    ai_integrator.initialize(attack_mappings)
```

AI models and MITRE mappings are loaded during startup:
- Zero-shot classifier for behavior analysis
- MITRE ATT&CK technique mappings for attack classification
- AI analysis integrator for connecting analysis results to the knowledge graph

### 6. System Monitoring Activation

```python
from src.utils.system_monitor import SystemMonitor

# Start monitoring
@app.on_event("startup")
async def start_monitoring():
    system_monitor = SystemMonitor()
    
    # Start background task for monitoring
    asyncio.create_task(dashboard.run_monitoring_loop(
        system_monitor, 
        ai_analyzer, 
        graph_builder, 
        report_generator
    ))
```

The monitoring loop connects all components:
1. `SystemMonitor` collects system metrics
2. `AITraceAnalyzer` analyzes the collected data
3. `EnhancedGraphBuilder` creates knowledge graphs from analysis
4. `ReportGenerator` generates reports from the analysis
5. `MonitoringDashboard` updates the UI with all results

### 7. Uvicorn Server Startup

```python
import uvicorn

# Run the application
if __name__ == "__main__":
    uvicorn.run(
        app, 
        host=os.getenv("DASHBOARD_HOST", "127.0.0.1"),
        port=int(os.getenv("DASHBOARD_PORT", "8081"))
    )
```

The Uvicorn server:
- Handles HTTP requests to the FastAPI application
- Manages WebSocket connections
- Serves the dashboard UI
- Processes API requests

## Data Flow Between Components

1. **System Monitoring → AI Analysis**:
   ```python
   async def run_monitoring_loop(self, system_monitor, ai_analyzer, graph_builder, report_generator):
       while True:
           # Collect system metrics
           metrics = system_monitor.get_metrics()
           
           # Analyze for suspicious activity
           analysis_results = ai_analyzer.analyze(metrics)
   ```

2. **AI Analysis → Knowledge Graph**:
   ```python
   # Generate knowledge graph from analysis
   if analysis_results.suspicious_activity_detected:
       graph = graph_builder.build_graph(analysis_results.data)
       graph_file = graph_builder.export_graph(graph)
   ```

3. **Analysis Results → Report Generation**:
   ```python
   # Generate report from analysis
   if analysis_results.suspicious_activity_detected:
       report = report_generator.generate_report(analysis_results.data)
   ```

4. **All Components → Dashboard UI**:
   ```python
   # Update connected clients with new data
   await self.broadcast_updates({
       "metrics": metrics,
       "alerts": analysis_results.alerts,
       "graph": graph_file if 'graph_file' in locals() else None,
       "report": report if 'report' in locals() else None
   })
   ```

## Configuration Integration

The dashboard reads configuration from `config/monitoring_dashboard_config.yaml`:

```python
def load_config():
    with open("config/monitoring_dashboard_config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

# Apply configuration
monitoring_interval = config["monitoring"]["interval"]
max_alerts = config["alerts"]["max_alerts"]
ui_theme = config["ui"]["theme"]
```

This configuration controls:
- Monitoring intervals
- Alert retention
- UI theme
- Knowledge graph generation settings
- Report generation settings

## Conclusion

The dashboard startup process creates a fully integrated system where:
1. The FastAPI application serves as the central hub
2. Components are initialized with their dependencies
3. The database ensures data persistence
4. WebSockets enable real-time communication
5. AI models analyze system behavior
6. The monitoring loop connects all components
7. The Uvicorn server handles HTTP and WebSocket connections

This architecture allows the system to automatically start all required components with a single command, providing a seamless user experience.
