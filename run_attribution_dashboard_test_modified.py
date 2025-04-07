"""
Test script to demonstrate attribution engine functionality with specific malware samples
and display results in the dashboard UI.
"""

import os
import sys
import json
import logging
import webbrowser
from datetime import datetime
from pathlib import Path
import threading
import time
import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

try:
    from attribution.attribution_engine import AttributionEngine
    from knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
    from knowledge_graph.graph_visualizer import GraphVisualizer
    from reporting.report_generator import ReportGenerator
    from alerting.alert_manager import AlertManager
    from utils.system_monitor import SystemMonitor
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attribution_dashboard_test")

app = FastAPI(title="Cyber Attack Tracer - Real-time Monitoring Dashboard")

templates_dir = os.path.join(os.path.dirname(__file__), "src", "alerting", "templates")
templates = Jinja2Templates(directory=templates_dir)

static_dir = os.path.join(os.path.dirname(__file__), "src", "alerting", "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

output_dir = Path("output/attribution_dashboard_test")
output_dir.mkdir(parents=True, exist_ok=True)

active_connections = []
system_monitor = SystemMonitor()
alert_manager = AlertManager()
attribution_results = {}
knowledge_graphs = {}
reports = {}

def create_sample_data():
    """Create sample data with attribution indicators."""
    return {
        "TrojanSample": {
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "name": "TrojanSample.exe",
            "type": "trojan",
            "tags": ["trojan", "stealer", "backdoor"],
            "description": "This trojan establishes persistence through registry modifications and communicates with command and control servers.",
            "network": [
                {
                    "ip": "45.77.65.211",
                    "country": "Russia",
                    "country_code": "RU",
                    "city": "Moscow"
                }
            ],
            "tools": [
                {
                    "name": "X-Agent",
                    "confidence": 0.92
                },
                {
                    "name": "X-Tunnel",
                    "confidence": 0.85
                }
            ],
            "techniques": [
                "T1055",  # Process Injection
                "T1059.003",  # Windows Command Shell
                "T1071.001",  # Web Protocols
                "T1547.001"  # Registry Run Keys / Startup Folder
            ]
        },
        "RansomwareSample": {
            "sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
            "name": "RansomwareSample.exe",
            "type": "ransomware",
            "tags": ["ransomware", "encryptor"],
            "description": "This ransomware encrypts user files and demands payment for decryption.",
            "network": [
                {
                    "ip": "175.45.176.3",
                    "country": "North Korea",
                    "country_code": "KP",
                    "city": "Pyongyang"
                }
            ],
            "tools": [
                {
                    "name": "HOPLIGHT",
                    "confidence": 0.88
                }
            ],
            "techniques": [
                "T1486",  # Data Encrypted for Impact
                "T1490",  # Inhibit System Recovery
                "T1083",  # File and Directory Discovery
                "T1222.001"  # File and Directory Permissions Modification
            ]
        }
    }

def create_actor_profiles():
    """Create actor profiles for attribution matching."""
    return {
        "APT28": {
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
            "attribution": {
                "country": "RU",
                "type": "state-sponsored"
            },
            "tools": ["X-Agent", "X-Tunnel", "Mimikatz"],
            "techniques": ["T1055", "T1059.003", "T1071.001", "T1547.001"],
            "description": "Russian state-sponsored threat actor known for targeting government and military organizations."
        },
        "Lazarus": {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "Guardians of Peace"],
            "attribution": {
                "country": "KP",
                "type": "state-sponsored"
            },
            "tools": ["HOPLIGHT", "BLINDINGCAN", "ELECTRICFISH"],
            "techniques": ["T1486", "T1490", "T1083", "T1222.001"],
            "description": "North Korean state-sponsored threat actor known for financially motivated attacks."
        }
    }

def run_attribution_analysis():
    """Run attribution analysis and generate outputs."""
    global attribution_results, knowledge_graphs, reports
    
    sample_data = create_sample_data()
    actor_profiles = create_actor_profiles()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for sample_name, sample in sample_data.items():
        attribution_engine = AttributionEngine()
        attribution_engine.actor_profiles = actor_profiles
        
        attribution_result = attribution_engine.attribute_attack({
            "malware_info": {
                "sha256": sample["sha256"],
                "name": sample["name"],
                "type": sample["type"],
                "tags": sample["tags"]
            },
            "network": sample["network"],
            "tools": sample["tools"],
            "techniques": sample["techniques"]
        })
        
        attribution_file = output_dir / f"attribution_{sample_name}_{timestamp}.json"
        with open(attribution_file, "w") as f:
            json.dump(attribution_result, f, indent=2)
        
        graph_builder = KnowledgeGraphBuilder()
        graph = graph_builder.build_graph_from_traces({
            "malware": sample,
            "attribution": attribution_result
        })
        
        graph_viz = GraphVisualizer()
        graph_file = output_dir / f"knowledge_graph_{sample_name}_{timestamp}.html"
        graph_viz.visualize_graph_html(graph, str(graph_file))
        
        report_gen = ReportGenerator()
        report_file = output_dir / f"report_{sample_name}_{timestamp}.html"
        
        report_data = {
            "malware_info": {
                "name": sample["name"],
                "sha256": sample["sha256"],
                "type": sample["type"],
                "description": sample["description"]
            },
            "attribution": attribution_result,
            "graph_path": str(graph_file)
        }
        
        report_gen.generate_report(report_data, str(report_file))
        
        attribution_results[sample_name] = attribution_result
        knowledge_graphs[sample_name] = str(graph_file)
        reports[sample_name] = str(report_file)
        
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": "malware",
            "severity": "CRITICAL",
            "message": f"Malware Detected: {sample['name']} - {sample['type']} with attribution to {attribution_result.get('potential_actors', [{}])[0].get('name', 'Unknown') if attribution_result.get('potential_actors') else 'Unknown'}",
            "details": {
                "malware": sample,
                "attribution": attribution_result
            }
        }
        alert_manager.alert_queue.put(alert)
        
        if not alert_manager.running:
            alert_manager.start()
    
    return {
        "attribution_results": attribution_results,
        "knowledge_graphs": knowledge_graphs,
        "reports": reports
    }

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """Render the dashboard template."""
    return templates.TemplateResponse(
        "real_time_dashboard.html",
        {
            "request": request,
            "title": "Cyber Attack Tracer - Real-time Monitoring Dashboard"
        }
    )

@app.get("/api/system-metrics")
async def get_system_metrics():
    """Get current system metrics."""
    return system_monitor.get_metrics()

@app.get("/api/alerts")
async def get_alerts():
    """Get all alerts."""
    return alert_manager.get_alerts()

@app.get("/api/attribution")
async def get_attribution():
    """Get attribution results."""
    return attribution_results

@app.get("/api/malware")
async def get_malware():
    """Get detected malware."""
    sample_data = create_sample_data()
    return {name: {
        "name": data["name"],
        "type": data["type"],
        "sha256": data["sha256"],
        "description": data["description"],
        "tags": data["tags"]
    } for name, data in sample_data.items()}

@app.get("/report/{sample_name}")
async def get_report(sample_name: str):
    """Get report for a specific malware sample."""
    if sample_name in reports:
        return FileResponse(reports[sample_name])
    return {"error": "Report not found"}

@app.get("/graph/{sample_name}")
async def get_graph(sample_name: str):
    """Get knowledge graph for a specific malware sample."""
    if sample_name in knowledge_graphs:
        return FileResponse(knowledge_graphs[sample_name])
    return {"error": "Graph not found"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_json({
                "type": "system_metrics",
                "data": system_monitor.get_metrics()
            })
            await websocket.send_json({
                "type": "alerts",
                "data": alert_manager.get_alerts()
            })
    except WebSocketDisconnect:
        active_connections.remove(websocket)

def broadcast_updates():
    """Broadcast updates to all connected clients."""
    while True:
        for connection in active_connections:
            try:
                pass
            except:
                pass
        time.sleep(5)

def run_dashboard():
    """Run the dashboard server."""
    uvicorn.run(app, host="0.0.0.0", port=8082)

def main():
    """Run attribution analysis and start dashboard."""
    results = run_attribution_analysis()
    
    dashboard_thread = threading.Thread(target=run_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()
    
    broadcast_thread = threading.Thread(target=broadcast_updates)
    broadcast_thread.daemon = True
    broadcast_thread.start()
    
    time.sleep(2)
    
    print("\n" + "="*80)
    print("ATTRIBUTION DASHBOARD TEST RESULTS")
    print("="*80)
    
    for sample_name, result in attribution_results.items():
        print(f"\n{sample_name}:")
        if "potential_actors" in result and result["potential_actors"]:
            for actor in result["potential_actors"]:
                print(f"  - {actor.get('name', 'Unknown')} (Match Score: {actor.get('match_score', 0):.2f})")
                print(f"    Aliases: {', '.join(actor.get('aliases', []))}")
                print(f"    Matches: {', '.join(actor.get('matches', []))}")
                print(f"    Description: {actor.get('description', '')}")
        else:
            print("  No potential actors identified")
        
        print(f"\nOutput Files:")
        print(f"  - Knowledge Graph: {knowledge_graphs.get(sample_name, 'Not available')}")
        print(f"  - Report: {reports.get(sample_name, 'Not available')}")
    
    print("\nDashboard URL: http://127.0.0.1:8081")
    
    webbrowser.open("http://127.0.0.1:8081")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")

if __name__ == "__main__":
    main()
