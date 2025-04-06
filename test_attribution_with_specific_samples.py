"""
Test script to demonstrate attribution engine functionality with specific malware samples.
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
import webbrowser
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

try:
    from attribution.attribution_engine import AttributionEngine
    from knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
    from knowledge_graph.graph_visualizer import GraphVisualizer
    from reporting.report_generator import ReportGenerator
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attribution_test")

app = FastAPI(title="Cyber Attack Tracer - Attribution Analysis Dashboard")

templates_dir = os.path.join(os.path.dirname(__file__), "src", "alerting", "templates")
templates = Jinja2Templates(directory=templates_dir)

static_dir = os.path.join(os.path.dirname(__file__), "src", "alerting", "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

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
    output_dir = Path("output/attribution_test")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    sample_data = create_sample_data()
    actor_profiles = create_actor_profiles()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    results = {}
    
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
        
        results[sample_name] = {
            "attribution": attribution_result,
            "graph_file": str(graph_file),
            "report_file": str(report_file)
        }
    
    return results

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """Render the dashboard template."""
    return templates.TemplateResponse(
        "real_time_dashboard.html",
        {
            "request": request,
            "title": "Cyber Attack Tracer - Attribution Analysis Dashboard"
        }
    )

def run_dashboard():
    """Run the dashboard server."""
    uvicorn.run(app, host="127.0.0.1", port=8081)

def main():
    """Run attribution analysis and start dashboard."""
    results = run_attribution_analysis()
    
    dashboard_thread = threading.Thread(target=run_dashboard)
    dashboard_thread.daemon = True
    dashboard_thread.start()
    
    time.sleep(2)
    
    print("\n" + "="*80)
    print("ATTRIBUTION TEST RESULTS")
    print("="*80)
    
    for sample_name, result in results.items():
        print(f"\n{sample_name}:")
        if "potential_actors" in result["attribution"] and result["attribution"]["potential_actors"]:
            for actor in result["attribution"]["potential_actors"]:
                print(f"  - {actor.get('name', 'Unknown')} (Match Score: {actor.get('match_score', 0):.2f})")
                print(f"    Matches: {', '.join(actor.get('matches', []))}")
        else:
            print("  No potential actors identified")
        
        print(f"\nOutput Files:")
        print(f"  - Knowledge Graph: {result['graph_file']}")
        print(f"  - Report: {result['report_file']}")
    
    print("\nDashboard URL: http://127.0.0.1:8081")
    
    webbrowser.open("http://127.0.0.1:8081")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")

if __name__ == "__main__":
    main()
