"""
Run Dashboard with Enhanced Relationships Script.

This script runs the monitoring dashboard with enhanced knowledge graph visualization
showing host-malware relationships and attack progression.
"""

import os
import sys
import logging
import webbrowser
import json
import time
import threading
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

sys.path.insert(0, str(Path(__file__).parent))

from src.knowledge_graph.enhanced_malware_graph_builder import EnhancedMalwareGraphBuilder
from src.reporting.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DashboardHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler for the dashboard."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent), **kwargs)
    
    def log_message(self, format, *args):
        """Override to reduce log verbosity."""
        return

def start_http_server(host="127.0.0.1", port=8109):
    """Start HTTP server to serve the dashboard."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, DashboardHandler)
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    return httpd, f"http://{host}:{port}/"

def generate_sample_data():
    """Generate sample data with host system relationships."""
    return {
        "summary": {
            "threat_level": "Critical",
            "confidence": 85,
            "total_techniques": 4,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_processes": 5,
            "total_network_connections": 3
        },
        "malware_analysis": [
            {
                "file": "TrojanSample.exe",
                "classification": "trojan",
                "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "tags": ["trojan", "stealer", "backdoor"],
                "description": "This trojan establishes persistence through registry modifications and communicates with command and control servers."
            },
            {
                "file": "RansomwareSample.exe",
                "classification": "ransomware",
                "sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
                "tags": ["ransomware", "encryptor"],
                "description": "This ransomware encrypts user files and demands payment for decryption."
            },
            {
                "file": "BotnetSample.exe",
                "classification": "botnet",
                "sha256": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                "tags": ["botnet", "ddos"],
                "description": "This botnet client connects to command and control servers and participates in distributed denial of service attacks."
            }
        ],
        "attack_techniques": [
            {
                "id": "T1547",
                "name": "Boot or Logon Autostart Execution",
                "confidence": 90,
                "description": "The malware establishes persistence through registry modifications."
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "confidence": 85,
                "description": "The malware uses HTTP/HTTPS for command and control communications."
            },
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "confidence": 80,
                "description": "The ransomware encrypts user files for impact."
            },
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "confidence": 75,
                "description": "The botnet participates in DDoS attacks."
            }
        ],
        "system_activity": {
            "processes": [
                {
                    "pid": 1234,
                    "name": "TrojanSample.exe",
                    "path": "C:\\Users\\Admin\\Downloads\\TrojanSample.exe",
                    "command_line": "TrojanSample.exe -silent",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:15:30",
                    "severity": "High"
                },
                {
                    "pid": 1235,
                    "name": "RansomwareSample.exe",
                    "path": "C:\\Users\\Admin\\Downloads\\RansomwareSample.exe",
                    "command_line": "RansomwareSample.exe",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:16:45",
                    "severity": "Critical"
                },
                {
                    "pid": 1236,
                    "name": "BotnetSample.exe",
                    "path": "C:\\Users\\Admin\\Downloads\\BotnetSample.exe",
                    "command_line": "BotnetSample.exe -hidden",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:17:20",
                    "severity": "Medium"
                },
                {
                    "pid": 1237,
                    "name": "powershell.exe",
                    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -ExecutionPolicy Bypass -Command ...",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:18:05",
                    "severity": "High"
                },
                {
                    "pid": 1238,
                    "name": "cmd.exe",
                    "path": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "cmd.exe /c ...",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:19:10",
                    "severity": "Medium"
                }
            ],
            "network": [
                {
                    "process_name": "TrojanSample.exe",
                    "local_addr": "192.168.1.100",
                    "local_port": 49152,
                    "remote_addr": "203.0.113.100",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "severity": "High"
                },
                {
                    "process_name": "BotnetSample.exe",
                    "local_addr": "192.168.1.100",
                    "local_port": 49153,
                    "remote_addr": "198.51.100.200",
                    "remote_port": 8080,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "severity": "Medium"
                },
                {
                    "process_name": "powershell.exe",
                    "local_addr": "192.168.1.100",
                    "local_port": 49154,
                    "remote_addr": "192.0.2.50",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "severity": "High"
                }
            ],
            "registry": [
                {
                    "process_name": "TrojanSample.exe",
                    "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value": "TrojanSample",
                    "action": "write",
                    "severity": "High"
                },
                {
                    "process_name": "RansomwareSample.exe",
                    "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                    "value": "Shell",
                    "action": "modify",
                    "severity": "Critical"
                }
            ],
            "files": [
                {
                    "process_name": "TrojanSample.exe",
                    "path": "C:\\ProgramData\\malware.dll",
                    "action": "create",
                    "severity": "High"
                },
                {
                    "process_name": "RansomwareSample.exe",
                    "path": "C:\\Users\\Admin\\Documents\\important.docx",
                    "action": "encrypt",
                    "severity": "Critical"
                },
                {
                    "process_name": "powershell.exe",
                    "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "action": "modify",
                    "severity": "Medium"
                }
            ]
        }
    }

def generate_enhanced_graph(sample_data, output_dir=None):
    """Generate an enhanced knowledge graph visualization."""
    if output_dir is None:
        output_dir = Path("output/dashboard_enhanced_graph")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    graph_builder = EnhancedMalwareGraphBuilder()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    graph_file = str(output_dir / f"dashboard_enhanced_graph_{timestamp}.json")
    
    graph = graph_builder.build_graph(sample_data)
    graph_path = graph_builder.export_graph(graph_file)
    
    if graph_path:
        logger.info(f"Enhanced knowledge graph generated at {graph_path}")
        
        html_file = str(output_dir / f"dashboard_enhanced_viz_{timestamp}.html")
        
        try:
            template_path = Path(__file__).parent / "src" / "knowledge_graph" / "templates" / "enhanced_graph_template.html"
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            with open(graph_path, 'r') as f:
                graph_data = json.load(f)
            
            html_content = template_content.replace(
                'NODES_DATA', json.dumps(graph_data['nodes'])
            ).replace(
                'EDGES_DATA', json.dumps(graph_data['edges'])
            )
            
            with open(html_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"HTML visualization created at {html_file}")
            return graph_path, html_file
        except Exception as e:
            logger.error(f"Error creating HTML visualization: {str(e)}")
            return graph_path, None
    else:
        logger.error("Failed to generate knowledge graph")
        return None, None

def generate_report(sample_data, output_dir=None):
    """Generate a report from the sample data."""
    if output_dir is None:
        output_dir = Path("output/dashboard_enhanced_graph")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    template_dir = Path(__file__).parent / "src" / "reporting" / "templates"
    report_generator = ReportGenerator(template_dir=str(template_dir))
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = str(output_dir / f"dashboard_enhanced_report_{timestamp}.html")
    
    report_path = report_generator.generate_report(sample_data, report_file, "html")
    
    if report_path:
        logger.info(f"Report generated at {report_path}")
        return report_path
    else:
        logger.error("Failed to generate report")
        return None

def main():
    """Main entry point."""
    try:
        os.makedirs("output/dashboard_enhanced_graph", exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
        logger.info("Starting dashboard with enhanced relationships...")
        
        port = 8109
        httpd = None
        dashboard_url = None
        
        while port < 8120:
            try:
                httpd, dashboard_url = start_http_server(port=port)
                logger.info(f"Server started on port {port}")
                break
            except OSError:
                logger.info(f"Port {port} is in use, trying next port")
                port += 1
        
        if not httpd:
            logger.error("Could not find an available port")
            return
        
        sample_data = generate_sample_data()
        
        graph_path, html_path = generate_enhanced_graph(sample_data)
        
        report_path = generate_report(sample_data)
        
        time.sleep(1)  # Give server time to start
        
        if html_path:
            graph_url = f"file://{os.path.abspath(html_path)}"
            webbrowser.open(graph_url)
            print(f"\nEnhanced knowledge graph visualization available at: {graph_url}")
        
        if report_path:
            report_url = f"file://{os.path.abspath(report_path)}"
            webbrowser.open(report_url)
            print(f"\nReport available at: {report_url}")
        
        dashboard_dir = Path("output/dashboard_enhanced_graph")
        dashboard_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dashboard_file = str(dashboard_dir / f"integrated_dashboard_{timestamp}.html")
        
        dashboard_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Attack Tracer - Real-time Monitoring Dashboard</title>
            <meta charset="utf-8">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                }
                .header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 15px;
                    text-align: center;
                }
                .tabs {
                    display: flex;
                    background-color: #34495e;
                }
                .tab {
                    padding: 15px 20px;
                    color: white;
                    cursor: pointer;
                }
                .tab.active {
                    background-color: #2980b9;
                }
                .content {
                    padding: 20px;
                }
                .tab-content {
                    display: none;
                }
                .tab-content.active {
                    display: block;
                }
                iframe {
                    width: 100%;
                    height: 800px;
                    border: 1px solid #ddd;
                }
                .button {
                    background-color: #2980b9;
                    color: white;
                    padding: 10px 15px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    margin-right: 10px;
                    margin-bottom: 10px;
                }
                .button:hover {
                    background-color: #3498db;
                }
                .download-btn {
                    background-color: #27ae60;
                }
                .download-btn:hover {
                    background-color: #2ecc71;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cyber Attack Tracer - Real-time Monitoring Dashboard</h1>
            </div>
            
            <div class="tabs">
                <div class="tab active" onclick="openTab('system')">System Monitoring</div>
                <div class="tab" onclick="openTab('alerts')">Alerts</div>
                <div class="tab" onclick="openTab('graph')">Knowledge Graph</div>
                <div class="tab" onclick="openTab('report')">Report</div>
            </div>
            
            <div class="content">
                <div id="system" class="tab-content active">
                    <h2>System Monitoring</h2>
                    <iframe src="DASHBOARD_URL"></iframe>
                </div>
                
                <div id="alerts" class="tab-content">
                    <h2>Alerts</h2>
                    <iframe src="DASHBOARD_URL"></iframe>
                </div>
                
                <div id="graph" class="tab-content">
                    <h2>Knowledge Graph</h2>
                    <div>
                        <button class="button download-btn" onclick="window.open('GRAPH_JSON_URL', '_blank')">Download Graph JSON</button>
                    </div>
                    <iframe src="GRAPH_HTML_URL"></iframe>
                </div>
                
                <div id="report" class="tab-content">
                    <h2>Analysis Report</h2>
                    <div>
                        <button class="button download-btn" onclick="window.open('REPORT_URL', '_blank')">Download Report</button>
                    </div>
                    <iframe src="REPORT_URL"></iframe>
                </div>
            </div>
            
            <script>
                function openTab(tabName) {
                    var i, tabContent, tabLinks;
                    
                    tabContent = document.getElementsByClassName("tab-content");
                    for (i = 0; i < tabContent.length; i++) {
                        tabContent[i].className = tabContent[i].className.replace(" active", "");
                    }
                    
                    tabLinks = document.getElementsByClassName("tab");
                    for (i = 0; i < tabLinks.length; i++) {
                        tabLinks[i].className = tabLinks[i].className.replace(" active", "");
                    }
                    
                    document.getElementById(tabName).className += " active";
                    document.querySelector(`.tab[onclick="openTab('${tabName}')"]`).className += " active";
                }
            </script>
        </body>
        </html>
        """
        
        dashboard_template_url = f"{dashboard_url}src/alerting/templates/real_time_dashboard.html"
        graph_html_url = f"file://{os.path.abspath(html_path)}" if html_path else ""
        graph_json_url = f"file://{os.path.abspath(graph_path)}" if graph_path else ""
        report_url = f"file://{os.path.abspath(report_path)}" if report_path else ""
        
        dashboard_html = dashboard_html.replace("DASHBOARD_URL", dashboard_template_url)
        dashboard_html = dashboard_html.replace("GRAPH_HTML_URL", graph_html_url)
        dashboard_html = dashboard_html.replace("GRAPH_JSON_URL", graph_json_url)
        dashboard_html = dashboard_html.replace("REPORT_URL", report_url)
        
        with open(dashboard_file, 'w') as f:
            f.write(dashboard_html)
        
        dashboard_url = f"file://{os.path.abspath(dashboard_file)}"
        webbrowser.open(dashboard_url)
        print(f"\nIntegrated dashboard available at: {dashboard_url}")
        
        print("\nPress Ctrl+C to stop the dashboard")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            httpd.shutdown()
            logger.info("Dashboard stopped")
            print("\nDashboard stopped")
        
        return True
    
    except Exception as e:
        logger.error(f"Error running dashboard with enhanced relationships: {str(e)}", exc_info=True)
        return False

if __name__ == "__main__":
    main()
