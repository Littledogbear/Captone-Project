"""
Comprehensive System Test with Specific Samples

This script demonstrates the complete workflow of the Cyber Attack Tracer system:
1. Start the monitoring dashboard
2. Introduce malware samples
3. Generate alerts
4. Create knowledge graphs and security reports

Use this script for demonstration and testing purposes.
"""

import os
import sys
import time
import logging
import argparse
import threading
import webbrowser
import subprocess
import json
import random
from pathlib import Path
from datetime import datetime
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("comprehensive_test.log")
    ]
)

logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.alerting.alert_dashboard import AlertDashboard
from src.alerting.enhanced_real_time_monitor import EnhancedRealTimeMonitor
from src.alerting.alert_types import Alert, AlertSeverity, AlertType
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.templates.ui_integration import UIIntegrator
from src.reporting.report_generator import ReportGenerator
from src.trace_collector.collector import TraceCollector
from src.utils.config import load_config

def load_malware_samples(samples_dir):
    """
    Load malware sample metadata from the specified directory.
    
    Args:
        samples_dir: Directory containing malware sample metadata
        
    Returns:
        List of malware sample metadata
    """
    samples = []
    
    if not os.path.exists(samples_dir):
        logger.warning(f"Samples directory not found: {samples_dir}")
        return samples
    
    for filename in os.listdir(samples_dir):
        if filename.endswith('.json'):
            try:
                with open(os.path.join(samples_dir, filename), 'r') as f:
                    sample_data = json.load(f)
                    samples.append(sample_data)
                    logger.info(f"Loaded sample: {filename}")
            except Exception as e:
                logger.error(f"Error loading sample {filename}: {str(e)}")
    
    return samples

def generate_sample_traces(samples):
    """
    Generate sample traces from malware samples.
    
    Args:
        samples: List of malware sample metadata
        
    Returns:
        List of traces
    """
    traces = []
    
    for sample in samples:
        sample_name = sample.get('file_name', 'unknown_sample.exe')
        sample_type = sample.get('type', 'unknown')
        sample_hash = sample.get('sha256_hash', '')
        
        process_trace = {
            'type': 'process',
            'timestamp': datetime.now().isoformat(),
            'process_name': sample_name,
            'process_id': random.randint(1000, 9999),
            'command_line': f"C:\\malware\\{sample_name}",
            'parent_process_id': random.randint(100, 999),
            'parent_process_name': 'explorer.exe',
            'user': 'SYSTEM',
            'hash': sample_hash
        }
        traces.append(process_trace)
        
        file_trace = {
            'type': 'file',
            'timestamp': datetime.now().isoformat(),
            'file_path': f"C:\\malware\\{sample_name}",
            'operation': 'create',
            'process_id': process_trace['process_id'],
            'process_name': sample_name,
            'hash': sample_hash
        }
        traces.append(file_trace)
        
        network_trace = {
            'type': 'network',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'destination_ip': f"10.0.0.{random.randint(1, 254)}",
            'destination_port': random.choice([80, 443, 8080, 8443, 4444]),
            'protocol': 'TCP',
            'process_id': process_trace['process_id'],
            'process_name': sample_name,
            'bytes_sent': random.randint(1000, 10000),
            'bytes_received': random.randint(100, 5000)
        }
        traces.append(network_trace)
        
        registry_trace = {
            'type': 'registry',
            'timestamp': datetime.now().isoformat(),
            'registry_key': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'registry_value': sample_name,
            'operation': 'set',
            'process_id': process_trace['process_id'],
            'process_name': sample_name
        }
        traces.append(registry_trace)
    
    return traces

def generate_alerts_from_traces(traces, dashboard):
    """
    Generate alerts from traces and send them to the dashboard.
    
    Args:
        traces: List of traces
        dashboard: AlertDashboard instance
    """
    for trace in traces:
        trace_type = trace.get('type')
        
        if trace_type == 'process':
            alert = Alert(
                title=f"Suspicious Process: {trace.get('process_name')}",
                message=f"Detected suspicious process {trace.get('process_name')} with PID {trace.get('process_id')}",
                severity=AlertSeverity.HIGH,
                type=AlertType.SUSPICIOUS_PROCESS,
                details={
                    'process_name': trace.get('process_name'),
                    'process_id': trace.get('process_id'),
                    'command_line': trace.get('command_line'),
                    'hash': trace.get('hash')
                }
            )
            dashboard.send_alert(alert.to_dict())
            logger.info(f"Sent process alert: {alert.title}")
            
        elif trace_type == 'network':
            alert = Alert(
                title=f"Suspicious Network Connection: {trace.get('process_name')}",
                message=f"Detected suspicious network connection from {trace.get('process_name')} to {trace.get('destination_ip')}:{trace.get('destination_port')}",
                severity=AlertSeverity.MEDIUM,
                type=AlertType.NETWORK,
                details={
                    'process_name': trace.get('process_name'),
                    'source_ip': trace.get('source_ip'),
                    'destination_ip': trace.get('destination_ip'),
                    'destination_port': trace.get('destination_port'),
                    'protocol': trace.get('protocol')
                }
            )
            dashboard.send_alert(alert.to_dict())
            logger.info(f"Sent network alert: {alert.title}")
            
        elif trace_type == 'file':
            alert = Alert(
                title=f"Suspicious File Operation: {trace.get('file_path')}",
                message=f"Detected suspicious file operation on {trace.get('file_path')}",
                severity=AlertSeverity.MEDIUM,
                type=AlertType.FILE,
                details={
                    'file_path': trace.get('file_path'),
                    'operation': trace.get('operation'),
                    'process_name': trace.get('process_name'),
                    'hash': trace.get('hash')
                }
            )
            dashboard.send_alert(alert.to_dict())
            logger.info(f"Sent file alert: {alert.title}")
            
        elif trace_type == 'registry':
            alert = Alert(
                title=f"Suspicious Registry Operation: {trace.get('registry_key')}",
                message=f"Detected suspicious registry operation on {trace.get('registry_key')}",
                severity=AlertSeverity.LOW,
                type=AlertType.REGISTRY,
                details={
                    'registry_key': trace.get('registry_key'),
                    'registry_value': trace.get('registry_value'),
                    'operation': trace.get('operation'),
                    'process_name': trace.get('process_name')
                }
            )
            dashboard.send_alert(alert.to_dict())
            logger.info(f"Sent registry alert: {alert.title}")

def main():
    """Run the comprehensive system test with specific samples."""
    parser = argparse.ArgumentParser(description='Cyber Attack Tracer - Comprehensive System Test')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to run the dashboard on')
    parser.add_argument('--port', type=int, default=8081, help='Port to run the dashboard on')
    parser.add_argument('--samples-dir', type=str, 
                       default=os.path.join(os.path.expanduser("~"), "samples", "malwarebazaa", "metadata"),
                       help='Directory containing malware samples metadata')
    args = parser.parse_args()
    
    logger.info("Initializing system components...")
    
    dashboard = AlertDashboard(host=args.host, port=args.port)
    
    graph_builder = KnowledgeGraphBuilder()
    
    output_dir = os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "dashboard")
    os.makedirs(output_dir, exist_ok=True)
    ui_integrator = UIIntegrator(output_dir=output_dir)
    
    report_generator = ReportGenerator()
    
    monitor = EnhancedRealTimeMonitor()
    
    dashboard.register_report_generator(report_generator)
    
    dashboard.register_knowledge_graph_builder(graph_builder, ui_integrator)
    
    logger.info(f"Starting dashboard on http://{args.host}:{args.port}")
    dashboard.start(dashboard_title="Cyber Attack Tracer - Real-time Monitoring Dashboard")
    
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    logger.info("Waiting for dashboard to initialize...")
    time.sleep(3)
    
    logger.info(f"Loading malware samples from {args.samples_dir}...")
    samples = load_malware_samples(args.samples_dir)
    
    if not samples:
        logger.warning("No malware samples found. Using simulated samples.")
        samples = [
            {
                'file_name': 'trojan_sample.exe',
                'type': 'trojan',
                'sha256_hash': 'a' * 64,
                'tags': ['trojan', 'stealer', 'backdoor']
            },
            {
                'file_name': 'ransomware_sample.exe',
                'type': 'ransomware',
                'sha256_hash': 'b' * 64,
                'tags': ['ransomware', 'crypter', 'dropper']
            }
        ]
    
    logger.info("Generating traces from malware samples...")
    traces = generate_sample_traces(samples)
    
    logger.info("Generating alerts from traces...")
    generate_alerts_from_traces(traces, dashboard)
    
    logger.info("Generating knowledge graph...")
    graph = graph_builder.build_graph_from_traces(traces)
    
    logger.info("Generating visualization...")
    result = ui_integrator.create_dashboard(
        graph=graph,
        filename="knowledge_graph_test.html",
        title="Cyber Attack Knowledge Graph"
    )
    
    logger.info("Generating report...")
    analysis_data = {
        "processes": [
            {
                "name": sample.get('file_name', 'unknown_sample.exe'),
                "pid": random.randint(1000, 9999),
                "path": f"C:\\malware\\{sample.get('file_name', 'unknown_sample.exe')}",
                "hash": sample.get('sha256_hash', ''),
                "type": sample.get('type', 'unknown')
            } for sample in samples
        ],
        "network_connections": [
            {
                "source_ip": "192.168.1.100",
                "destination_ip": f"10.0.0.{random.randint(1, 254)}",
                "destination_port": random.choice([80, 443, 8080, 8443, 4444]),
                "protocol": "TCP",
                "process_name": sample.get('file_name', 'unknown_sample.exe')
            } for sample in samples
        ],
        "techniques": [
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "confidence": random.randint(70, 95),
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic."
            },
            {
                "id": "T1547.001",
                "name": "Registry Run Keys / Startup Folder",
                "confidence": random.randint(70, 95),
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key."
            }
        ],
        "malware_samples": [
            {
                "name": sample.get('file_name', 'unknown_sample.exe'),
                "type": sample.get('type', 'unknown'),
                "hash": sample.get('sha256_hash', ''),
                "tags": sample.get('tags', [])
            } for sample in samples
        ]
    }
    
    report_html = report_generator.generate_report(analysis_data, report_type="html")
    
    reports_dir = os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    report_filename = "security_report_test.html"
    report_path = os.path.join(reports_dir, report_filename)
    
    with open(report_path, "w") as f:
        f.write(report_html)
    
    logger.info(f"Report saved to {report_path}")
    
    print("\n" + "="*80)
    print("CYBER ATTACK TRACER - COMPREHENSIVE SYSTEM TEST")
    print("="*80)
    print(f"\nDashboard is running at: http://{args.host}:{args.port}")
    print("\nInstructions for demonstration:")
    print("1. Open the dashboard in your browser")
    print("2. Navigate through the tabs to see the different components")
    print("3. View the alerts generated from the malware samples")
    print("4. Click the 'Generate Knowledge Graph' button to create a knowledge graph")
    print("5. Click the 'Generate Security Report' button to create a security report")
    print("\nPress Ctrl+C to stop the test")
    print("="*80 + "\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping test...")
        dashboard.stop()
        logger.info("Test stopped")

def generate_security_improvements(attack_techniques):
    """Generate security improvement suggestions based on attack techniques."""
    improvements = {
        "high_priority": [],
        "medium_priority": [],
        "low_priority": []
    }
    
    technique_improvements = {
        "T1547.001": {
            "priority": "high",
            "suggestion": "Implement AppLocker or Software Restriction Policies to prevent unauthorized executables from running.",
            "details": "Configure Windows to prevent unauthorized modifications to startup registry keys."
        },
        "T1059.001": {
            "priority": "high",
            "suggestion": "Enable PowerShell script block logging and constrained language mode.",
            "details": "Monitor for suspicious PowerShell commands and implement AMSI for script scanning."
        },
        "T1486": {
            "priority": "high",
            "suggestion": "Implement regular backups with offline storage and test restoration procedures.",
            "details": "Use application control to prevent unauthorized encryption tools from executing."
        },
        "T1498": {
            "priority": "medium",
            "suggestion": "Implement DoS protection services and traffic filtering.",
            "details": "Configure network monitoring to detect unusual traffic patterns and implement rate limiting."
        }
    }
    
    for technique in attack_techniques:
        technique_id = technique.get("id")
        if technique_id in technique_improvements:
            improvement = technique_improvements[technique_id]
            priority = improvement["priority"]
            
            if priority == "high":
                improvements["high_priority"].append({
                    "technique_id": technique_id,
                    "suggestion": improvement["suggestion"],
                    "details": improvement["details"]
                })
            elif priority == "medium":
                improvements["medium_priority"].append({
                    "technique_id": technique_id,
                    "suggestion": improvement["suggestion"],
                    "details": improvement["details"]
                })
            else:
                improvements["low_priority"].append({
                    "technique_id": technique_id,
                    "suggestion": improvement["suggestion"],
                    "details": improvement["details"]
                })
    
    return improvements

def test_dashboard_ui():
    """Test the dashboard UI by accessing it and checking for key elements."""
    try:
        response = requests.get(f"http://127.0.0.1:8081")
        if response.status_code == 200:
            content = response.text
            
            ui_elements = [
                "Cyber Attack Tracer - Real-time Monitoring Dashboard",
                "System Monitoring",
                "Alerts",
                "Knowledge Graph",
                "Reports",
                "Generate Knowledge Graph",
                "Generate Report"
            ]
            
            missing_elements = []
            for element in ui_elements:
                if element not in content:
                    missing_elements.append(element)
            
            if missing_elements:
                logger.error(f"Missing UI elements: {', '.join(missing_elements)}")
                return False
            else:
                logger.info("All UI elements present in the dashboard")
                return True
        else:
            logger.error(f"Failed to access dashboard: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error testing dashboard UI: {str(e)}")
        return False

if __name__ == "__main__":
    main()
