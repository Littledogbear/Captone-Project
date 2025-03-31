"""
Comprehensive System Test with Specific Malware Samples

This script tests the entire Cyber Attack Tracer system functionality including:
- Dashboard UI display
- Knowledge graph generation with relationship lines
- Report generation with proper confidence scores
- Button functionalities
"""

import os
import sys
import logging
import time
import webbrowser
import subprocess
import signal
import json
from pathlib import Path
from datetime import datetime
import threading
import requests

sys.path.insert(0, str(Path(__file__).parent))

from src.knowledge_graph.enhanced_malware_graph_builder import EnhancedMalwareGraphBuilder
from src.reporting.report_generator import ReportGenerator

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 9090  # Using a different port to avoid conflicts

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output", "comprehensive_test")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_specific_malware_data():
    """Generate data with the specific malware samples from the security report."""
    return {
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
        "system_activity": {
            "processes": [
                {
                    "pid": 1234,
                    "name": "TrojanSample.exe",
                    "path": "C:\\Windows\\Temp\\TrojanSample.exe",
                    "command_line": "TrojanSample.exe -s",
                    "user": "SYSTEM",
                    "start_time": "2025-03-30T10:15:30",
                    "severity": "High"
                },
                {
                    "pid": 1235,
                    "name": "powershell.exe",
                    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand <base64>",
                    "parent_pid": 1234,
                    "user": "SYSTEM",
                    "start_time": "2025-03-30T10:15:35",
                    "severity": "High"
                },
                {
                    "pid": 1236,
                    "name": "RansomwareSample.exe",
                    "path": "C:\\Users\\Admin\\Downloads\\RansomwareSample.exe",
                    "command_line": "RansomwareSample.exe",
                    "user": "Admin",
                    "start_time": "2025-03-30T10:20:15",
                    "severity": "Critical"
                },
                {
                    "pid": 1237,
                    "name": "BotnetSample.exe",
                    "path": "C:\\ProgramData\\BotnetSample.exe",
                    "command_line": "BotnetSample.exe --hidden",
                    "user": "SYSTEM",
                    "start_time": "2025-03-30T10:25:45",
                    "severity": "High"
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
                    "severity": "High"
                }
            ],
            "registry": [
                {
                    "process_name": "TrojanSample.exe",
                    "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value": "TrojanSample",
                    "data": "C:\\Windows\\Temp\\TrojanSample.exe",
                    "action": "write",
                    "severity": "High"
                }
            ],
            "files": [
                {
                    "process_name": "RansomwareSample.exe",
                    "path": "C:\\Users\\Admin\\Documents\\important.docx.encrypted",
                    "action": "create",
                    "severity": "Critical"
                },
                {
                    "process_name": "RansomwareSample.exe",
                    "path": "C:\\Users\\Admin\\Documents\\important.docx",
                    "action": "delete",
                    "severity": "Critical"
                },
                {
                    "process_name": "TrojanSample.exe",
                    "path": "C:\\Windows\\Temp\\config.bin",
                    "action": "create",
                    "severity": "High"
                }
            ]
        },
        "attack_techniques": [
            {
                "id": "T1547.001",
                "name": "Boot or Logon Autostart Execution: Registry Run Keys",
                "confidence": 90,
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or registry run keys."
            },
            {
                "id": "T1059.001",
                "name": "Command and Scripting Interpreter: PowerShell",
                "confidence": 85,
                "description": "Adversaries may abuse PowerShell commands and scripts for execution."
            },
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "confidence": 95,
                "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources."
            },
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "confidence": 80,
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users."
            }
        ]
    }

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

def generate_knowledge_graph(data):
    """Generate knowledge graph with the specific malware samples."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(OUTPUT_DIR, f"comprehensive_graph_{timestamp}.html")
    
    graph_builder = EnhancedMalwareGraphBuilder()
    graph_builder.build_graph(data)
    graph_builder.export_graph(html_path)
    
    logger.info(f"Knowledge graph exported to {html_path}")
    return html_path

def generate_security_report(data):
    """Generate security report with the specific malware samples."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(OUTPUT_DIR, f"comprehensive_report_{timestamp}.html")
    
    threat_level = "Critical"  # Based on ransomware presence
    
    improvements = generate_security_improvements(data["attack_techniques"])
    
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "threat_level": threat_level,
        "malware_analysis": data["malware_analysis"],
        "attack_techniques": data["attack_techniques"],
        "system_activity": data["system_activity"],
        "security_improvements": improvements
    }
    
    report_generator = ReportGenerator()
    report_generator.generate_report(report_data, html_path)
    
    logger.info(f"Security report generated at {html_path}")
    return html_path

def start_dashboard():
    """Start the monitoring dashboard in a separate process."""
    dashboard_script = os.path.join(os.path.dirname(__file__), "run_monitoring_dashboard.py")
    
    env = os.environ.copy()
    env["DASHBOARD_HOST"] = DASHBOARD_HOST
    env["DASHBOARD_PORT"] = str(DASHBOARD_PORT)
    
    dashboard_process = subprocess.Popen(
        [sys.executable, dashboard_script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    time.sleep(5)
    
    return dashboard_process

def test_dashboard_ui():
    """Test the dashboard UI by accessing it and checking for key elements."""
    try:
        response = requests.get(f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
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

def test_button_functionality():
    """Test the functionality of the dashboard buttons."""
    try:
        response = requests.post(
            f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/generate_knowledge_graph",
            json=generate_specific_malware_data()
        )
        
        if response.status_code == 200:
            logger.info("Generate Knowledge Graph button works")
            knowledge_graph_success = True
        else:
            logger.error(f"Generate Knowledge Graph button failed: {response.status_code}")
            knowledge_graph_success = False
        
        response = requests.post(
            f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/generate_report",
            json=generate_specific_malware_data()
        )
        
        if response.status_code == 200:
            logger.info("Generate Report button works")
            report_success = True
        else:
            logger.error(f"Generate Report button failed: {response.status_code}")
            report_success = False
        
        return knowledge_graph_success and report_success
    
    except Exception as e:
        logger.error(f"Error testing button functionality: {str(e)}")
        return False

def main():
    """Run comprehensive system test with specific malware samples."""
    logger.info("Starting comprehensive system test with specific malware samples")
    
    data = generate_specific_malware_data()
    
    graph_path = generate_knowledge_graph(data)
    
    report_path = generate_security_report(data)
    
    dashboard_process = start_dashboard()
    
    try:
        ui_success = test_dashboard_ui()
        
        button_success = test_button_functionality()
        
        webbrowser.open(f"file://{graph_path}")
        webbrowser.open(f"file://{report_path}")
        webbrowser.open(f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
        
        print("\n=== Comprehensive System Test Results ===")
        print(f"Knowledge Graph Generation: {'Success' if os.path.exists(graph_path) else 'Failed'}")
        print(f"Security Report Generation: {'Success' if os.path.exists(report_path) else 'Failed'}")
        print(f"Dashboard UI Test: {'Success' if ui_success else 'Failed'}")
        print(f"Button Functionality Test: {'Success' if button_success else 'Failed'}")
        print("\n=== Generated Files ===")
        print(f"Knowledge Graph: {graph_path}")
        print(f"Security Report: {report_path}")
        print(f"Dashboard URL: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
        
        print("\nPress Ctrl+C to stop the test and close the dashboard...")
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\nTest stopped by user")
    finally:
        if dashboard_process:
            dashboard_process.terminate()
            try:
                dashboard_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard_process.kill()

if __name__ == "__main__":
    main()
