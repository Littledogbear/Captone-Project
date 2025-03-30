"""
Test Fixed Graph Template

This script tests the fixed graph template to ensure it properly renders
the JSON data into a visual graph with relationship labels and color legend.
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime
import webbrowser
import json

sys.path.insert(0, str(Path(__file__).parent))

from src.knowledge_graph.enhanced_malware_graph_builder import EnhancedMalwareGraphBuilder

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_sample_data():
    """Generate sample data with Emotet and TrickBot malware."""
    return {
        "malware_analysis": [
            {
                "file": "Emotet.exe",
                "classification": "trojan",
                "sha256": "a94bf485d6a5faea1f68f596b4923e7f61798ba710a7d8d5d7ad9ef9b3ecc5e5",
                "tags": ["banking", "trojan", "emotet"],
                "description": "Emotet banking trojan"
            },
            {
                "file": "TrickBot.exe",
                "classification": "trojan",
                "sha256": "b94bf485d6a5faea1f68f596b4923e7f61798ba710a7d8d5d7ad9ef9b3ecc5e6",
                "tags": ["banking", "trojan", "trickbot"],
                "description": "TrickBot banking trojan"
            }
        ],
        "system_activity": {
            "processes": [
                {
                    "pid": 1234,
                    "name": "Emotet.exe",
                    "path": "C:\\Windows\\Temp\\Emotet.exe",
                    "command_line": "Emotet.exe -s",
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
                }
            ],
            "network": [
                {
                    "process_name": "Emotet.exe",
                    "local_addr": "192.168.1.100",
                    "local_port": 49152,
                    "remote_addr": "203.0.113.100",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                    "severity": "High"
                }
            ],
            "registry": [
                {
                    "process_name": "Emotet.exe",
                    "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "value": "Emotet",
                    "data": "C:\\Windows\\Temp\\Emotet.exe",
                    "action": "write",
                    "severity": "High"
                }
            ],
            "files": [
                {
                    "process_name": "Emotet.exe",
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
                "description": "Adversaries may achieve persistence by adding a program to a startup folder."
            },
            {
                "id": "T1059.001",
                "name": "Command and Scripting Interpreter: PowerShell",
                "confidence": 85,
                "description": "Adversaries may abuse PowerShell commands and scripts for execution."
            }
        ]
    }

def verify_html_content(html_path):
    """Verify that the HTML file contains proper graph data and not raw JSON."""
    try:
        with open(html_path, 'r') as f:
            content = f.read()
        
        if 'var nodes = new vis.DataSet(' not in content:
            logger.error("HTML file does not contain proper vis.js node initialization")
            return False
        
        if 'NODES_DATA' in content or 'EDGES_DATA' in content:
            logger.error("HTML file contains unreplaced placeholders")
            return False
        
        if '"id": "host_system"' not in content:
            logger.error("HTML file does not contain expected node data")
            return False
        
        logger.info("HTML file contains properly formatted graph data")
        return True
    
    except Exception as e:
        logger.error(f"Error verifying HTML content: {str(e)}")
        return False

def main():
    """Generate and display enhanced knowledge graph with malware samples."""
    output_dir = os.path.join(os.path.dirname(__file__), "output", "fixed_graph_test")
    os.makedirs(output_dir, exist_ok=True)
    
    sample_data = generate_sample_data()
    
    graph_builder = EnhancedMalwareGraphBuilder()
    graph_builder.build_graph(sample_data)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(output_dir, f"fixed_graph_{timestamp}.html")
    
    if not html_path.endswith('.html'):
        html_path = html_path.replace('.json', '.html')
        if not html_path.endswith('.html'):
            html_path += '.html'
    
    graph_builder.export_graph(html_path)
    logger.info(f"Enhanced knowledge graph exported to {html_path}")
    
    if verify_html_content(html_path):
        logger.info("HTML content verification passed")
    else:
        logger.error("HTML content verification failed")
    
    webbrowser.open(f"file://{html_path}")
    
    print(f"\nEnhanced knowledge graph visualization available at: {html_path}")
    
    return html_path

if __name__ == "__main__":
    main()
