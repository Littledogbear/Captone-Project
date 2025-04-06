"""
Script to integrate attribution data into the security report.
This demonstrates how attribution information is incorporated into the existing report format.
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path

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
logger = logging.getLogger("attribution_report_integration")

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

def generate_integrated_report():
    """Generate a security report with integrated attribution data."""
    output_dir = Path("output/integrated_report")
    output_dir.mkdir(parents=True, exist_ok=True)
    
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
        
        graph_builder = KnowledgeGraphBuilder()
        graph = graph_builder.build_graph_from_traces({
            "malware": sample,
            "attribution": attribution_result
        })
        
        graph_viz = GraphVisualizer()
        graph_file = output_dir / f"knowledge_graph_{sample_name}_{timestamp}.html"
        graph_viz.visualize_graph_html(graph, str(graph_file))
        
        report_data = {
            "report_title": "Cyber Attack Tracer - Security Report",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "malware_analysis": [
                {
                    "file": sample["name"],
                    "classification": sample["type"],
                    "sha256": sample["sha256"],
                    "tags": sample["tags"],
                    "description": sample["description"]
                }
            ],
            "attack_techniques": [
                {
                    "id": "T1055",
                    "name": "Process Injection",
                    "confidence": 85,
                    "description": "The malware injects code into legitimate processes to evade detection."
                },
                {
                    "id": "T1486",
                    "name": "Data Encrypted for Impact",
                    "confidence": 90,
                    "description": "The ransomware encrypts user files to prevent access and demands payment for decryption."
                },
                {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                    "confidence": 80,
                    "description": "The malware uses HTTP/HTTPS protocols for command and control communications."
                },
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "confidence": 75,
                    "description": "The malware uses command line interfaces to execute commands and scripts."
                }
            ],
            "system_activity": {
                "processes": [
                    {"pid": 1234, "name": "malware.exe", "username": "SYSTEM", "cpu_usage": 5.2},
                    {"pid": 1235, "name": "cmd.exe", "username": "SYSTEM", "cpu_usage": 0.8},
                    {"pid": 1236, "name": "explorer.exe", "username": "user", "cpu_usage": 2.1}
                ],
                "network": [
                    {
                        "local_address": {"ip": "192.168.1.100", "port": 49152},
                        "remote_address": {"ip": "45.77.65.211", "port": 443},
                        "status": "ESTABLISHED",
                        "pid": 1234
                    }
                ]
            },
            "visualizations": {
                "knowledge_graph": str(graph_file)
            },
            "suggestions": True,
            "attribution": attribution_result
        }
        
        report_gen = ReportGenerator()
        report_file = output_dir / f"integrated_report_{sample_name}_{timestamp}.html"
        report_gen.generate_report(report_data, str(report_file))
        
        logger.info(f"Generated integrated report for {sample_name}: {report_file}")
        
        print(f"\n{'='*80}")
        print(f"INTEGRATED REPORT FOR {sample_name}")
        print(f"{'='*80}")
        print(f"Report file: {report_file}")
        print(f"Knowledge graph: {graph_file}")
        
        if "potential_actors" in attribution_result and attribution_result["potential_actors"]:
            print("\nAttribution Results:")
            for actor in attribution_result["potential_actors"]:
                print(f"  - {actor.get('name', 'Unknown')} (Match Score: {actor.get('match_score', 0):.2f})")
                print(f"    Aliases: {', '.join(actor.get('aliases', []))}")
                print(f"    Matches: {', '.join(actor.get('matches', []))}")
                print(f"    Description: {actor.get('description', '')}")
        else:
            print("\nNo potential actors identified")

if __name__ == "__main__":
    generate_integrated_report()
