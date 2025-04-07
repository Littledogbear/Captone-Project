"""
Test script to verify the updated report template with fixed malware samples section.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

try:
    from reporting.report_generator import ReportGenerator
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def test_updated_report_template():
    """Test the updated report template with fixed malware samples section."""
    output_dir = Path("output/updated_template_test")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    report_data = {
        "report_title": "Cyber Attack Tracer - Security Report",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "malware_analysis": [
            {
                "file": "AdditionalMalware.exe",
                "classification": "adware",
                "sha256": "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
                "tags": ["adware", "browser-hijacker"],
                "description": "This adware displays unwanted advertisements and modifies browser settings."
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
        "attribution": {
            "confidence_score": 0.92,
            "potential_actors": [
                {
                    "name": "APT28",
                    "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
                    "match_score": 0.92,
                    "matches": ["Tool: X-Agent", "Technique: T1055", "Geolocation: Russia"],
                    "description": "Russian state-sponsored threat actor known for targeting government and military organizations."
                }
            ],
            "overall_assessment": "HIGH CONFIDENCE ATTRIBUTION: The attack patterns, tools, and techniques strongly match those associated with APT28 (Fancy Bear), a Russian state-sponsored threat actor."
        },
        "suggestions": True
    }
    
    report_gen = ReportGenerator()
    report_file = output_dir / f"updated_template_report_{timestamp}.html"
    report_gen.generate_report(report_data, str(report_file))
    
    print(f"\n{'='*80}")
    print(f"UPDATED TEMPLATE TEST REPORT")
    print(f"{'='*80}")
    print(f"Report file: {report_file}")
    print(f"This report should display both the fixed malware samples (TrojanSample, RansomwareSample, BotnetSample)")
    print(f"and any additional malware samples provided in the malware_analysis data.")
    print(f"Please open the report in a browser to verify the correct display format.")

if __name__ == "__main__":
    test_updated_report_template()
