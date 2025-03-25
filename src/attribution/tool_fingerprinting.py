import logging
import re
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import hashlib

class ToolFingerprinting:
    """Identifies attack tools based on their fingerprints."""
    
    def __init__(self, fingerprint_db_path: str = "data/fingerprints/tool_fingerprints.json"):
        self.logger = logging.getLogger(__name__)
        self.fingerprint_db_path = fingerprint_db_path
        self.fingerprints = {}
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.fingerprint_db_path), exist_ok=True)
        
        # Load fingerprints
        self._load_fingerprints()
        
    def _load_fingerprints(self):
        """Load tool fingerprints from database."""
        try:
            if os.path.exists(self.fingerprint_db_path):
                with open(self.fingerprint_db_path, "r") as f:
                    self.fingerprints = json.load(f)
                self.logger.info(f"Loaded {len(self.fingerprints)} tool fingerprints")
            else:
                self.logger.info("Fingerprint database not found, creating default database")
                self._create_default_fingerprints()
        except Exception as e:
            self.logger.error(f"Error loading fingerprints: {str(e)}")
            self._create_default_fingerprints()
            
    def _save_fingerprints(self):
        """Save tool fingerprints to database."""
        try:
            with open(self.fingerprint_db_path, "w") as f:
                json.dump(self.fingerprints, f, indent=2)
            self.logger.info(f"Saved {len(self.fingerprints)} tool fingerprints")
        except Exception as e:
            self.logger.error(f"Error saving fingerprints: {str(e)}")
            
    def _create_default_fingerprints(self):
        """Create default tool fingerprints."""
        self.fingerprints = {
            "nmap": {
                "name": "Nmap",
                "description": "Network scanning tool",
                "patterns": [
                    r"Nmap scan report",
                    r"PORT\s+STATE\s+SERVICE",
                    r"Host is up \(\d+\.\d+s latency\)"
                ],
                "process_names": ["nmap", "nmap.exe"],
                "network_signatures": [
                    {"port": 80, "payload_pattern": r"Mozilla/5\.0 \(compatible; Nmap Scripting Engine"}
                ],
                "attribution": {
                    "skill_level": "medium",
                    "common_users": ["penetration testers", "network administrators", "hackers"],
                    "countries": []  # Used globally
                }
            },
            "metasploit": {
                "name": "Metasploit Framework",
                "description": "Penetration testing framework",
                "patterns": [
                    r"msf\d?>\s",
                    r"meterpreter>\s",
                    r"\[\*\] Meterpreter session \d+ opened"
                ],
                "process_names": ["msfconsole", "msfvenom", "metasploit"],
                "network_signatures": [
                    {"port": 4444, "payload_pattern": r"Meterpreter"}
                ],
                "attribution": {
                    "skill_level": "medium-high",
                    "common_users": ["penetration testers", "red teams", "hackers"],
                    "countries": []  # Used globally
                }
            },
            "cobalt_strike": {
                "name": "Cobalt Strike",
                "description": "Commercial penetration testing tool",
                "patterns": [
                    r"beacon>\s",
                    r"cobaltstrike",
                    r"stage\d{4}.dll"
                ],
                "process_names": ["cobaltstrike", "javaw.exe"],
                "network_signatures": [
                    {"port": 0, "payload_pattern": r"MZ.{100,300}This program cannot be run in DOS mode"}
                ],
                "attribution": {
                    "skill_level": "high",
                    "common_users": ["advanced penetration testers", "APT groups", "nation-state actors"],
                    "countries": ["CN", "RU", "IR", "KP"]  # Commonly associated with these countries
                }
            },
            "mimikatz": {
                "name": "Mimikatz",
                "description": "Credential dumping tool",
                "patterns": [
                    r"mimikatz",
                    r"sekurlsa::",
                    r"kerberos::"
                ],
                "process_names": ["mimikatz", "mimikatz.exe"],
                "network_signatures": [],
                "attribution": {
                    "skill_level": "medium-high",
                    "common_users": ["penetration testers", "hackers", "APT groups"],
                    "countries": []  # Used globally
                }
            }
        }
        self._save_fingerprints()
        
    def add_fingerprint(self, tool_id: str, fingerprint: Dict[str, Any]) -> bool:
        """Add a new tool fingerprint."""
        try:
            self.fingerprints[tool_id] = fingerprint
            self._save_fingerprints()
            self.logger.info(f"Added fingerprint for tool {tool_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding fingerprint for tool {tool_id}: {str(e)}")
            return False
            
    def identify_tools_from_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify tools based on process information."""
        identified_tools = []
        
        for process in processes:
            process_name = process.get("name", "").lower()
            process_cmd = process.get("cmdline", "").lower()
            
            for tool_id, fingerprint in self.fingerprints.items():
                # Check process names
                if process_name in [p.lower() for p in fingerprint.get("process_names", [])]:
                    identified_tools.append({
                        "tool_id": tool_id,
                        "name": fingerprint.get("name"),
                        "description": fingerprint.get("description"),
                        "process_id": process.get("pid"),
                        "process_name": process_name,
                        "confidence": 0.9,
                        "attribution": fingerprint.get("attribution", {})
                    })
                    continue
                    
                # Check patterns in command line
                for pattern in fingerprint.get("patterns", []):
                    if re.search(pattern, process_cmd, re.IGNORECASE):
                        identified_tools.append({
                            "tool_id": tool_id,
                            "name": fingerprint.get("name"),
                            "description": fingerprint.get("description"),
                            "process_id": process.get("pid"),
                            "process_name": process_name,
                            "confidence": 0.8,
                            "attribution": fingerprint.get("attribution", {})
                        })
                        break
                        
        return identified_tools
        
    def identify_tools_from_network(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify tools based on network connections."""
        identified_tools = []
        
        for connection in connections:
            remote_port = connection.get("remote_address", {}).get("port")
            payload = connection.get("payload", "")
            
            for tool_id, fingerprint in self.fingerprints.items():
                for signature in fingerprint.get("network_signatures", []):
                    # Check port if specified
                    if signature.get("port", 0) != 0 and remote_port != signature.get("port"):
                        continue
                        
                    # Check payload pattern if available
                    if payload and signature.get("payload_pattern"):
                        if re.search(signature.get("payload_pattern"), payload, re.IGNORECASE):
                            identified_tools.append({
                                "tool_id": tool_id,
                                "name": fingerprint.get("name"),
                                "description": fingerprint.get("description"),
                                "connection": {
                                    "local": connection.get("local_address"),
                                    "remote": connection.get("remote_address")
                                },
                                "confidence": 0.85,
                                "attribution": fingerprint.get("attribution", {})
                            })
                            
        return identified_tools
        
    def get_tool_attribution_info(self, tool_id: str) -> Dict[str, Any]:
        """Get attribution information for a specific tool."""
        if tool_id in self.fingerprints:
            return self.fingerprints[tool_id].get("attribution", {})
        else:
            return {}
