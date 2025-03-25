import networkx as nx
from typing import Dict, Any, List
import logging
import json
import os
from pathlib import Path

class TechniqueIdentifier:
    """Identifies attack techniques in knowledge graphs."""
    
    def __init__(self, techniques_db_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.techniques_db_path = techniques_db_path or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "techniques_db.json"
        )
        self.techniques_db = self._load_techniques_db()
        
    def _load_techniques_db(self) -> Dict[str, Any]:
        """Load techniques database from file."""
        if os.path.exists(self.techniques_db_path):
            try:
                with open(self.techniques_db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading techniques database: {str(e)}")
                
        # Return default techniques database if file doesn't exist or loading fails
        return self._create_default_techniques_db()
        
    def _create_default_techniques_db(self) -> Dict[str, Any]:
        """Create default techniques database based on MITRE ATT&CK framework."""
        techniques = {
            "T1071": {
                "name": "Command and Control",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering.",
                "patterns": [
                    {"type": "network_connection", "ports": [80, 443, 8080, 8443]},
                    {"type": "process_behavior", "suspicious_processes": ["cmd.exe", "powershell.exe"]}
                ]
            },
            "T1048": {
                "name": "Exfiltration Over Alternative Protocol",
                "description": "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
                "patterns": [
                    {"type": "data_transfer", "threshold": 1000000},  # 1MB
                    {"type": "network_connection", "ports": [21, 22, 53]}
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "patterns": [
                    {"type": "process_execution", "processes": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]}
                ]
            },
            "T1082": {
                "name": "System Information Discovery",
                "description": "Adversaries may attempt to get detailed information about the operating system and hardware.",
                "patterns": [
                    {"type": "process_execution", "processes": ["systeminfo.exe", "hostname.exe", "ipconfig.exe"]}
                ]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "description": "Adversaries may enumerate files and directories to identify sensitive information.",
                "patterns": [
                    {"type": "process_execution", "processes": ["dir", "find", "ls"]}
                ]
            }
        }
        
        # Save default techniques database
        os.makedirs(os.path.dirname(self.techniques_db_path), exist_ok=True)
        try:
            with open(self.techniques_db_path, "w") as f:
                json.dump(techniques, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving default techniques database: {str(e)}")
            
        return techniques
        
    def identify_techniques(self, graph: nx.DiGraph) -> List[Dict[str, Any]]:
        """Identify attack techniques in a knowledge graph."""
        identified_techniques = []
        
        for technique_id, technique_info in self.techniques_db.items():
            confidence = self._calculate_technique_confidence(graph, technique_info)
            
            if confidence > 0.5:  # Confidence threshold
                identified_techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_info["name"],
                    "description": technique_info["description"],
                    "confidence": confidence
                })
                
        return identified_techniques
        
    def _calculate_technique_confidence(self, graph: nx.DiGraph, technique_info: Dict[str, Any]) -> float:
        """Calculate confidence score for a technique based on graph patterns."""
        confidence = 0.0
        matched_patterns = 0
        total_patterns = len(technique_info.get("patterns", []))
        
        if total_patterns == 0:
            return 0.0
            
        for pattern in technique_info.get("patterns", []):
            pattern_type = pattern.get("type")
            
            if pattern_type == "network_connection":
                if self._match_network_pattern(graph, pattern):
                    matched_patterns += 1
                    
            elif pattern_type == "process_execution":
                if self._match_process_pattern(graph, pattern):
                    matched_patterns += 1
                    
            elif pattern_type == "data_transfer":
                if self._match_data_transfer_pattern(graph, pattern):
                    matched_patterns += 1
                    
            elif pattern_type == "process_behavior":
                if self._match_process_behavior_pattern(graph, pattern):
                    matched_patterns += 1
                    
        confidence = matched_patterns / total_patterns
        return confidence
        
    def _match_network_pattern(self, graph: nx.DiGraph, pattern: Dict[str, Any]) -> bool:
        """Match network connection pattern in graph."""
        suspicious_ports = pattern.get("ports", [])
        
        for node in graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "network" and node_data.get("port") in suspicious_ports:
                return True
                
        return False
        
    def _match_process_pattern(self, graph: nx.DiGraph, pattern: Dict[str, Any]) -> bool:
        """Match process execution pattern in graph."""
        suspicious_processes = pattern.get("processes", [])
        
        for node in graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process" and node_data.get("name") in suspicious_processes:
                return True
                
        return False
        
    def _match_data_transfer_pattern(self, graph: nx.DiGraph, pattern: Dict[str, Any]) -> bool:
        """Match data transfer pattern in graph."""
        threshold = pattern.get("threshold", 0)
        
        for _, _, edge_data in graph.edges(data=True):
            if edge_data.get("type") == "transfers_data" and edge_data.get("bytes", 0) > threshold:
                return True
                
        return False
        
    def _match_process_behavior_pattern(self, graph: nx.DiGraph, pattern: Dict[str, Any]) -> bool:
        """Match process behavior pattern in graph."""
        suspicious_processes = pattern.get("suspicious_processes", [])
        
        for node in graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process" and node_data.get("name") in suspicious_processes:
                # Check if process has suspicious behavior (e.g., network connections)
                if graph.out_degree(node_id) > 0:
                    return True
                    
        return False
        
    def add_technique(self, technique_id: str, technique_info: Dict[str, Any]) -> bool:
        """Add a new technique to the database."""
        if technique_id in self.techniques_db:
            self.logger.warning(f"Technique {technique_id} already exists in database")
            return False
            
        self.techniques_db[technique_id] = technique_info
        
        # Save updated database
        try:
            with open(self.techniques_db_path, "w") as f:
                json.dump(self.techniques_db, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Error saving techniques database: {str(e)}")
            return False
            
    def update_technique(self, technique_id: str, technique_info: Dict[str, Any]) -> bool:
        """Update an existing technique in the database."""
        if technique_id not in self.techniques_db:
            self.logger.warning(f"Technique {technique_id} does not exist in database")
            return False
            
        self.techniques_db[technique_id] = technique_info
        
        # Save updated database
        try:
            with open(self.techniques_db_path, "w") as f:
                json.dump(self.techniques_db, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Error saving techniques database: {str(e)}")
            return False
