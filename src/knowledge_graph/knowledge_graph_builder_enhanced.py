import networkx as nx
from typing import Dict, Any, List, Optional
import logging
import json
import os
import re
from datetime import datetime

class KnowledgeGraphBuilder:
    """Builds knowledge graphs from cyber attack traces."""
    
    def __init__(self, attack_kg_mapping_path: str = ""):
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()
        
        # Load AttackKG mappings
        self.attack_kg_mapping_path = attack_kg_mapping_path or os.path.join(
            os.path.dirname(__file__), "attack_kg_mapping.json"
        )
        self.attack_kg_mappings = self._load_attack_kg_mappings()
        
    def _load_attack_kg_mappings(self) -> Dict[str, Any]:
        """Load AttackKG mappings from JSON file."""
        try:
            if os.path.exists(self.attack_kg_mapping_path):
                with open(self.attack_kg_mapping_path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"AttackKG mapping file not found at {self.attack_kg_mapping_path}")
                return {
                    "process_patterns": {},
                    "network_patterns": {},
                    "file_patterns": {},
                    "registry_patterns": {},
                    "behavior_patterns": {}
                }
        except Exception as e:
            self.logger.error(f"Error loading AttackKG mappings: {str(e)}")
            return {
                "process_patterns": {},
                "network_patterns": {},
                "file_patterns": {},
                "registry_patterns": {},
                "behavior_patterns": {}
            }
        
    def build_graph_from_traces(self, traces: Dict[str, Any]) -> nx.DiGraph:
        """Build a knowledge graph from collected traces."""
        self.graph = nx.DiGraph()
        
        # Extract entities from traces
        entities = self._extract_entities(traces)
        
        # Add entities to graph
        for entity_id, entity_data in entities.items():
            self.graph.add_node(entity_id, **entity_data)
            
        # Extract and add dependencies
        dependencies = self._extract_dependencies(traces, entities)
        
        for source, target, rel_type in dependencies:
            self.graph.add_edge(source, target, type=rel_type)
            
        # Identify attack techniques
        techniques = self.identify_techniques()
        
        # Add technique nodes to graph
        for technique in techniques:
            technique_id = technique["technique_id"]
            technique_node_id = f"technique_{technique_id}"
            
            # Add technique node
            self.graph.add_node(technique_node_id, 
                               type="technique",
                               technique_id=technique_id,
                               technique_name=technique["technique_name"],
                               confidence=technique["confidence"])
            
            # Connect entities to technique
            if "entities" in technique:
                for entity_id in technique["entities"]:
                    if entity_id in self.graph:
                        self.graph.add_edge(entity_id, technique_node_id, type="exhibits")
        
        return self.graph
        
    def _extract_entities(self, traces: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract entities from traces."""
        entities = {}
        
        # Extract process entities
        for process in traces.get("processes", []):
            process_id = f"process_{process.get('pid', '')}"
            entities[process_id] = {
                "type": "process",
                "name": process.get("name", ""),
                "pid": process.get("pid", ""),
                "username": process.get("username", ""),
                "timestamp": traces.get("timestamp", "")
            }
            
        # Extract network entities
        for i, conn in enumerate(traces.get("network_connections", [])):
            if conn.get("remote_address"):
                network_id = f"network_{i}"
                entities[network_id] = {
                    "type": "network",
                    "ip": conn.get("remote_address", {}).get("ip", ""),
                    "port": conn.get("remote_address", {}).get("port", ""),
                    "timestamp": traces.get("timestamp", "")
                }
                
        # Extract file system entities
        for i, file_event in enumerate(traces.get("file_system_events", [])):
            file_id = f"file_{i}"
            entities[file_id] = {
                "type": "file",
                "path": file_event.get("path", ""),
                "operation": file_event.get("operation", ""),
                "timestamp": traces.get("timestamp", "")
            }
            
        # Extract registry entities
        for i, reg_event in enumerate(traces.get("registry_events", [])):
            registry_id = f"registry_{i}"
            entities[registry_id] = {
                "type": "registry",
                "key": reg_event.get("key", ""),
                "operation": reg_event.get("operation", ""),
                "timestamp": traces.get("timestamp", "")
            }
                
        return entities
        
    def _extract_dependencies(self, traces: Dict[str, Any], 
                             entities: Dict[str, Dict[str, Any]]) -> List[tuple]:
        """Extract dependencies between entities."""
        dependencies = []
        
        # Connect processes to network connections
        for i, conn in enumerate(traces.get("network_connections", [])):
            if conn.get("pid") and conn.get("remote_address"):
                process_id = f"process_{conn.get('pid', '')}"
                network_id = f"network_{i}"
                
                if process_id in entities and network_id in entities:
                    dependencies.append((process_id, network_id, "connects_to"))
                    
        # Connect processes to file system events
        for i, file_event in enumerate(traces.get("file_system_events", [])):
            if file_event.get("pid"):
                process_id = f"process_{file_event.get('pid', '')}"
                file_id = f"file_{i}"
                
                if process_id in entities and file_id in entities:
                    dependencies.append((process_id, file_id, file_event.get("operation", "accesses")))
                    
        # Connect processes to registry events
        for i, reg_event in enumerate(traces.get("registry_events", [])):
            if reg_event.get("pid"):
                process_id = f"process_{reg_event.get('pid', '')}"
                registry_id = f"registry_{i}"
                
                if process_id in entities and registry_id in entities:
                    dependencies.append((process_id, registry_id, reg_event.get("operation", "modifies")))
                    
        return dependencies
        
    def identify_techniques(self) -> List[Dict[str, Any]]:
        """Identify attack techniques from the graph."""
        techniques = []
        
        # Find techniques based on process patterns
        process_techniques = self._identify_process_techniques()
        techniques.extend(process_techniques)
        
        # Find techniques based on network patterns
        network_techniques = self._identify_network_techniques()
        techniques.extend(network_techniques)
        
        # Find techniques based on file patterns
        file_techniques = self._identify_file_techniques()
        techniques.extend(file_techniques)
        
        # Find techniques based on registry patterns
        registry_techniques = self._identify_registry_techniques()
        techniques.extend(registry_techniques)
        
        # Find techniques based on behavior patterns
        behavior_techniques = self._identify_behavior_techniques()
        techniques.extend(behavior_techniques)
        
        # Find command and control pattern
        c2_subgraph = self._find_command_and_control_pattern()
        if c2_subgraph:
            techniques.append({
                "technique_id": "T1071",
                "technique_name": "Command and Control",
                "confidence": 0.7,
                "subgraph": c2_subgraph,
                "entities": [node for node in c2_subgraph.nodes()]
            })
            
        # Find data exfiltration pattern
        exfil_subgraph = self._find_data_exfiltration_pattern()
        if exfil_subgraph:
            techniques.append({
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "confidence": 0.6,
                "subgraph": exfil_subgraph,
                "entities": [node for node in exfil_subgraph.nodes()]
            })
            
        return techniques
        
    def _identify_process_techniques(self) -> List[Dict[str, Any]]:
        """Identify techniques based on process patterns."""
        techniques = []
        process_patterns = self.attack_kg_mappings.get("process_patterns", {})
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process":
                process_name = node_data.get("name", "").lower()
                
                for pattern, technique_info in process_patterns.items():
                    if re.search(pattern.lower(), process_name):
                        technique_id, technique_name = technique_info
                        techniques.append({
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "confidence": 0.8,
                            "entities": [node_id]
                        })
                        
        return techniques
        
    def _identify_network_techniques(self) -> List[Dict[str, Any]]:
        """Identify techniques based on network patterns."""
        techniques = []
        network_patterns = self.attack_kg_mappings.get("network_patterns", {})
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "network":
                ip = node_data.get("ip", "")
                port = node_data.get("port", "")
                network_string = f"http://{ip}:{port}"
                
                for pattern, technique_info in network_patterns.items():
                    if re.search(pattern, network_string):
                        technique_id, technique_name = technique_info
                        techniques.append({
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "confidence": 0.7,
                            "entities": [node_id]
                        })
                        
        return techniques
        
    def _identify_file_techniques(self) -> List[Dict[str, Any]]:
        """Identify techniques based on file patterns."""
        techniques = []
        file_patterns = self.attack_kg_mappings.get("file_patterns", {})
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "file":
                file_path = node_data.get("path", "")
                
                for pattern, technique_info in file_patterns.items():
                    if re.search(pattern, file_path):
                        technique_id, technique_name = technique_info
                        techniques.append({
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "confidence": 0.7,
                            "entities": [node_id]
                        })
                        
        return techniques
        
    def _identify_registry_techniques(self) -> List[Dict[str, Any]]:
        """Identify techniques based on registry patterns."""
        techniques = []
        registry_patterns = self.attack_kg_mappings.get("registry_patterns", {})
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "registry":
                registry_key = node_data.get("key", "")
                
                for pattern, technique_info in registry_patterns.items():
                    if re.search(pattern, registry_key):
                        technique_id, technique_name = technique_info
                        techniques.append({
                            "technique_id": technique_id,
                            "technique_name": technique_name,
                            "confidence": 0.8,
                            "entities": [node_id]
                        })
                        
        return techniques
        
    def _identify_behavior_techniques(self) -> List[Dict[str, Any]]:
        """Identify techniques based on behavior patterns."""
        techniques = []
        behavior_patterns = self.attack_kg_mappings.get("behavior_patterns", {})
        
        # Check for high network traffic
        if self._has_high_network_traffic():
            technique_info = behavior_patterns.get("high_network_traffic")
            if technique_info:
                technique_id, technique_name = technique_info
                techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "confidence": 0.6,
                    "entities": []
                })
                
        # Check for unusual process relationships
        unusual_processes = self._find_unusual_process_relationships()
        if unusual_processes:
            technique_info = behavior_patterns.get("unusual_process_relationships")
            if technique_info:
                technique_id, technique_name = technique_info
                techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "confidence": 0.7,
                    "entities": unusual_processes
                })
                
        return techniques
        
    def _has_high_network_traffic(self) -> bool:
        """Check if there is high network traffic."""
        network_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("type") == "network"]
        return len(network_nodes) > 10
        
    def _find_unusual_process_relationships(self) -> List[str]:
        """Find unusual process relationships."""
        unusual_processes = []
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process":
                # Check if process has many connections
                if len(list(self.graph.out_edges(node_id))) > 5:
                    unusual_processes.append(node_id)
                    
        return unusual_processes
        
    def _find_command_and_control_pattern(self) -> Optional[nx.DiGraph]:
        """Find command and control pattern in the graph."""
        # Look for processes connecting to suspicious network entities
        c2_subgraph = nx.DiGraph()
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process":
                # Check outgoing connections
                for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                    target_data = self.graph.nodes[target]
                    
                    if (target_data.get("type") == "network" and 
                        edge_data.get("type") == "connects_to"):
                        # Add to C2 subgraph
                        c2_subgraph.add_node(node_id, **node_data)
                        c2_subgraph.add_node(target, **target_data)
                        c2_subgraph.add_edge(node_id, target, **edge_data)
                        
        return c2_subgraph if c2_subgraph.number_of_nodes() > 0 else None
        
    def _find_data_exfiltration_pattern(self) -> Optional[nx.DiGraph]:
        """Find data exfiltration pattern in the graph."""
        # Look for processes with high network activity
        exfil_subgraph = nx.DiGraph()
        
        for node in self.graph.nodes(data=True):
            node_id, node_data = node
            
            if node_data.get("type") == "process":
                # Count outgoing connections
                outgoing_connections = list(self.graph.out_edges(node_id, data=True))
                
                if len(outgoing_connections) > 3:  # Threshold for suspicious activity
                    # Add to exfiltration subgraph
                    exfil_subgraph.add_node(node_id, **node_data)
                    
                    for _, target, edge_data in outgoing_connections:
                        target_data = self.graph.nodes[target]
                        exfil_subgraph.add_node(target, **target_data)
                        exfil_subgraph.add_edge(node_id, target, **edge_data)
                        
        return exfil_subgraph if exfil_subgraph.number_of_nodes() > 0 else None
