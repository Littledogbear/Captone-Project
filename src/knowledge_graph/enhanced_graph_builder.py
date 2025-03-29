"""
Enhanced knowledge graph builder for comprehensive malware behavior visualization.
"""
import networkx as nx
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

class EnhancedGraphBuilder:
    """Builds comprehensive knowledge graphs from attack traces with all node types."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()
        
    def build_graph_from_traces(self, traces: List[Dict[str, Any]]) -> nx.DiGraph:
        """Build a knowledge graph from attack traces."""
        try:
            self.graph = nx.DiGraph()
            
            for event in traces:
                event_type = event.get("type")
                
                if event_type == "process":
                    self._process_process_event(event)
                elif event_type == "file":
                    self._process_file_event(event)
                elif event_type == "network":
                    self._process_network_event(event)
                elif event_type == "registry":
                    self._process_registry_event(event)
            
            self._create_edges(traces)
            
            return self.graph
        except Exception as e:
            self.logger.error(f"Error building knowledge graph: {str(e)}")
            return nx.DiGraph()
    
    def _process_process_event(self, event: Dict[str, Any]):
        """Process a process event."""
        pid = event.get("pid")
        if not pid:
            return
            
        node_id = f"process_{pid}"
        
        self.graph.add_node(
            node_id,
            type="process",
            pid=pid,
            name=event.get("name", ""),
            command_line=event.get("command_line", ""),
            parent_pid=event.get("parent_pid"),
            timestamp=event.get("timestamp", ""),
            operation=event.get("operation", "")
        )
        
        if event.get("parent_pid"):
            parent_node_id = f"process_{event.get('parent_pid')}"
            if parent_node_id in self.graph:
                self.graph.add_edge(
                    parent_node_id,
                    node_id,
                    operation="creates",
                    timestamp=event.get("timestamp", "")
                )
        
        if event.get("injected_by"):
            injector_node_id = f"process_{event.get('injected_by')}"
            if injector_node_id in self.graph:
                self.graph.add_edge(
                    injector_node_id,
                    node_id,
                    operation="injects",
                    technique=event.get("technique", ""),
                    timestamp=event.get("timestamp", "")
                )
    
    def _process_file_event(self, event: Dict[str, Any]):
        """Process a file event."""
        path = event.get("path")
        if not path:
            return
            
        node_id = path
        
        self.graph.add_node(
            node_id,
            type="file",
            path=path,
            timestamp=event.get("timestamp", ""),
            operation=event.get("operation", "")
        )
        
        if event.get("process_id"):
            process_node_id = f"process_{event.get('process_id')}"
            if process_node_id in self.graph:
                operation = event.get("operation", "")
                edge_operation = {
                    "read": "reads",
                    "write": "writes",
                    "delete": "deletes",
                    "encrypt": "encrypts",
                    "execute": "executes"
                }.get(operation, "accesses")
                
                self.graph.add_edge(
                    process_node_id,
                    node_id,
                    operation=edge_operation,
                    timestamp=event.get("timestamp", "")
                )
    
    def _process_network_event(self, event: Dict[str, Any]):
        """Process a network event."""
        destination = event.get("destination")
        port = event.get("port")
        if not destination or not port:
            return
            
        node_id = f"network_{destination}_{port}"
        
        self.graph.add_node(
            node_id,
            type="network",
            destination=destination,
            port=port,
            protocol=event.get("protocol", ""),
            timestamp=event.get("timestamp", "")
        )
        
        if event.get("process_id"):
            process_node_id = f"process_{event.get('process_id')}"
            if process_node_id in self.graph:
                operation = event.get("operation", "")
                edge_operation = {
                    "connect": "connects",
                    "send": "sends_data",
                    "receive": "receives_data",
                    "scan": "scans"
                }.get(operation, "connects")
                
                self.graph.add_edge(
                    process_node_id,
                    node_id,
                    operation=edge_operation,
                    timestamp=event.get("timestamp", "")
                )
    
    def _process_registry_event(self, event: Dict[str, Any]):
        """Process a registry event."""
        key = event.get("key")
        if not key:
            return
            
        node_id = key
        
        self.graph.add_node(
            node_id,
            type="registry",
            key=key,
            value=event.get("value", ""),
            timestamp=event.get("timestamp", ""),
            operation=event.get("operation", "")
        )
        
        if event.get("process_id"):
            process_node_id = f"process_{event.get('process_id')}"
            if process_node_id in self.graph:
                operation = event.get("operation", "")
                edge_operation = {
                    "read": "reads",
                    "write": "writes",
                    "delete": "deletes"
                }.get(operation, "modifies")
                
                self.graph.add_edge(
                    process_node_id,
                    node_id,
                    operation=edge_operation,
                    timestamp=event.get("timestamp", "")
                )
    
    def _create_edges(self, traces: List[Dict[str, Any]]):
        """Create additional edges between nodes based on relationships."""
        for event in traces:
            pass
    
    def identify_techniques(self) -> Dict[str, Any]:
        """Identify attack techniques in the knowledge graph."""
        techniques = {}
        
        if self._has_command_and_control():
            techniques["T1071"] = {
                "name": "Command and Control",
                "confidence": 0.8,
                "description": "The malware establishes command and control communications with remote servers."
            }
        
        if self._has_data_exfiltration():
            techniques["T1048"] = {
                "name": "Exfiltration Over Alternative Protocol",
                "confidence": 0.7,
                "description": "The malware exfiltrates data to remote servers."
            }
        
        if self._has_persistence():
            techniques["T1547"] = {
                "name": "Boot or Logon Autostart Execution",
                "confidence": 0.75,
                "description": "The malware establishes persistence through registry or startup folder modifications."
            }
        
        if self._has_process_injection():
            techniques["T1055"] = {
                "name": "Process Injection",
                "confidence": 0.85,
                "description": "The malware injects code into other processes to evade detection or gain privileges."
            }
        
        if self._has_file_encryption():
            techniques["T1486"] = {
                "name": "Data Encrypted for Impact",
                "confidence": 0.9,
                "description": "The malware encrypts files on the system, potentially for ransomware purposes."
            }
        
        if self._has_defense_evasion():
            techniques["T1112"] = {
                "name": "Modify Registry",
                "confidence": 0.7,
                "description": "The malware modifies registry settings to evade defenses or maintain persistence."
            }
        
        return techniques
    
    def _has_command_and_control(self) -> bool:
        """Check if the graph has command and control behavior."""
        for node in self.graph.nodes():
            if self.graph.nodes[node].get("type") == "network":
                for pred in self.graph.predecessors(node):
                    if self.graph.nodes[pred].get("type") == "process":
                        return True
        return False
    
    def _has_data_exfiltration(self) -> bool:
        """Check if the graph has data exfiltration behavior."""
        for u, v, data in self.graph.edges(data=True):
            if (self.graph.nodes[u].get("type") == "process" and 
                self.graph.nodes[v].get("type") == "network" and 
                data.get("operation") == "sends_data"):
                return True
        return False
    
    def _has_persistence(self) -> bool:
        """Check if the graph has persistence behavior."""
        for node in self.graph.nodes():
            if self.graph.nodes[node].get("type") == "registry":
                key = self.graph.nodes[node].get("key", "")
                if "Run" in key or "Startup" in key:
                    return True
            elif self.graph.nodes[node].get("type") == "file":
                path = self.graph.nodes[node].get("path", "")
                if "Startup" in path or "Start Menu" in path:
                    return True
        return False
    
    def _has_process_injection(self) -> bool:
        """Check if the graph has process injection behavior."""
        for u, v, data in self.graph.edges(data=True):
            if data.get("operation") == "injects":
                return True
        
        for node in self.graph.nodes():
            if (self.graph.nodes[node].get("type") == "process" and 
                self.graph.nodes[node].get("injected_by")):
                return True
        return False
    
    def _has_file_encryption(self) -> bool:
        """Check if the graph has file encryption behavior."""
        for u, v, data in self.graph.edges(data=True):
            if data.get("operation") == "encrypts":
                return True
        return False
    
    def _has_defense_evasion(self) -> bool:
        """Check if the graph has defense evasion behavior."""
        for node in self.graph.nodes():
            if self.graph.nodes[node].get("type") == "registry":
                key = self.graph.nodes[node].get("key", "")
                if "Windows Defender" in key or "Security" in key:
                    return True
        return False
