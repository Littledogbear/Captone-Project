import networkx as nx
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

class KnowledgeGraphBuilder:
    """Builds knowledge graphs from attack traces based on AttacKG approach."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()
        
    def build_graph_from_traces(self, traces: Dict[str, Any]) -> nx.DiGraph:
        """Build a knowledge graph from attack traces."""
        try:
            # Extract entities
            entities = self._extract_entities(traces)
            
            # Add entities to graph
            for entity in entities:
                self.graph.add_node(entity["id"], **entity)
                
            # Extract dependencies
            dependencies = self._extract_dependencies(traces, entities)
            
            # Add dependencies to graph
            for dep in dependencies:
                self.graph.add_edge(dep["source"], dep["target"], **dep)
                
            return self.graph
        except Exception as e:
            self.logger.error("Error building knowledge graph: %s", str(e))
            return nx.DiGraph()
            
    def _extract_entities(self, traces: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract entities from traces."""
        entities = []
        
        # Extract process entities
        for process in traces.get("processes", []):
            entities.append({
                "id": f"process_{process['pid']}",
                "type": "process",
                "name": process["name"],
                "pid": process["pid"],
                "username": process.get("username", ""),
                "cpu_usage": process.get("cpu_usage", 0),
                "memory_usage": process.get("memory_usage", 0)
            })
            
        # Extract network entities
        for conn in traces.get("network_connections", []):
            if conn.get("remote_address"):
                entities.append({
                    "id": f"network_{conn['remote_address'].get('ip', '')}_{conn['remote_address'].get('port', '')}",
                    "type": "network",
                    "ip": conn['remote_address'].get('ip', ''),
                    "port": conn['remote_address'].get('port', ''),
                    "status": conn.get("status", "")
                })
                
        return entities
        
    def _extract_dependencies(self, traces: Dict[str, Any], entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract dependencies between entities."""
        dependencies = []
        
        # Map PIDs to entity IDs
        pid_to_id = {entity["pid"]: entity["id"] for entity in entities if "pid" in entity}
        
        # Extract process-network dependencies
        for conn in traces.get("network_connections", []):
            if conn.get("pid") and conn.get("remote_address"):
                source_id = pid_to_id.get(conn["pid"])
                target_id = f"network_{conn['remote_address'].get('ip', '')}_{conn['remote_address'].get('port', '')}"
                
                if source_id and target_id:
                    dependencies.append({
                        "source": source_id,
                        "target": target_id,
                        "type": "connects_to",
                        "timestamp": traces.get("timestamp", "")
                    })
                    
        return dependencies
        
    def identify_techniques(self) -> List[Dict[str, Any]]:
        """Identify attack techniques in the knowledge graph."""
        techniques = []
        
        # Identify command and control technique
        c2_subgraph = self._find_command_and_control_pattern()
        if c2_subgraph:
            techniques.append({
                "technique_id": "T1071",
                "technique_name": "Command and Control",
                "confidence": 0.8,
                "entities": list(c2_subgraph.nodes()),
                "dependencies": list(c2_subgraph.edges())
            })
            
        # Identify data exfiltration technique
        exfil_subgraph = self._find_data_exfiltration_pattern()
        if exfil_subgraph:
            techniques.append({
                "technique_id": "T1048",
                "technique_name": "Exfiltration Over Alternative Protocol",
                "confidence": 0.7,
                "entities": list(exfil_subgraph.nodes()),
                "dependencies": list(exfil_subgraph.edges())
            })
            
        return techniques
        
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
