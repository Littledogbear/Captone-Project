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
            
    def build_graph(self, data: Dict[str, Any]) -> nx.DiGraph:
        """
        Build a knowledge graph from the provided data.
        
        This is an alias for build_graph_from_traces to maintain compatibility
        with the test_dashboard_with_malware.py script.
        
        Args:
            data: Dictionary containing trace data
            
        Returns:
            NetworkX DiGraph object representing the knowledge graph
        """
        self.graph = nx.DiGraph()
        
        if 'processes' in data and isinstance(data['processes'], list):
            for process in data['processes']:
                pid = process.get('pid')
                if pid:
                    node_id = f"process_{pid}"
                    self.graph.add_node(
                        node_id,
                        type="process",
                        pid=pid,
                        name=process.get("name", ""),
                        path=process.get("path", ""),
                        parent=process.get("parent")
                    )
        
        if 'network_connections' in data and isinstance(data['network_connections'], list):
            for conn in data['network_connections']:
                pid = conn.get('pid')
                remote_addr = conn.get('remote_addr')
                remote_port = conn.get('remote_port')
                if pid and remote_addr and remote_port:
                    node_id = f"network_{remote_addr}_{remote_port}"
                    self.graph.add_node(
                        node_id,
                        type="network",
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        local_addr=conn.get('local_addr', ''),
                        local_port=conn.get('local_port', '')
                    )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph:
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation="connects"
                        )
        
        if 'file_operations' in data and isinstance(data['file_operations'], list):
            for file_op in data['file_operations']:
                pid = file_op.get('pid')
                path = file_op.get('path')
                operation = file_op.get('operation', '')
                if pid and path:
                    node_id = f"file_{path}"
                    self.graph.add_node(
                        node_id,
                        type="file",
                        path=path,
                        operation=operation
                    )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph:
                        edge_operation = {
                            "create": "creates",
                            "modify": "modifies",
                            "delete": "deletes",
                            "encrypt": "encrypts",
                            "read": "reads",
                            "write": "writes"
                        }.get(operation, "accesses")
                        
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation=edge_operation
                        )
        
        if 'registry_operations' in data and isinstance(data['registry_operations'], list):
            for reg_op in data['registry_operations']:
                pid = reg_op.get('pid')
                key = reg_op.get('key')
                operation = reg_op.get('operation', '')
                if pid and key:
                    node_id = f"registry_{key}"
                    self.graph.add_node(
                        node_id,
                        type="registry",
                        key=key,
                        value=reg_op.get('value', ''),
                        data=reg_op.get('data', '')
                    )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph:
                        edge_operation = {
                            "set": "sets",
                            "delete": "deletes",
                            "read": "reads"
                        }.get(operation, "modifies")
                        
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation=edge_operation
                        )
        
        for node in list(self.graph.nodes()):
            if self.graph.nodes[node].get('type') == 'process':
                parent = self.graph.nodes[node].get('parent')
                if parent:
                    parent_node_id = f"process_{parent}"
                    if parent_node_id in self.graph:
                        self.graph.add_edge(
                            parent_node_id,
                            node,
                            operation="spawns"
                        )
        
        return self.graph
        
    def add_to_graph(self, data: Dict[str, Any]) -> nx.DiGraph:
        """
        Add data to an existing knowledge graph.
        
        Args:
            data: Dictionary containing trace data
            
        Returns:
            NetworkX DiGraph object representing the updated knowledge graph
        """
        if 'processes' in data and isinstance(data['processes'], list):
            for process in data['processes']:
                pid = process.get('pid')
                if pid:
                    node_id = f"process_{pid}"
                    if node_id not in self.graph:
                        self.graph.add_node(
                            node_id,
                            type="process",
                            pid=pid,
                            name=process.get("name", ""),
                            path=process.get("path", ""),
                            parent=process.get("parent")
                        )
        
        if 'network_connections' in data and isinstance(data['network_connections'], list):
            for conn in data['network_connections']:
                pid = conn.get('pid')
                remote_addr = conn.get('remote_addr')
                remote_port = conn.get('remote_port')
                if pid and remote_addr and remote_port:
                    node_id = f"network_{remote_addr}_{remote_port}"
                    if node_id not in self.graph:
                        self.graph.add_node(
                            node_id,
                            type="network",
                            remote_addr=remote_addr,
                            remote_port=remote_port,
                            local_addr=conn.get('local_addr', ''),
                            local_port=conn.get('local_port', '')
                        )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph and not self.graph.has_edge(process_node_id, node_id):
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation="connects"
                        )
        
        if 'file_operations' in data and isinstance(data['file_operations'], list):
            for file_op in data['file_operations']:
                pid = file_op.get('pid')
                path = file_op.get('path')
                operation = file_op.get('operation', '')
                if pid and path:
                    node_id = f"file_{path}"
                    if node_id not in self.graph:
                        self.graph.add_node(
                            node_id,
                            type="file",
                            path=path,
                            operation=operation
                        )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph and not self.graph.has_edge(process_node_id, node_id):
                        edge_operation = {
                            "create": "creates",
                            "modify": "modifies",
                            "delete": "deletes",
                            "encrypt": "encrypts",
                            "read": "reads",
                            "write": "writes"
                        }.get(operation, "accesses")
                        
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation=edge_operation
                        )
        
        if 'registry_operations' in data and isinstance(data['registry_operations'], list):
            for reg_op in data['registry_operations']:
                pid = reg_op.get('pid')
                key = reg_op.get('key')
                operation = reg_op.get('operation', '')
                if pid and key:
                    node_id = f"registry_{key}"
                    if node_id not in self.graph:
                        self.graph.add_node(
                            node_id,
                            type="registry",
                            key=key,
                            value=reg_op.get('value', ''),
                            data=reg_op.get('data', '')
                        )
                    
                    process_node_id = f"process_{pid}"
                    if process_node_id in self.graph and not self.graph.has_edge(process_node_id, node_id):
                        edge_operation = {
                            "set": "sets",
                            "delete": "deletes",
                            "read": "reads"
                        }.get(operation, "modifies")
                        
                        self.graph.add_edge(
                            process_node_id,
                            node_id,
                            operation=edge_operation
                        )
        
        for node in list(self.graph.nodes()):
            if self.graph.nodes[node].get('type') == 'process':
                parent = self.graph.nodes[node].get('parent')
                if parent:
                    parent_node_id = f"process_{parent}"
                    if parent_node_id in self.graph and not self.graph.has_edge(parent_node_id, node):
                        self.graph.add_edge(
                            parent_node_id,
                            node,
                            operation="spawns"
                        )
        
        return self.graph
    
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
        process_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'process']
        file_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'file']
        network_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'network']
        registry_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'registry']
        
        self.logger.info(f"Creating additional edges between {len(process_nodes)} processes, {len(file_nodes)} files, "
                         f"{len(network_nodes)} network connections, and {len(registry_nodes)} registry keys")
        
        for proc_node in process_nodes:
            proc_name = self.graph.nodes[proc_node].get('name', '').lower()
            
            for file_node in file_nodes:
                file_path = self.graph.nodes[file_node].get('path', '').lower()
                
                if not self.graph.has_edge(proc_node, file_node):
                    if proc_name and proc_name in file_path:
                        self.graph.add_edge(proc_node, file_node, operation="accesses")
                    
                    if any(ext in file_path for ext in ['.dll', '.exe', '.sys']):
                        if any(keyword in proc_name for keyword in ['malware', 'trojan', 'virus']):
                            self.graph.add_edge(proc_node, file_node, operation="creates")
        
        for proc_node in process_nodes:
            proc_name = self.graph.nodes[proc_node].get('name', '').lower()
            
            for net_node in network_nodes:
                if not self.graph.has_edge(proc_node, net_node):
                    destination = self.graph.nodes[net_node].get('destination', '')
                    port = self.graph.nodes[net_node].get('port', '')
                    
                    if port in ['443', '8080', '1443', '4444', '8081']:
                        self.graph.add_edge(proc_node, net_node, operation="connects")
                    
                    if destination and any(c.isdigit() for c in destination):
                        self.graph.add_edge(proc_node, net_node, operation="connects")
        
        for proc_node in process_nodes:
            for reg_node in registry_nodes:
                if not self.graph.has_edge(proc_node, reg_node):
                    key = self.graph.nodes[reg_node].get('key', '').lower()
                    
                    if any(pattern in key for pattern in ['run', 'startup', 'boot', 'services']):
                        self.graph.add_edge(proc_node, reg_node, operation="modifies")
        
        for proc_node in process_nodes:
            parent_pid = self.graph.nodes[proc_node].get('parent_pid')
            
            if parent_pid:
                parent_node_id = f"process_{parent_pid}"
                
                if parent_node_id in self.graph and not self.graph.has_edge(parent_node_id, proc_node):
                    self.graph.add_edge(parent_node_id, proc_node, operation="spawns")
        
        self._add_malware_specific_edges(process_nodes, file_nodes, network_nodes, registry_nodes)
    
    def _add_malware_specific_edges(self, process_nodes, file_nodes, network_nodes, registry_nodes):
        """Add edges specific to common malware behaviors."""
        malware_processes = []
        for proc_node in process_nodes:
            proc_name = self.graph.nodes[proc_node].get('name', '').lower()
            cmd_line = self.graph.nodes[proc_node].get('command_line', '').lower()
            
            if any(keyword in proc_name for keyword in ['svc', 'host', 'system', 'explorer']):
                if any(susp in cmd_line for susp in ['-e', '/c', 'powershell', 'cmd.exe', 'rundll32']):
                    malware_processes.append(proc_node)
        
        for proc_node in malware_processes:
            for net_node in network_nodes:
                if not self.graph.has_edge(proc_node, net_node):
                    self.graph.add_edge(proc_node, net_node, operation="connects")
            
            for reg_node in registry_nodes:
                key = self.graph.nodes[reg_node].get('key', '').lower()
                if 'run' in key or 'startup' in key:
                    if not self.graph.has_edge(proc_node, reg_node):
                        self.graph.add_edge(proc_node, reg_node, operation="modifies")
            
            for file_node in file_nodes:
                path = self.graph.nodes[file_node].get('path', '').lower()
                if any(ext in path for ext in ['.doc', '.pdf', '.xls', '.txt', '.zip']):
                    if not self.graph.has_edge(proc_node, file_node):
                        self.graph.add_edge(proc_node, file_node, operation="accesses")
    
    def generate_relationship_edges(self):
        """Generate relationship edges between related nodes."""
        try:
            self.logger.info("Generating relationship edges between nodes")
            
            process_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'process']
            file_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'file']
            network_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'network']
            registry_nodes = [n for n in self.graph.nodes() if self.graph.nodes[n].get('type') == 'registry']
            
            self.logger.info(f"Found {len(process_nodes)} processes, {len(file_nodes)} files, "
                            f"{len(network_nodes)} network connections, and {len(registry_nodes)} registry keys")
            
            for proc_node in process_nodes:
                proc_name = self.graph.nodes[proc_node].get('name', '').lower()
                
                for file_node in file_nodes:
                    file_path = self.graph.nodes[file_node].get('path', '').lower()
                    
                    if not self.graph.has_edge(proc_node, file_node):
                        if proc_name and proc_name in file_path:
                            self.graph.add_edge(proc_node, file_node, operation="related_to")
                        
                        if any(ext in file_path for ext in ['.dll', '.exe', '.sys']):
                            if any(keyword in proc_name for keyword in ['malware', 'trojan', 'virus', 'sample']):
                                self.graph.add_edge(proc_node, file_node, operation="related_to")
            
            for proc_node in process_nodes:
                for net_node in network_nodes:
                    if not self.graph.has_edge(proc_node, net_node):
                        port = self.graph.nodes[net_node].get('remote_port', '')
                        if port in ['443', '8080', '1443', '4444', '8081']:
                            self.graph.add_edge(proc_node, net_node, operation="potentially_connects_to")
            
            for proc_node in process_nodes:
                for reg_node in registry_nodes:
                    if not self.graph.has_edge(proc_node, reg_node):
                        key = self.graph.nodes[reg_node].get('key', '').lower()
                        
                        if any(pattern in key for pattern in ['run', 'startup', 'boot', 'services']):
                            self.graph.add_edge(proc_node, reg_node, operation="potentially_modifies")
            
            for proc1 in process_nodes:
                for proc2 in process_nodes:
                    if proc1 != proc2 and not self.graph.has_edge(proc1, proc2) and not self.graph.has_edge(proc2, proc1):
                        proc1_files = [n for n in self.graph.successors(proc1) 
                                    if self.graph.nodes[n].get('type') == 'file']
                        proc2_files = [n for n in self.graph.successors(proc2) 
                                    if self.graph.nodes[n].get('type') == 'file']
                        
                        common_files = set(proc1_files).intersection(set(proc2_files))
                        if common_files:
                            self.graph.add_edge(proc1, proc2, operation="shares_resources_with")
                        
                        proc1_nets = [n for n in self.graph.successors(proc1) 
                                    if self.graph.nodes[n].get('type') == 'network']
                        proc2_nets = [n for n in self.graph.successors(proc2) 
                                    if self.graph.nodes[n].get('type') == 'network']
                        
                        common_nets = set(proc1_nets).intersection(set(proc2_nets))
                        if common_nets:
                            self.graph.add_edge(proc1, proc2, operation="shares_connections_with")
            
            for file1 in file_nodes:
                for file2 in file_nodes:
                    if file1 != file2 and not self.graph.has_edge(file1, file2) and not self.graph.has_edge(file2, file1):
                        file1_procs = [n for n in self.graph.predecessors(file1) 
                                    if self.graph.nodes[n].get('type') == 'process']
                        file2_procs = [n for n in self.graph.predecessors(file2) 
                                    if self.graph.nodes[n].get('type') == 'process']
                        
                        common_procs = set(file1_procs).intersection(set(file2_procs))
                        if common_procs:
                            self.graph.add_edge(file1, file2, operation="related_to")
            
            for net1 in network_nodes:
                for net2 in network_nodes:
                    if net1 != net2 and not self.graph.has_edge(net1, net2) and not self.graph.has_edge(net2, net1):
                        net1_procs = [n for n in self.graph.predecessors(net1) 
                                    if self.graph.nodes[n].get('type') == 'process']
                        net2_procs = [n for n in self.graph.predecessors(net2) 
                                    if self.graph.nodes[n].get('type') == 'process']
                        
                        common_procs = set(net1_procs).intersection(set(net2_procs))
                        if common_procs:
                            self.graph.add_edge(net1, net2, operation="related_to")
            
            edge_count = self.graph.number_of_edges()
            self.logger.info(f"Generated relationship edges. Graph now has {edge_count} edges.")
            
            return self.graph
        except Exception as e:
            self.logger.error(f"Error generating relationship edges: {str(e)}")
            return self.graph
    
    def identify_techniques(self) -> Dict[str, Any]:
        """Identify attack techniques in the knowledge graph."""
        techniques = {}
        
        if self._has_command_and_control():
            techniques["T1071"] = {
                "name": "Command and Control",
                "confidence": 80,
                "description": "The malware establishes command and control communications with remote servers."
            }
        
        if self._has_data_exfiltration():
            techniques["T1048"] = {
                "name": "Exfiltration Over Alternative Protocol",
                "confidence": 70,
                "description": "The malware exfiltrates data to remote servers."
            }
        
        if self._has_persistence():
            techniques["T1547"] = {
                "name": "Boot or Logon Autostart Execution",
                "confidence": 75,
                "description": "The malware establishes persistence through registry or startup folder modifications."
            }
        
        if self._has_process_injection():
            techniques["T1055"] = {
                "name": "Process Injection",
                "confidence": 85,
                "description": "The malware injects code into other processes to evade detection or gain privileges."
            }
        
        if self._has_file_encryption():
            techniques["T1486"] = {
                "name": "Data Encrypted for Impact",
                "confidence": 90,
                "description": "The malware encrypts files on the system, potentially for ransomware purposes."
            }
        
        if self._has_defense_evasion():
            techniques["T1112"] = {
                "name": "Modify Registry",
                "confidence": 70,
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
        
    def export_graph(self, output_path: str) -> str:
        """
        Export the graph to a JSON file.
        
        Args:
            output_path: Path to save the JSON file
            
        Returns:
            Path to the saved JSON file
        """
        import json
        
        try:
            nodes = []
            edges = []
            
            for node_id, attrs in self.graph.nodes(data=True):
                node_type = attrs.get('type', 'unknown')
                
                if node_type == 'process':
                    label = attrs.get('name', str(node_id))
                    color = "#FF5733"  # Red for processes
                elif node_type == 'file':
                    label = attrs.get('path', str(node_id)).split('\\')[-1] if '\\' in attrs.get('path', '') else attrs.get('path', str(node_id)).split('/')[-1]
                    color = "#33FF57"  # Green for files
                elif node_type == 'network':
                    label = f"{attrs.get('remote_addr', '')}:{attrs.get('remote_port', '')}"
                    color = "#3357FF"  # Blue for network
                elif node_type == 'registry':
                    label = attrs.get('key', str(node_id)).split('\\')[-1] if '\\' in attrs.get('key', '') else attrs.get('key', str(node_id)).split('/')[-1]
                    color = "#FF33F5"  # Purple for registry
                else:
                    label = str(node_id)
                    color = "#AAAAAA"  # Gray for unknown
                
                nodes.append({
                    'id': str(node_id),
                    'label': label,
                    'type': node_type,
                    'color': color,
                    'data': {k: v for k, v in attrs.items() if k not in ['type']}
                })
            
            for source, target, attrs in self.graph.edges(data=True):
                edge_type = attrs.get('operation', 'unknown')
                
                edges.append({
                    'id': f"{source}_{target}",
                    'source': str(source),
                    'target': str(target),
                    'label': edge_type,
                    'type': edge_type,
                    'arrows': 'to'
                })
            
            graph_data = {
                'nodes': nodes,
                'edges': edges
            }
            
            with open(output_path, 'w') as f:
                json.dump(graph_data, f, indent=2)
            
            self.logger.info(f"Graph exported to {output_path}")
            return output_path
        
        except Exception as e:
            self.logger.error(f"Error exporting graph: {str(e)}")
            return ""
