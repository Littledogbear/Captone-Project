import os
import json
import logging
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from jinja2 import Environment, FileSystemLoader
import base64
from io import BytesIO

class ReportGenerator:
    """Generates comprehensive reports from cyber attack analysis."""
    
    def __init__(self, output_dir: str = "", template_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "reports"
        )
        self.template_dir = template_dir or os.path.join(
            os.path.dirname(__file__), "templates"
        )
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
    def generate_report(self, analysis_data, output_file: str = "", report_type: str = "html") -> str:
        """
        Generate a report from analysis data.
        
        Args:
            analysis_data: Dictionary containing analysis data or string
            output_file: Optional path to save the report to
            report_type: Type of report to generate (html, json, or comprehensive)
            
        Returns:
            Path to the generated report
        """
        try:
            if isinstance(analysis_data, str):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                
                if output_file:
                    report_path = output_file
                    os.makedirs(os.path.dirname(output_file), exist_ok=True)
                else:
                    report_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
                
                with open(report_path, "w") as f:
                    f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Simple Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Report Generated at {timestamp}</h1>
    <p>{analysis_data}</p>
</body>
</html>""")
                
                return report_path
            
            # Generate timestamp for report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Process analysis data
            processed_data = self._process_analysis_data(analysis_data)
            
            # Generate visualizations
            visualizations = self._generate_visualizations(analysis_data)
            
            # Generate improvement suggestions
            suggestions = self._generate_improvement_suggestions(analysis_data)
            
            # Combine all data for the report
            report_data = {
                "timestamp": timestamp,
                "analysis_data": processed_data,
                "visualizations": visualizations,
                "suggestions": suggestions
            }
            
            # Generate report based on type
            if report_type == "html" or report_type == "comprehensive":
                return self._generate_html_report(report_data, timestamp, output_file)
            elif report_type == "json":
                return self._generate_json_report(report_data, timestamp, output_file)
            else:
                self.logger.error(f"Unsupported report type: {report_type}")
                return ""
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return ""
            
    def _process_analysis_data(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process and structure analysis data for the report."""
        if isinstance(analysis_data, str):
            return {
                "summary": {
                    "scan_time": datetime.now().isoformat(),
                    "threat_level": "UNKNOWN",
                    "total_processes": 0,
                    "total_network_connections": 0,
                    "total_file_events": 0,
                    "total_registry_events": 0
                },
                "malware_analysis": [],
                "attack_techniques": [],
                "system_activity": {
                    "processes": [],
                    "network": [],
                    "file_system": [],
                    "registry": []
                }
            }
            
        processed_data = {
            "summary": {
                "scan_time": analysis_data.get("timestamp", datetime.now().isoformat()),
                "threat_level": self._determine_overall_threat_level(analysis_data),
                "total_processes": len(analysis_data.get("processes", [])),
                "total_network_connections": len(analysis_data.get("network_connections", [])),
                "total_file_events": len(analysis_data.get("file_system_events", [])),
                "total_registry_events": len(analysis_data.get("registry_events", []))
            },
            "malware_analysis": self._process_malware_analysis(analysis_data),
            "attack_techniques": self._process_attack_techniques(analysis_data),
            "system_activity": {
                "processes": self._process_processes(analysis_data.get("processes", [])),
                "network": self._process_network_connections(analysis_data.get("network_connections", [])),
                "file_system": analysis_data.get("file_system_events", []),
                "registry": analysis_data.get("registry_events", [])
            }
        }
        
        if "ai_analysis" in analysis_data:
            ai_analysis = analysis_data["ai_analysis"]
            if isinstance(ai_analysis, dict):
                processed_data["ai_analysis"] = ai_analysis
            else:
                processed_data["ai_analysis"] = {"summary": str(ai_analysis)}
        
        if "ioc_analysis" in analysis_data:
            ioc_analysis = analysis_data["ioc_analysis"]
            if isinstance(ioc_analysis, dict):
                processed_data["ioc_analysis"] = ioc_analysis
            else:
                processed_data["ioc_analysis"] = {"summary": str(ioc_analysis)}
        
        return processed_data
        
    def _determine_overall_threat_level(self, analysis_data) -> str:
        """Determine the overall threat level from analysis data."""
        if isinstance(analysis_data, str):
            return "UNKNOWN"
            
        # Check for explicit threat level in AI analysis
        ai_threat_level = analysis_data.get("ai_analysis", {}).get("threat_assessment", {}).get("threat_level", "")
        if ai_threat_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            return ai_threat_level
            
        # Check for malware analysis results
        malware_results = analysis_data.get("malware_analysis", {})
        if malware_results:
            if isinstance(malware_results, dict):
                severity_levels = [result.get("severity", "UNKNOWN") for result in malware_results.values()]
            elif isinstance(malware_results, list):
                severity_levels = [result.get("severity", "UNKNOWN") for result in malware_results]
            else:
                severity_levels = []
                
            if "CRITICAL" in severity_levels:
                return "CRITICAL"
            elif "HIGH" in severity_levels:
                return "HIGH"
            elif "MEDIUM" in severity_levels:
                return "MEDIUM"
            elif "LOW" in severity_levels:
                return "LOW"
                
        # Check for attack techniques
        techniques = analysis_data.get("techniques", [])
        if techniques:
            confidence_levels = [technique.get("confidence", 0) for technique in techniques]
            avg_confidence = sum(confidence_levels) / len(confidence_levels) if confidence_levels else 0
            
            if avg_confidence > 0.8:
                return "HIGH"
            elif avg_confidence > 0.6:
                return "MEDIUM"
            elif avg_confidence > 0.3:
                return "LOW"
                
        # Default to LOW if no other indicators
        return "LOW"
        
    def _process_malware_analysis(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process malware analysis results."""
        malware_results = []
        
        if "malware_analysis" in analysis_data:
            malware_analysis = analysis_data.get("malware_analysis", [])
            if isinstance(malware_analysis, list):
                for sample in malware_analysis:
                    if isinstance(sample, dict):
                        malware_results.append(sample)
                    elif isinstance(sample, str):
                        malware_results.append({
                            "file": sample,
                            "classification": "unknown",
                            "severity": "UNKNOWN",
                            "description": "No detailed information available"
                        })
                return malware_results
            elif isinstance(malware_analysis, dict):
                for file_name, sample_data in malware_analysis.items():
                    if isinstance(sample_data, dict):
                        sample_data["file"] = file_name
                        malware_results.append(sample_data)
                return malware_results
        
        # Process VirusTotal results
        vt_results = analysis_data.get("virustotal_analysis", {})
        if vt_results:
            if isinstance(vt_results, dict):
                for file_path, result in vt_results.items():
                    if "error" not in result:
                        malware_results.append({
                            "file": os.path.basename(file_path),
                            "engine": "VirusTotal",
                            "detection_ratio": result.get("detection_ratio", 0),
                            "severity": result.get("severity", "UNKNOWN"),
                            "threat_category": result.get("threat_category", []),
                            "scan_date": result.get("scan_date", "")
                        })
            elif isinstance(vt_results, list):
                for result in vt_results:
                    if isinstance(result, dict) and "error" not in result:
                        malware_results.append({
                            "file": os.path.basename(result.get("file", "unknown.exe")),
                            "engine": "VirusTotal",
                            "detection_ratio": result.get("detection_ratio", 0),
                            "severity": result.get("severity", "UNKNOWN"),
                            "threat_category": result.get("threat_category", []),
                            "scan_date": result.get("scan_date", "")
                        })
                    
        # Process EMBER results
        ember_results = analysis_data.get("ember_analysis", {})
        if ember_results:
            for file_path, result in ember_results.items():
                if "error" not in result:
                    malware_results.append({
                        "file": os.path.basename(file_path),
                        "engine": "EMBER",
                        "malware_score": result.get("malware_score", 0),
                        "severity": result.get("severity", "UNKNOWN"),
                        "classification": result.get("classification", ""),
                        "scan_date": result.get("scan_date", "")
                    })
                    
        # Process Cuckoo results
        cuckoo_results = analysis_data.get("cuckoo_analysis", {})
        if cuckoo_results:
            for file_path, result in cuckoo_results.items():
                if "error" not in result:
                    malware_results.append({
                        "file": os.path.basename(file_path),
                        "engine": "Cuckoo Sandbox",
                        "score": result.get("score", 0),
                        "severity": result.get("severity", "UNKNOWN"),
                        "signatures": result.get("signatures", []),
                        "scan_date": result.get("scan_date", "")
                    })
                    
        return malware_results
        
    def _process_attack_techniques(self, analysis_data) -> List[Dict[str, Any]]:
        """Process attack techniques."""
        if isinstance(analysis_data, str):
            return []
            
        techniques = []
        
        if "attack_techniques" in analysis_data and isinstance(analysis_data["attack_techniques"], list):
            for technique in analysis_data["attack_techniques"]:
                if isinstance(technique, dict):
                    techniques.append({
                        "id": technique.get("id", "T0000"),
                        "name": technique.get("name", "Unknown"),
                        "confidence": technique.get("confidence", 0),
                        "description": technique.get("description", self._get_technique_description(technique.get("id", "")))
                    })
            return techniques
        
        if "techniques" not in analysis_data:
            return techniques
            
        # Process techniques from knowledge graph
        techniques_data = analysis_data.get("techniques", {})
        
        try:
            if isinstance(techniques_data, dict):
                for technique_id, technique_data in techniques_data.items():
                    if not isinstance(technique_data, dict):
                        self.logger.warning(f"Technique data for {technique_id} is not a dictionary: {type(technique_data)}")
                        continue
                        
                    techniques.append({
                        "id": technique_id,
                        "name": technique_data.get("name", "Unknown"),
                        "confidence": technique_data.get("confidence", 0),
                        "description": self._get_technique_description(technique_id)
                    })
            elif isinstance(techniques_data, list):
                for technique in techniques_data:
                    if not isinstance(technique, dict):
                        self.logger.warning(f"Technique in list is not a dictionary: {type(technique)}")
                        continue
                        
                    technique_id = technique.get("technique_id", technique.get("id", ""))
                    technique_name = technique.get("technique_name", technique.get("name", "Unknown"))
                    
                    techniques.append({
                        "id": technique_id,
                        "name": technique_name,
                        "confidence": technique.get("confidence", 0),
                        "description": self._get_technique_description(technique_id)
                    })
            elif isinstance(techniques_data, str):
                self.logger.warning(f"Techniques data is a string: {techniques_data}")
                techniques.append({
                    "id": "T0000",
                    "name": "Unknown Technique",
                    "confidence": 0,
                    "description": "No detailed information available"
                })
            else:
                self.logger.warning(f"Techniques data is of unexpected type: {type(techniques_data)}")
                techniques.append({
                    "id": "T0000",
                    "name": "Unknown Technique",
                    "confidence": 0,
                    "description": "No detailed information available"
                })
        except Exception as e:
            self.logger.error(f"Error processing attack techniques: {str(e)}")
            techniques.append({
                "id": "T0000",
                "name": "Error Processing Techniques",
                "confidence": 0,
                "description": f"Error: {str(e)}"
            })
            
        return techniques
        
    def _get_technique_description(self, technique_id) -> str:
        """Get description for a MITRE ATT&CK technique."""
        # This is a simplified version - in a real implementation, this would query the MITRE ATT&CK database
        descriptions = {
            "T1059.003": "Command-Line Interface: Adversaries may use command-line interfaces to interact with systems and execute commands.",
            "T1059.001": "PowerShell: Adversaries may use PowerShell to execute commands and scripts.",
            "T1112": "Modify Registry: Adversaries may modify the Windows registry to hide configuration information.",
            "T1071": "Command and Control: Adversaries use command and control channels to communicate with systems under their control.",
            "T1048": "Exfiltration Over Alternative Protocol: Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
            "T1055": "Process Injection: Adversaries may inject code into processes to evade detection or gain privileges.",
            "T1486": "Data Encrypted for Impact: Adversaries may encrypt data on target systems to disrupt system access or as part of a ransomware campaign.",
            "T1547": "Boot or Logon Autostart Execution: Adversaries may configure system settings to automatically execute a program during system boot or when a user logs in."
        }
        
        if not technique_id:
            return "No description available."
            
        if not isinstance(technique_id, str):
            try:
                technique_id = str(technique_id)
            except:
                return "No description available."
            
        return descriptions.get(technique_id, "No description available.")
        
    def _process_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and filter relevant processes."""
        # Sort processes by CPU usage
        sorted_processes = sorted(processes, key=lambda p: p.get("cpu_usage", 0), reverse=True)
        
        # Return top 10 processes by CPU usage
        return sorted_processes[:10]
        
    def _process_network_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and filter relevant network connections."""
        # Filter out connections with no remote address
        filtered_connections = [conn for conn in connections if conn.get("remote_address")]
        
        # Sort by remote address
        sorted_connections = sorted(filtered_connections, 
                                   key=lambda c: c.get("remote_address", {}).get("ip", ""))
        
        return sorted_connections
        
    def _generate_visualizations(self, analysis_data) -> Dict[str, str]:
        """Generate visualizations for the report."""
        if isinstance(analysis_data, str):
            return {}
            
        visualizations = {}
        
        try:
            # Generate process activity visualization
            process_viz = self._generate_process_activity_visualization(analysis_data.get("processes", []))
            if process_viz:
                visualizations["process_activity"] = process_viz
                
            # Generate network activity visualization
            network_viz = self._generate_network_activity_visualization(analysis_data.get("network_connections", []))
            if network_viz:
                visualizations["network_activity"] = network_viz
                
            # Generate attack technique visualization
            techniques = analysis_data.get("techniques", [])
            technique_viz = self._generate_technique_visualization(techniques)
            if technique_viz:
                visualizations["attack_techniques"] = technique_viz
                
            # Generate knowledge graph visualization if available
            if "knowledge_graph" in analysis_data:
                graph_viz = self._generate_knowledge_graph_visualization(analysis_data["knowledge_graph"])
                if graph_viz:
                    visualizations["knowledge_graph"] = graph_viz
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {str(e)}")
                
        return visualizations
        
    def _generate_process_activity_visualization(self, processes: List[Dict[str, Any]]) -> Optional[str]:
        """Generate visualization of process activity."""
        try:
            if not processes:
                return None
                
            # Get top processes by CPU usage
            top_processes = sorted(processes, key=lambda p: p.get("cpu_usage", 0), reverse=True)[:10]
            
            # Create plot
            plt.figure(figsize=(10, 6))
            
            process_names = [p.get("name", "Unknown")[:15] for p in top_processes]
            cpu_usages = [p.get("cpu_usage", 0) for p in top_processes]
            
            plt.barh(process_names, cpu_usages, color='skyblue')
            plt.xlabel('CPU Usage (%)')
            plt.title('Top Processes by CPU Usage')
            plt.tight_layout()
            
            # Convert plot to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{image_base64}"
        except Exception as e:
            self.logger.error(f"Error generating process visualization: {str(e)}")
            return None
            
    def _generate_network_activity_visualization(self, connections: List[Dict[str, Any]]) -> Optional[str]:
        """Generate visualization of network activity."""
        try:
            if not connections:
                return None
                
            # Count connections by remote IP
            ip_counts = {}
            for conn in connections:
                remote_ip = conn.get("remote_address", {}).get("ip", "Unknown")
                if remote_ip in ip_counts:
                    ip_counts[remote_ip] += 1
                else:
                    ip_counts[remote_ip] = 1
                    
            # Get top IPs by connection count
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Create plot
            plt.figure(figsize=(10, 6))
            
            ips = [ip[:20] for ip, _ in top_ips]
            counts = [count for _, count in top_ips]
            
            plt.barh(ips, counts, color='lightgreen')
            plt.xlabel('Connection Count')
            plt.title('Top Remote IPs by Connection Count')
            plt.tight_layout()
            
            # Convert plot to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{image_base64}"
        except Exception as e:
            self.logger.error(f"Error generating network visualization: {str(e)}")
            return None
            
    def _generate_technique_visualization(self, techniques: Union[List[Dict[str, Any]], Dict[str, Any], str]) -> Optional[str]:
        """Generate visualization of attack techniques."""
        try:
            if not techniques:
                return None
                
            # Create plot
            plt.figure(figsize=(10, 6))
            
            technique_names = []
            confidence_levels = []
            
            if isinstance(techniques, str):
                self.logger.warning(f"Techniques data is a string: {techniques}")
                technique_names.append("Unknown Technique")
                confidence_levels.append(50)  # Default value
            elif isinstance(techniques, dict):
                for technique_id, technique_data in techniques.items():
                    if not isinstance(technique_data, dict):
                        continue
                        
                    name = technique_data.get('name', 'Unknown')
                    confidence = technique_data.get('confidence', 0)
                    if isinstance(confidence, (int, float)):
                        confidence = confidence * 100 if confidence <= 1.0 else confidence
                    else:
                        confidence = 50  # Default value
                        
                    technique_names.append(f"{name} ({technique_id})")
                    confidence_levels.append(confidence)
            elif isinstance(techniques, list):
                for t in techniques:
                    if not isinstance(t, dict):
                        continue
                        
                    name = t.get('name', t.get('technique_name', 'Unknown'))
                    technique_id = t.get('id', t.get('technique_id', ''))
                    confidence = t.get("confidence", 0)
                    
                    if isinstance(confidence, (int, float)):
                        confidence = confidence * 100 if confidence <= 1.0 else confidence
                    else:
                        confidence = 50  # Default value
                        
                    technique_names.append(f"{name} ({technique_id})")
                    confidence_levels.append(confidence)
            
            if not technique_names:
                return None
            
            # Set colors based on confidence
            colors = ['red' if c >= 80 else 'orange' if c >= 60 else 'yellow' if c >= 40 else 'green' 
                     for c in confidence_levels]
            
            plt.barh(technique_names, confidence_levels, color=colors)
            plt.xlabel('Confidence (%)')
            plt.title('Attack Techniques by Confidence Level')
            plt.tight_layout()
            
            # Convert plot to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{image_base64}"
        except Exception as e:
            self.logger.error(f"Error generating technique visualization: {str(e)}")
            return None
            
    def _generate_knowledge_graph_visualization(self, graph_data) -> Optional[str]:
        """Generate visualization of knowledge graph."""
        try:
            if not graph_data:
                return None
                
            if isinstance(graph_data, str):
                try:
                    if os.path.exists(graph_data):
                        with open(graph_data, 'r') as f:
                            graph_data = json.load(f)
                    else:
                        self.logger.error(f"Graph data file not found: {graph_data}")
                        return None
                except Exception as e:
                    self.logger.error(f"Error loading graph data from file: {str(e)}")
                    return None
                
            # Create graph from data
            G = nx.DiGraph()
            
            if isinstance(graph_data, dict):
                if "nodes" in graph_data:
                    if isinstance(graph_data.get("nodes"), dict):
                        for node_id, node_data in graph_data.get("nodes", {}).items():
                            G.add_node(node_id, **node_data)
                    elif isinstance(graph_data.get("nodes"), list):
                        for node in graph_data.get("nodes", []):
                            if isinstance(node, dict) and "id" in node:
                                node_id = node["id"]
                                node_data = node.get("data", {})
                                G.add_node(node_id, **node_data)
                    
                    if isinstance(graph_data.get("edges"), list):
                        for edge in graph_data.get("edges", []):
                            if isinstance(edge, dict) and "source" in edge and "target" in edge:
                                G.add_edge(edge["source"], edge["target"], **edge.get("data", {}))
                else:
                    self.logger.warning(f"Graph data missing 'nodes' key")
                    return None
            else:
                self.logger.warning(f"Invalid graph data type: {type(graph_data)}")
                return None
                
            if len(G.nodes()) == 0:
                return None
                
            # Create plot
            plt.figure(figsize=(12, 8))
            
            # Set node colors based on type
            node_colors = []
            for node in G.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_colors.append("lightblue")
                elif node_data.get("type") == "network":
                    node_colors.append("lightgreen")
                elif node_data.get("type") == "technique":
                    node_colors.append("red")
                else:
                    node_colors.append("lightgray")
                    
            # Create node labels
            node_labels = {}
            for node in G.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_labels[node_id] = f"{node_data.get('name', '')}\n(PID: {node_data.get('pid', '')})"
                elif node_data.get("type") == "network":
                    remote_addr = node_data.get('remote_addr', node_data.get('ip', ''))
                    remote_port = node_data.get('remote_port', node_data.get('port', ''))
                    node_labels[node_id] = f"{remote_addr}:{remote_port}"
                elif node_data.get("type") == "file":
                    path = node_data.get('path', '')
                    operation = node_data.get('operation', '')
                    node_labels[node_id] = f"{os.path.basename(path)}\n({operation})"
                elif node_data.get("type") == "registry":
                    key = node_data.get('key', '')
                    node_labels[node_id] = f"{os.path.basename(key)}"
                elif node_data.get("type") == "technique":
                    node_labels[node_id] = f"{node_data.get('technique_name', '')}"
                else:
                    node_labels[node_id] = node_id
                    
            # Draw the graph
            pos = nx.spring_layout(G)
            nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=500, alpha=0.8)
            nx.draw_networkx_edges(G, pos, width=1.0, alpha=0.5, arrowsize=20)
            nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=8)
            
            plt.title("Attack Knowledge Graph")
            plt.axis("off")
            
            # Convert plot to base64 string
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            plt.close()
            
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return f"data:image/png;base64,{image_base64}"
        except Exception as e:
            self.logger.error(f"Error generating knowledge graph visualization: {str(e)}")
            return None
            
    def _generate_improvement_suggestions(self, analysis_data) -> List[Dict[str, Any]]:
        """Generate security improvement suggestions based on analysis."""
        if isinstance(analysis_data, str):
            return []
            
        suggestions = []
        
        # Check for command and control techniques
        c2_techniques = [t for t in analysis_data.get("techniques", []) 
                        if t.get("technique_id") in ["T1071", "T1095", "T1065", "T1105"]]
        if c2_techniques:
            suggestions.append({
                "category": "Network Security",
                "title": "Enhance Network Monitoring and Filtering",
                "description": "Implement advanced network monitoring and filtering to detect and block command and control traffic.",
                "actions": [
                    "Deploy a next-generation firewall with deep packet inspection",
                    "Implement DNS filtering to block known malicious domains",
                    "Set up network traffic analysis to detect unusual patterns",
                    "Consider using a secure web gateway to filter outbound traffic"
                ]
            })
            
        # Check for data exfiltration techniques
        exfil_techniques = [t for t in analysis_data.get("techniques", []) 
                           if t.get("technique_id") in ["T1048", "T1041", "T1567", "T1052"]]
        if exfil_techniques:
            suggestions.append({
                "category": "Data Protection",
                "title": "Prevent Data Exfiltration",
                "description": "Implement controls to prevent unauthorized data exfiltration from your systems.",
                "actions": [
                    "Deploy data loss prevention (DLP) solutions",
                    "Encrypt sensitive data at rest and in transit",
                    "Implement egress filtering at network boundaries",
                    "Monitor and alert on unusual data transfer patterns"
                ]
            })
            
        # Check for process-related techniques
        process_techniques = [t for t in analysis_data.get("techniques", []) 
                             if t.get("technique_id") in ["T1059", "T1106", "T1218", "T1055"]]
        if process_techniques:
            suggestions.append({
                "category": "Endpoint Security",
                "title": "Enhance Endpoint Protection",
                "description": "Strengthen endpoint security to prevent malicious process execution and injection.",
                "actions": [
                    "Deploy application whitelisting/allowlisting",
                    "Implement script blocking and logging",
                    "Use advanced endpoint protection with behavior monitoring",
                    "Restrict PowerShell execution with constrained language mode"
                ]
            })
            
        # Check for registry-related techniques
        registry_techniques = [t for t in analysis_data.get("techniques", []) 
                              if t.get("technique_id") in ["T1112", "T1547.001", "T1546"]]
        if registry_techniques:
            suggestions.append({
                "category": "System Hardening",
                "title": "Secure Registry Configuration",
                "description": "Protect and monitor registry to prevent persistence and privilege escalation.",
                "actions": [
                    "Restrict registry modification permissions",
                    "Monitor changes to autorun locations",
                    "Implement registry auditing",
                    "Use group policies to enforce secure registry settings"
                ]
            })
            
        # Add general suggestions if no specific techniques found
        if not suggestions:
            suggestions.append({
                "category": "General Security",
                "title": "Implement Security Best Practices",
                "description": "Enhance your security posture with these general best practices.",
                "actions": [
                    "Keep all systems and applications updated with security patches",
                    "Implement the principle of least privilege for all accounts",
                    "Deploy multi-factor authentication for all remote access",
                    "Conduct regular security awareness training for all users",
                    "Perform periodic security assessments and penetration testing"
                ]
            })
            
        return suggestions
        
    def _generate_html_report(self, report_data: Dict[str, Any], timestamp: str, output_file: str = "") -> str:
        """
        Generate HTML report.
        
        Args:
            report_data: Dictionary containing report data
            timestamp: Timestamp for the report
            output_file: Optional path to save the report to
            
        Returns:
            Path to the generated report
        """
        try:
            # Load template
            template = self.env.get_template("report_template.html")
            
            # Render template with data
            html_content = template.render(
                report_title="Cyber Attack Analysis Report",
                timestamp=timestamp,
                summary=report_data["analysis_data"]["summary"],
                malware_analysis=report_data["analysis_data"]["malware_analysis"],
                attack_techniques=report_data["analysis_data"]["attack_techniques"],
                system_activity=report_data["analysis_data"]["system_activity"],
                visualizations=report_data["visualizations"],
                suggestions=report_data["suggestions"]
            )
            
            # Save report to file
            if output_file:
                report_path = output_file
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
            else:
                report_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
                
            with open(report_path, "w") as f:
                f.write(html_content)
                
            self.logger.info(f"HTML report generated at {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            return ""
            
    def _generate_json_report(self, report_data: Dict[str, Any], timestamp: str, output_file: str = "") -> str:
        """
        Generate JSON report.
        
        Args:
            report_data: Dictionary containing report data
            timestamp: Timestamp for the report
            output_file: Optional path to save the report to
            
        Returns:
            Path to the generated report
        """
        try:
            # Save report to file
            if output_file:
                report_path = output_file
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
            else:
                report_path = os.path.join(self.output_dir, f"report_{timestamp}.json")
            
            # Remove non-serializable data
            clean_data = self._clean_for_json(report_data)
            
            with open(report_path, "w") as f:
                json.dump(clean_data, f, indent=2)
                
            self.logger.info(f"JSON report generated at {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {str(e)}")
            return ""
            
    def _clean_for_json(self, data: Any) -> Any:
        """Clean data for JSON serialization."""
        if isinstance(data, dict):
            return {k: self._clean_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._clean_for_json(item) for item in data]
        elif isinstance(data, (int, float, str, bool, type(None))):
            return data
        else:
            return str(data)
