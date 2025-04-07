import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, Any, Optional
import os
import json
from pathlib import Path
import logging
import random

class GraphVisualizer:
    """Visualizes knowledge graphs of attack techniques."""
    
    def __init__(self, output_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "visualizations"
        )
        self.output_dir = os.path.abspath(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.node_colors = {
            'process': '#FF5733',  # Red
            'file': '#33FF57',     # Green
            'network': '#3357FF',  # Blue
            'registry': '#FF33F5', # Purple
            'unknown': '#AAAAAA'   # Gray
        }
        
    def visualize_graph(self, graph: nx.DiGraph, filename: str = "knowledge_graph.png") -> str:
        """Visualize a knowledge graph and save it to a file."""
        try:
            plt.figure(figsize=(12, 8))
            
            # Create node colors based on node type
            node_colors = []
            for node in graph.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_colors.append("lightblue")
                elif node_data.get("type") == "network":
                    node_colors.append("lightgreen")
                else:
                    node_colors.append("lightgray")
                    
            # Create node labels
            node_labels = {}
            for node in graph.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_labels[node_id] = f"{node_data.get('name', '')}\n(PID: {node_data.get('pid', '')})"
                elif node_data.get("type") == "network":
                    node_labels[node_id] = f"{node_data.get('ip', '')}:{node_data.get('port', '')}"
                else:
                    node_labels[node_id] = node_id
                    
            # Create edge labels
            edge_labels = {}
            for source, target, edge_data in graph.edges(data=True):
                edge_labels[(source, target)] = edge_data.get("type", "")
                
            # Draw the graph
            pos = nx.spring_layout(graph)
            nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=500, alpha=0.8)
            nx.draw_networkx_edges(graph, pos, width=1.0, alpha=0.5, arrowsize=20)
            nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=8)
            nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_size=8)
            
            plt.title("Attack Technique Knowledge Graph")
            plt.axis("off")
            
            # Save the graph
            output_path = filename if os.path.isabs(filename) else os.path.join(self.output_dir, os.path.basename(filename))
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()
            
            self.logger.info(f"Graph visualization saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing graph: {str(e)}")
            return ""
            
    def visualize_technique_subgraph(self, graph: nx.DiGraph, technique_id: str, 
                                    technique_name: str, filename: str = "") -> str:
        """Visualize a subgraph for a specific attack technique."""
        if not filename:
            filename = f"technique_{technique_id}.png"
            
        try:
            plt.figure(figsize=(10, 6))
            
            # Create node colors based on node type
            node_colors = []
            for node in graph.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_colors.append("lightcoral")
                elif node_data.get("type") == "network":
                    node_colors.append("lightgreen")
                else:
                    node_colors.append("lightgray")
                    
            # Create node labels
            node_labels = {}
            for node in graph.nodes(data=True):
                node_id, node_data = node
                if node_data.get("type") == "process":
                    node_labels[node_id] = f"{node_data.get('name', '')}\n(PID: {node_data.get('pid', '')})"
                elif node_data.get("type") == "network":
                    node_labels[node_id] = f"{node_data.get('ip', '')}:{node_data.get('port', '')}"
                else:
                    node_labels[node_id] = node_id
                    
            # Draw the graph
            pos = nx.spring_layout(graph)
            nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=500, alpha=0.8)
            nx.draw_networkx_edges(graph, pos, width=1.5, alpha=0.7, arrowsize=20)
            nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=8)
            
            plt.title(f"Technique: {technique_name} ({technique_id})")
            plt.axis("off")
            
            # Save the graph
            output_path = filename if os.path.isabs(filename) else os.path.join(self.output_dir, os.path.basename(filename))
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()
            
            self.logger.info(f"Technique visualization saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing technique subgraph: {str(e)}")
            return ""
            
    def visualize_graph_html(self, graph: nx.DiGraph, output_path: str, enhanced: bool = False) -> str:
        """
        Create an interactive HTML visualization of a knowledge graph.
        
        Args:
            graph: NetworkX DiGraph object
            output_path: Path to save the HTML file
            enhanced: Whether to use enhanced visualization with connecting lines
            
        Returns:
            Path to the saved HTML file
        """
        try:
            nodes_data = []
            edges_data = []
            
            for node_id, attrs in graph.nodes(data=True):
                node_type = attrs.get('type', 'unknown')
                
                color = self.node_colors.get(node_type, self.node_colors['unknown'])
                
                if node_type == 'process':
                    label = attrs.get('name', str(node_id))
                    title = f"Process: {label}<br>PID: {attrs.get('pid', 'Unknown')}"
                elif node_type == 'file':
                    path = attrs.get('path', str(node_id))
                    label = path.split('\\')[-1] if '\\' in path else path.split('/')[-1]
                    title = f"File: {path}<br>Operation: {attrs.get('operation', 'Unknown')}"
                elif node_type == 'network':
                    remote_addr = attrs.get('remote_addr', '')
                    remote_port = attrs.get('remote_port', '')
                    label = f"{remote_addr}:{remote_port}"
                    title = f"Network: {remote_addr}:{remote_port}"
                elif node_type == 'registry':
                    key = attrs.get('key', str(node_id))
                    label = key.split('\\')[-1] if '\\' in key else key
                    title = f"Registry: {key}<br>Operation: {attrs.get('operation', 'Unknown')}"
                else:
                    label = str(node_id)
                    title = f"Node: {node_id}"
                
                nodes_data.append({
                    'id': str(node_id),
                    'label': label,
                    'title': title,
                    'color': color,
                    'shape': 'dot',
                    'size': 10,
                    'type': node_type
                })
            
            for source, target, attrs in graph.edges(data=True):
                edge_type = attrs.get('operation', 'unknown')
                
                edges_data.append({
                    'from': str(source),
                    'to': str(target),
                    'label': edge_type,
                    'title': f"Type: {edge_type}",
                    'arrows': 'to',
                    'color': {'color': '#848484', 'opacity': 0.8}
                })
            
            html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>{'Enhanced ' if enhanced else ''}Knowledge Graph Visualization</title>
    <meta charset="utf-8">
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style type="text/css">
            width: 100%;
            height: 800px;
            border: 1px solid lightgray;
        }}
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}
        .legend {{
            margin-top: 20px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            display: inline-block;
        }}
        .legend-item {{
            margin: 5px;
            display: flex;
            align-items: center;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            margin-right: 10px;
            border-radius: 3px;
        }}
        .techniques {{
            margin-top: 20px;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }}
        h1, h2 {{
            color: #333;
        }}
    </style>
</head>
<body>
    <h1>{'Enhanced ' if enhanced else ''}Knowledge Graph Visualization</h1>
    <div id="graph"></div>
    
    <div class="legend">
        <h2>Legend</h2>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.node_colors['process']};"></div>
            <div>Process</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.node_colors['file']};"></div>
            <div>File</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.node_colors['network']};"></div>
            <div>Network Connection</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: {self.node_colors['registry']};"></div>
            <div>Registry Key</div>
        </div>
    </div>
    
    <script type="text/javascript">
        // Create nodes and edges
        var nodes = new vis.DataSet({nodes_data});
        var edges = new vis.DataSet({edges_data});
        
        // Create network
        var container = document.getElementById('graph');
        var data = {{
            nodes: nodes,
            edges: edges
        }};
        var options = {{
            nodes: {{
                shape: 'dot',
                size: 16,
                font: {{
                    size: 14
                }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                width: 2,
                shadow: true,
                smooth: {{
                    type: 'continuous',
                    forceDirection: 'none'
                }}
            }},
            physics: {{
                stabilization: true,
                barnesHut: {{
                    gravitationalConstant: -8000,
                    springConstant: 0.04,
                    springLength: 95
                }}
            }},
            interaction: {{
                navigationButtons: true,
                keyboard: true,
                tooltipDelay: 200
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"Interactive graph visualization saved to {output_path}")
            return output_path
        
        except Exception as e:
            self.logger.error(f"Error creating HTML visualization: {str(e)}")
            return ""
