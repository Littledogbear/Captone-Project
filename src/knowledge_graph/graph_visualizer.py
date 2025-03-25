import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, Any
import os
from pathlib import Path
import logging

class GraphVisualizer:
    """Visualizes knowledge graphs of attack techniques."""
    
    def __init__(self, output_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "visualizations"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
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
            output_path = os.path.join(self.output_dir, filename)
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
            output_path = os.path.join(self.output_dir, filename)
            plt.savefig(output_path, dpi=300, bbox_inches="tight")
            plt.close()
            
            self.logger.info(f"Technique visualization saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error visualizing technique subgraph: {str(e)}")
            return ""
