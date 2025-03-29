"""
Script to generate knowledge graphs from malware behavior data.
"""
import os
import sys
import json
import logging
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_test_results():
    """Load test results from previous malware analysis."""
    results_file = os.path.join(os.path.dirname(__file__), "test_results.json")
    if not os.path.exists(results_file):
        logger.error(f"Test results file not found: {results_file}")
        return []
    
    with open(results_file, "r") as f:
        return json.load(f)

def simulate_attack_traces(sample_info, behavior):
    """Simulate attack traces based on malware behavior."""
    traces = []
    
    process_id = 1001
    traces.append({
        "type": "process",
        "pid": process_id,
        "name": sample_info.get("file_name", "malware.exe"),
        "command_line": f"C:\\Users\\victim\\Downloads\\{sample_info.get('file_name', 'malware.exe')}",
        "timestamp": "2025-03-29T12:00:00Z"
    })
    
    for i, op in enumerate(behavior.get("file_operations", [])):
        file_path = f"C:\\Users\\victim\\{op}_file_{i}.dat"
        traces.append({
            "type": "file",
            "operation": op,
            "path": file_path,
            "process_id": process_id,
            "timestamp": f"2025-03-29T12:0{i}:00Z"
        })
    
    for i, op in enumerate(behavior.get("registry_operations", [])):
        reg_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        traces.append({
            "type": "registry",
            "operation": op,
            "key": reg_key,
            "value": "MalwareService",
            "process_id": process_id,
            "timestamp": f"2025-03-29T12:1{i}:00Z"
        })
    
    for i, op in enumerate(behavior.get("network_operations", [])):
        domain = "evil-domain.com"
        port = 443
        traces.append({
            "type": "network",
            "operation": op,
            "destination": domain,
            "port": port,
            "protocol": "tcp",
            "process_id": process_id,
            "timestamp": f"2025-03-29T12:2{i}:00Z"
        })
    
    child_pid = 1002
    for i, op in enumerate(behavior.get("process_operations", [])):
        if op == "create":
            traces.append({
                "type": "process",
                "operation": op,
                "pid": child_pid,
                "parent_pid": process_id,
                "name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
                "timestamp": f"2025-03-29T12:3{i}:00Z"
            })
        elif op == "inject":
            traces.append({
                "type": "process",
                "operation": op,
                "pid": 1003,
                "name": "explorer.exe",
                "injected_by": process_id,
                "timestamp": f"2025-03-29T12:3{i}:00Z"
            })
    
    for tag in sample_info.get("tags", []):
        traces.append({
            "type": "context",
            "key": "tag",
            "value": tag,
            "timestamp": "2025-03-29T12:00:00Z"
        })
    
    return traces

def main():
    """Main function to generate knowledge graphs."""
    output_dir = os.path.join(os.path.dirname(__file__), "output", "knowledge_graphs")
    os.makedirs(output_dir, exist_ok=True)
    
    results = load_test_results()
    if not results:
        logger.error("No test results found")
        return
    
    logger.info(f"Loaded {len(results)} malware sample results")
    
    kg_builder = KnowledgeGraphBuilder()
    
    for i, result in enumerate(results[:5]):  # Process first 5 samples
        sample_info = result["sample_info"]
        behavior = result["behavior"]
        category = result["category"]
        
        sample_id = sample_info["sha256_hash"]
        sample_name = sample_info["file_name"]
        
        logger.info(f"Processing sample {i+1}: {sample_name} ({sample_id})")
        
        traces = simulate_attack_traces(sample_info, behavior)
        
        logger.info("Building knowledge graph...")
        formatted_traces = {
            "processes": [],
            "network_connections": [],
            "timestamp": "2025-03-29T12:00:00Z"
        }
        
        for trace in traces:
            if trace["type"] == "process":
                formatted_traces["processes"].append({
                    "pid": trace["pid"],
                    "name": trace["name"],
                    "username": "victim",
                    "cpu_usage": 5.0,
                    "memory_usage": 100.0
                })
            elif trace["type"] == "network":
                formatted_traces["network_connections"].append({
                    "pid": trace.get("process_id"),
                    "remote_address": {
                        "ip": trace.get("destination"),
                        "port": trace.get("port")
                    },
                    "status": trace.get("operation")
                })
        
        graph = kg_builder.build_graph_from_traces(formatted_traces)
        
        graph_data = nx.node_link_data(graph)
        graph_file = os.path.join(output_dir, f"sample_{i+1}_{sample_id[:8]}_graph.json")
        with open(graph_file, "w") as f:
            json.dump(graph_data, f, indent=2)
        
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(graph, seed=42)  # Fixed seed for reproducibility
        
        node_colors = []
        node_sizes = []
        for node in graph.nodes():
            node_type = graph.nodes[node].get("type", "")
            if node_type == "process":
                node_colors.append("red")
                node_sizes.append(300)
            elif node_type == "file":
                node_colors.append("green")
                node_sizes.append(200)
            elif node_type == "network":
                node_colors.append("blue")
                node_sizes.append(200)
            elif node_type == "registry":
                node_colors.append("purple")
                node_sizes.append(200)
            else:
                node_colors.append("gray")
                node_sizes.append(100)
        
        nx.draw_networkx_nodes(graph, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8)
        
        edge_colors = []
        for u, v in graph.edges():
            edge_type = graph.edges[u, v].get("type", "")
            if edge_type == "creates":
                edge_colors.append("red")
            elif edge_type == "writes":
                edge_colors.append("green")
            elif edge_type == "connects":
                edge_colors.append("blue")
            elif edge_type == "modifies":
                edge_colors.append("purple")
            else:
                edge_colors.append("gray")
        
        nx.draw_networkx_edges(graph, pos, edge_color=edge_colors, width=1.5, alpha=0.7, arrows=True, arrowsize=15)
        
        labels = {}
        for node in graph.nodes():
            node_data = graph.nodes[node]
            if "name" in node_data:
                labels[node] = node_data["name"]
            elif "path" in node_data:
                labels[node] = os.path.basename(node_data["path"])
            elif "destination" in node_data:
                labels[node] = node_data["destination"]
            elif "key" in node_data:
                labels[node] = "Registry"
            else:
                labels[node] = str(node)
        
        nx.draw_networkx_labels(graph, pos, labels=labels, font_size=8, font_weight="bold")
        
        category_name = category.get("category", "unknown")
        plt.title(f"Knowledge Graph for {sample_name} (Category: {category_name})")
        
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Process'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='File'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='blue', markersize=10, label='Network'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='purple', markersize=10, label='Registry')
        ]
        plt.legend(handles=legend_elements, loc='upper right')
        
        plt.axis("off")
        
        figure_file = os.path.join(output_dir, f"sample_{i+1}_{sample_id[:8]}_graph.png")
        plt.savefig(figure_file, dpi=300, bbox_inches="tight")
        plt.close()
        
        logger.info(f"Knowledge graph saved to {figure_file}")
        
        logger.info("Identifying attack techniques...")
        techniques = kg_builder.identify_techniques()
        
        techniques_file = os.path.join(output_dir, f"sample_{i+1}_{sample_id[:8]}_techniques.json")
        with open(techniques_file, "w") as f:
            json.dump(techniques, f, indent=2)
        
        logger.info(f"Identified {len(techniques)} attack techniques")
        for technique in techniques:
            logger.info(f"- {technique['technique_id']}: {technique['technique_name']}")
            logger.info(f"  Confidence: {technique['confidence']}")
    
    logger.info(f"Generated knowledge graphs for {min(5, len(results))} samples")
    logger.info(f"Output directory: {output_dir}")

if __name__ == "__main__":
    main()
