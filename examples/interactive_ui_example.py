#!/usr/bin/env python3
"""
Interactive UI Example

This example demonstrates the enhanced interactive UI capabilities of the
Cyber Attack Trace Analyzer, including knowledge graph visualization,
attribution analysis, trend visualization, and malware similarity analysis.
"""

import os
import sys
import logging
import networkx as nx
from datetime import datetime, timedelta
import random

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.templates.ui_integration import UIIntegrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_sample_graph():
    """Generate a sample knowledge graph for demonstration."""
    graph = nx.DiGraph()
    
    # Add process nodes
    for i in range(1, 6):
        graph.add_node(
            f"process_{i}", 
            type="process",
            name=f"process_{i}.exe",
            pid=str(1000 + i),
            username="user"
        )
    
    # Add network nodes
    for i in range(1, 4):
        graph.add_node(
            f"network_{i}",
            type="network",
            ip=f"192.168.1.{10+i}",
            port=str(8000 + i)
        )
    
    # Add file nodes
    for i in range(1, 4):
        graph.add_node(
            f"file_{i}",
            type="file",
            path=f"C:\\temp\\file_{i}.exe",
            size=str(random.randint(10000, 1000000))
        )
    
    # Add registry nodes
    for i in range(1, 3):
        graph.add_node(
            f"registry_{i}",
            type="registry",
            key=f"HKLM\\Software\\Example\\Key{i}"
        )
    
    # Add technique nodes
    techniques = [
        ("T1055", "Process Injection"),
        ("T1059", "Command and Scripting Interpreter"),
        ("T1082", "System Information Discovery"),
        ("T1105", "Ingress Tool Transfer"),
        ("T1204", "User Execution")
    ]
    
    for technique_id, technique_name in techniques:
        graph.add_node(
            technique_id,
            type="technique",
            technique_id=technique_id,
            name=technique_name
        )
    
    # Add edges
    # Process to process
    graph.add_edge("process_1", "process_2", relationship="parent_of")
    graph.add_edge("process_1", "process_3", relationship="parent_of")
    graph.add_edge("process_2", "process_4", relationship="parent_of")
    graph.add_edge("process_3", "process_5", relationship="parent_of")
    
    # Process to network
    graph.add_edge("process_2", "network_1", relationship="connects_to")
    graph.add_edge("process_4", "network_2", relationship="connects_to")
    graph.add_edge("process_5", "network_3", relationship="connects_to")
    
    # Process to file
    graph.add_edge("process_2", "file_1", relationship="writes_to")
    graph.add_edge("process_3", "file_2", relationship="reads_from")
    graph.add_edge("process_5", "file_3", relationship="executes")
    
    # Process to registry
    graph.add_edge("process_1", "registry_1", relationship="modifies")
    graph.add_edge("process_4", "registry_2", relationship="reads")
    
    # Technique to entity
    graph.add_edge("T1055", "process_2", relationship="technique_of")
    graph.add_edge("T1059", "process_3", relationship="technique_of")
    graph.add_edge("T1082", "process_4", relationship="technique_of")
    graph.add_edge("T1105", "file_3", relationship="technique_of")
    graph.add_edge("T1204", "process_5", relationship="technique_of")
    
    return graph

def generate_sample_attribution_data():
    """Generate sample attribution data for demonstration."""
    return {
        "actor_techniques": {
            "APT29": ["T1055", "T1059", "T1082"],
            "APT28": ["T1059", "T1105", "T1204"],
            "Lazarus": ["T1055", "T1204"]
        },
        "confidence": {
            "T1055": 0.85,
            "T1059": 0.75,
            "T1082": 0.65,
            "T1105": 0.80,
            "T1204": 0.70
        },
        "actor_info": {
            "APT29": {
                "actor_type": "Nation State",
                "first_seen": "2015-03-15"
            },
            "APT28": {
                "actor_type": "Nation State",
                "first_seen": "2014-07-22"
            },
            "Lazarus": {
                "actor_type": "Nation State",
                "first_seen": "2009-11-10"
            }
        }
    }

def generate_sample_trend_data():
    """Generate sample trend data for demonstration."""
    # Generate time periods (last 30 days)
    today = datetime.now()
    time_periods = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30)]
    time_periods.reverse()  # Oldest to newest
    
    # Generate technique data
    techniques = {
        "T1055": {
            "name": "Process Injection",
            "count": 42,
            "trend": "increasing",
            "periods": time_periods,
            "period_counts": {period: random.randint(0, 3) for period in time_periods},
            "platforms": ["windows"],
            "severity": "high"
        },
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "count": 78,
            "trend": "stable",
            "periods": time_periods,
            "period_counts": {period: random.randint(1, 5) for period in time_periods},
            "platforms": ["windows", "mac"],
            "severity": "medium"
        },
        "T1082": {
            "name": "System Information Discovery",
            "count": 35,
            "trend": "decreasing",
            "periods": time_periods,
            "period_counts": {period: random.randint(0, 2) for period in time_periods},
            "platforms": ["windows", "mac"],
            "severity": "low"
        },
        "T1105": {
            "name": "Ingress Tool Transfer",
            "count": 56,
            "trend": "increasing",
            "periods": time_periods,
            "period_counts": {period: random.randint(0, 4) for period in time_periods},
            "platforms": ["windows"],
            "severity": "high"
        },
        "T1204": {
            "name": "User Execution",
            "count": 92,
            "trend": "increasing",
            "periods": time_periods,
            "period_counts": {period: random.randint(1, 6) for period in time_periods},
            "platforms": ["windows", "mac"],
            "severity": "critical"
        }
    }
    
    return {
        "techniques": techniques,
        "time_periods": time_periods
    }

def generate_sample_similarity_data():
    """Generate sample malware similarity data for demonstration."""
    malware_samples = [
        {
            "id": "malware_1",
            "name": "Emotet.A",
            "family": "Emotet",
            "detection_rate": 0.92,
            "severity": "critical",
            "first_seen": "2022-03-15"
        },
        {
            "id": "malware_2",
            "name": "Emotet.B",
            "family": "Emotet",
            "detection_rate": 0.88,
            "severity": "critical",
            "first_seen": "2022-05-22"
        },
        {
            "id": "malware_3",
            "name": "TrickBot.A",
            "family": "TrickBot",
            "detection_rate": 0.85,
            "severity": "high",
            "first_seen": "2022-01-10"
        },
        {
            "id": "malware_4",
            "name": "TrickBot.B",
            "family": "TrickBot",
            "detection_rate": 0.82,
            "severity": "high",
            "first_seen": "2022-02-18"
        },
        {
            "id": "malware_5",
            "name": "Qakbot.A",
            "family": "Qakbot",
            "detection_rate": 0.78,
            "severity": "high",
            "first_seen": "2022-04-05"
        },
        {
            "id": "malware_6",
            "name": "Dridex.A",
            "family": "Dridex",
            "detection_rate": 0.75,
            "severity": "medium",
            "first_seen": "2022-06-12"
        },
        {
            "id": "malware_7",
            "name": "Dridex.B",
            "family": "Dridex",
            "detection_rate": 0.72,
            "severity": "medium",
            "first_seen": "2022-07-20"
        }
    ]
    
    # Generate similarity relationships
    similarities = [
        {"source": "malware_1", "target": "malware_2", "similarity": 0.95},
        {"source": "malware_1", "target": "malware_3", "similarity": 0.45},
        {"source": "malware_2", "target": "malware_3", "similarity": 0.42},
        {"source": "malware_3", "target": "malware_4", "similarity": 0.92},
        {"source": "malware_3", "target": "malware_5", "similarity": 0.65},
        {"source": "malware_4", "target": "malware_5", "similarity": 0.68},
        {"source": "malware_5", "target": "malware_6", "similarity": 0.55},
        {"source": "malware_6", "target": "malware_7", "similarity": 0.88},
        {"source": "malware_1", "target": "malware_6", "similarity": 0.35},
        {"source": "malware_2", "target": "malware_7", "similarity": 0.32}
    ]
    
    return {
        "malware": malware_samples,
        "similarities": similarities
    }

def main():
    """Main function to demonstrate the interactive UI."""
    try:
        logger.info("Generating sample data for interactive UI demonstration")
        
        # Generate sample graph
        graph = generate_sample_graph()
        logger.info(f"Generated sample graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges")
        
        # Generate sample attribution data
        attribution_data = generate_sample_attribution_data()
        logger.info(f"Generated attribution data for {len(attribution_data['actor_techniques'])} threat actors")
        
        # Generate sample trend data
        trend_data = generate_sample_trend_data()
        logger.info(f"Generated trend data for {len(trend_data['techniques'])} techniques over {len(trend_data['time_periods'])} time periods")
        
        # Generate sample similarity data
        similarity_data = generate_sample_similarity_data()
        logger.info(f"Generated similarity data for {len(similarity_data['malware'])} malware samples")
        
        # Create output directory
        output_dir = os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "examples", "interactive_ui")
        os.makedirs(output_dir, exist_ok=True)
        
        # Create UI integrator
        ui_integrator = UIIntegrator(output_dir=output_dir)
        
        # Create dashboard
        logger.info("Creating interactive dashboard")
        dashboard_paths = ui_integrator.create_dashboard(
            graph=graph,
            attribution_data=attribution_data,
            trend_data=trend_data,
            similarity_data=similarity_data
        )
        
        # Print results
        logger.info("Interactive UI dashboard created successfully")
        logger.info("Dashboard files:")
        for key, path in dashboard_paths.items():
            logger.info(f"  - {key}: {path}")
        
        # Print instructions
        print("\n" + "="*80)
        print("INTERACTIVE UI EXAMPLE")
        print("="*80)
        print(f"Dashboard index: {dashboard_paths.get('index', '')}")
        print("\nOpen the index file in a web browser to explore the interactive UI.")
        print("The dashboard includes:")
        print("  - Knowledge Graph Visualization")
        print("  - Attack Attribution Visualization")
        print("  - Attack Trend Visualization")
        print("  - Malware Similarity Visualization")
        print("\nThe UI is optimized for both Windows and Mac environments.")
        print("="*80)
        
    except Exception as e:
        logger.error(f"Error in interactive UI example: {str(e)}")
        raise

if __name__ == "__main__":
    main()
