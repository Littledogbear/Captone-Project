"""Test script for the Knowledge Graph components."""

import logging
import sys
import os
import networkx as nx
from pathlib import Path
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.technique_identifier import TechniqueIdentifier

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_traces():
    """Create sample traces for testing."""
    return {
        "timestamp": "2025-03-06T07:45:00",
        "processes": [
            {
                "pid": 1234,
                "name": "cmd.exe",
                "username": "user",
                "cpu_usage": 2.5,
                "memory_usage": 10.2
            },
            {
                "pid": 5678,
                "name": "powershell.exe",
                "username": "user",
                "cpu_usage": 5.1,
                "memory_usage": 25.7
            }
        ],
        "network_connections": [
            {
                "pid": 1234,
                "local_address": {"ip": "192.168.1.100", "port": 49152},
                "remote_address": {"ip": "203.0.113.1", "port": 443},
                "status": "ESTABLISHED"
            },
            {
                "pid": 5678,
                "local_address": {"ip": "192.168.1.100", "port": 49153},
                "remote_address": {"ip": "198.51.100.1", "port": 80},
                "status": "ESTABLISHED"
            }
        ],
        "system_resources": {
            "cpu_percent": 15.2,
            "memory_percent": 45.7,
            "disk_io": {"read_bytes": 1024, "write_bytes": 2048}
        }
    }

def test_knowledge_graph_builder():
    """Test the KnowledgeGraphBuilder component."""
    try:
        logger.info("Initializing KnowledgeGraphBuilder...")
        graph_builder = KnowledgeGraphBuilder()
        
        # Create sample traces
        traces = create_sample_traces()
        
        logger.info("Building knowledge graph from traces...")
        graph = graph_builder.build_graph_from_traces(traces)
        
        logger.info("Knowledge graph built successfully:")
        logger.info(f"- Nodes: {len(graph.nodes())}")
        logger.info(f"- Edges: {len(graph.edges())}")
        
        # Test technique identification
        techniques = graph_builder.identify_techniques()
        
        logger.info("Identified techniques:")
        for technique in techniques:
            logger.info(f"- {technique.get('technique_id', '')}: {technique.get('technique_name', '')}")
            logger.info(f"  Confidence: {technique.get('confidence', 0)}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing KnowledgeGraphBuilder: {str(e)}")
        return False

def test_technique_identifier():
    """Test the TechniqueIdentifier component."""
    try:
        logger.info("Initializing TechniqueIdentifier...")
        identifier = TechniqueIdentifier()
        
        # Create a simple graph for testing
        graph = nx.DiGraph()
        
        # Add nodes
        graph.add_node("process_1234", type="process", name="cmd.exe", pid=1234)
        graph.add_node("network_203.0.113.1_443", type="network", ip="203.0.113.1", port=443)
        
        # Add edges
        graph.add_edge("process_1234", "network_203.0.113.1_443", type="connects_to")
        
        logger.info("Identifying techniques in graph...")
        techniques = identifier.identify_techniques(graph)
        
        logger.info("Identified techniques:")
        for technique in techniques:
            logger.info(f"- {technique.get('technique_id', '')}: {technique.get('technique_name', '')}")
            logger.info(f"  Confidence: {technique.get('confidence', 0)}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing TechniqueIdentifier: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_knowledge_graph_builder() and test_technique_identifier()
    sys.exit(0 if success else 1)
