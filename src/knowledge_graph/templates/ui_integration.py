"""
UI Integration Module

This module provides integration between knowledge graphs and interactive UI visualizations.
It generates HTML dashboards for visualizing cyber attack data.
"""

import os
import json
import logging
import networkx as nx
from datetime import datetime
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)

class UIIntegrator:
    """
    Integrates knowledge graphs with interactive UI visualizations.
    
    This class generates HTML dashboards for visualizing cyber attack data,
    including knowledge graphs, attribution analysis, trend visualization,
    and malware similarity analysis.
    """
    
    def __init__(self, output_dir=None):
        """
        Initialize the UI integrator.
        
        Args:
            output_dir: Directory to save output files
        """
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "dashboard")
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
        
        self.static_dir = os.path.join(self.output_dir, "static")
        os.makedirs(self.static_dir, exist_ok=True)
        
        logger.info(f"UI Integrator initialized with output directory: {self.output_dir}")
    
    def create_dashboard(self, graph=None, filename=None, title=None, attribution_data=None, trend_data=None, similarity_data=None):
        """
        Create an interactive dashboard for visualizing cyber attack data.
        
        Args:
            graph: NetworkX graph object
            filename: Output filename
            title: Dashboard title
            attribution_data: Attribution analysis data
            trend_data: Trend visualization data
            similarity_data: Malware similarity data
            
        Returns:
            Dictionary with paths to generated files
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = filename or f"dashboard_{timestamp}.html"
        title = title or "Cyber Attack Knowledge Graph"
        
        main_graph_path = os.path.join(self.output_dir, filename)
        
        if graph:
            self._generate_graph_visualization(graph, main_graph_path, title)
            logger.info(f"Generated graph visualization: {main_graph_path}")
        
        result = {
            "main_graph": main_graph_path,
        }
        
        return result
    
    def _generate_graph_visualization(self, graph, output_path, title):
        """
        Generate an interactive visualization of a knowledge graph.
        
        Args:
            graph: NetworkX graph object
            output_path: Path to save the visualization
            title: Visualization title
        """
        nodes = []
        for node_id in graph.nodes():
            node_data = graph.nodes[node_id]
            node_type = node_data.get('type', 'unknown')
            
            node_info = {
                'id': node_id,
                'type': node_type,
                'label': node_id,
            }
            
            for key, value in node_data.items():
                node_info[key] = value
            
            nodes.append(node_info)
        
        edges = []
        for source, target, edge_data in graph.edges(data=True):
            edge_info = {
                'source': source,
                'target': target,
                'relationship': edge_data.get('relationship', 'unknown')
            }
            
            for key, value in edge_data.items():
                if key != 'relationship':
                    edge_info[key] = value
            
            edges.append(edge_info)
        
        graph_data = {
            'nodes': nodes,
            'edges': edges
        }
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{title}</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                h1 {{
                    color: #333;
                    text-align: center;
                    margin-bottom: 20px;
                }}
                    width: 100%;
                    height: 600px;
                    background-color: white;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }}
                .legend {{
                    margin-top: 20px;
                    padding: 10px;
                    background-color: white;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                .legend-item {{
                    display: inline-block;
                    margin-right: 15px;
                    margin-bottom: 5px;
                }}
                .legend-color {{
                    display: inline-block;
                    width: 15px;
                    height: 15px;
                    margin-right: 5px;
                    border-radius: 3px;
                    vertical-align: middle;
                }}
                .controls {{
                    margin-top: 20px;
                    margin-bottom: 20px;
                    text-align: center;
                }}
                button {{
                    padding: 8px 15px;
                    margin: 0 5px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }}
                button:hover {{
                    background-color: #45a049;
                }}
                .node-info {{
                    margin-top: 20px;
                    padding: 10px;
                    background-color: white;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    display: none;
                }}
            </style>
            <script src="https://d3js.org/d3.v7.min.js"></script>
            <script src="https://unpkg.com/force-graph"></script>
        </head>
        <body>
            <div class="container">
                <h1>{title}</h1>
                
                <div class="controls">
                    <button id="zoom-in">Zoom In</button>
                    <button id="zoom-out">Zoom Out</button>
                    <button id="reset-view">Reset View</button>
                </div>
                
                <div id="graph-container"></div>
                
                <div class="legend">
                    <h3>Legend</h3>
                    <div class="legend-item">
                        <span class="legend-color" style="background-color: #ff5722;"></span>
                        <span>Process</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-color" style="background-color: #2196f3;"></span>
                        <span>Network</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-color" style="background-color: #4caf50;"></span>
                        <span>File</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-color" style="background-color: #9c27b0;"></span>
                        <span>Registry</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-color" style="background-color: #f44336;"></span>
                        <span>Technique</span>
                    </div>
                </div>
                
                <div id="node-info" class="node-info">
                    <h3>Node Information</h3>
                    <div id="node-details"></div>
                </div>
            </div>
            
            <script>
                // Graph data
                const graphData = {json.dumps(graph_data)};
                
                // Node colors by type
                const nodeColors = {{
                    'process': '#ff5722',
                    'network': '#2196f3',
                    'file': '#4caf50',
                    'registry': '#9c27b0',
                    'technique': '#f44336',
                    'unknown': '#9e9e9e'
                }};
                
                // Initialize the graph
                const Graph = ForceGraph()
                    (document.getElementById('graph-container'))
                    .graphData(graphData)
                    .nodeId('id')
                    .nodeLabel(node => `${{node.label || node.id}}`)
                    .nodeColor(node => nodeColors[node.type] || nodeColors.unknown)
                    .nodeRelSize(6)
                    .linkLabel(link => link.relationship)
                    .linkDirectionalArrowLength(3.5)
                    .linkDirectionalArrowRelPos(1)
                    .linkCurvature(0.25)
                    .onNodeClick(node => {{
                        // Display node information
                        const nodeInfo = document.getElementById('node-info');
                        const nodeDetails = document.getElementById('node-details');
                        
                        nodeInfo.style.display = 'block';
                        
                        let html = '<table>';
                        for (const [key, value] of Object.entries(node)) {{
                            if (key !== 'x' && key !== 'y' && key !== 'vx' && key !== 'vy' && key !== 'index') {{
                                html += `<tr><td><strong>${{key}}</strong></td><td>${{value}}</td></tr>`;
                            }}
                        }}
                        html += '</table>';
                        
                        nodeDetails.innerHTML = html;
                    }});
                
                // Zoom controls
                document.getElementById('zoom-in').addEventListener('click', () => {{
                    Graph.zoom(Graph.zoom() * 1.5);
                }});
                
                document.getElementById('zoom-out').addEventListener('click', () => {{
                    Graph.zoom(Graph.zoom() / 1.5);
                }});
                
                document.getElementById('reset-view').addEventListener('click', () => {{
                    Graph.centerAt(0, 0);
                    Graph.zoom(1);
                }});
            </script>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_template)
