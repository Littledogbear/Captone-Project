import logging
import os
import json
import base64
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import networkx as nx
from pathlib import Path

class InteractiveVisualizer:
    """Creates interactive web-based visualizations of knowledge graphs."""
    
    def __init__(self, output_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "interactive_visualizations"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # HTML template directory
        self.template_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "templates"
        )
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Create default template if it doesn't exist
        self._create_default_template()
        
    def _create_default_template(self):
        """Create default HTML template for interactive visualization."""
        template_path = os.path.join(self.template_dir, "graph_template.html")
        
        if not os.path.exists(template_path):
            template_html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cyber Attack Knowledge Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        #container {
            width: 100%;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        #header {
            background-color: #333;
            color: white;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        #title {
            font-size: 1.5em;
            font-weight: bold;
        }
        #controls {
            display: flex;
            gap: 10px;
        }
        #graph-container {
            flex-grow: 1;
            position: relative;
            overflow: hidden;
        }
        #graph {
            width: 100%;
            height: 100%;
        }
        #sidebar {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 300px;
            background-color: rgba(255, 255, 255, 0.9);
            border: 1px solid #ccc;
            border-radius: 5px;
            padding: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-height: calc(100% - 20px);
            overflow-y: auto;
        }
        #node-info {
            margin-top: 10px;
        }
        .node {
            cursor: pointer;
        }
        .link {
            stroke: #999;
            stroke-opacity: 0.6;
        }
        .node text {
            font-size: 10px;
            fill: #333;
        }
        .legend {
            margin-top: 10px;
            border-top: 1px solid #ccc;
            padding-top: 10px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 3px;
        }
        button {
            background-color: #4CAF50;
            border: none;
            color: white;
            padding: 5px 10px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 14px;
            margin: 2px;
            cursor: pointer;
            border-radius: 3px;
        }
        select {
            padding: 5px;
            border-radius: 3px;
            border: 1px solid #ccc;
        }
    </style>
</head>
<body>
    <div id="container">
        <div id="header">
            <div id="title">Cyber Attack Knowledge Graph</div>
            <div id="controls">
                <select id="layout-select">
                    <option value="force">Force-Directed</option>
                    <option value="radial">Radial</option>
                    <option value="tree">Tree</option>
                    <option value="circle">Circle</option>
                </select>
                <button id="zoom-in">Zoom In</button>
                <button id="zoom-out">Zoom Out</button>
                <button id="reset-zoom">Reset</button>
                <button id="toggle-sidebar">Toggle Info</button>
            </div>
        </div>
        <div id="graph-container">
            <div id="graph"></div>
            <div id="sidebar">
                <h3>Graph Information</h3>
                <div>Nodes: <span id="node-count">0</span></div>
                <div>Edges: <span id="edge-count">0</span></div>
                <div>Techniques: <span id="technique-count">0</span></div>
                <div class="legend">
                    <h4>Legend</h4>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #AED6F1;"></div>
                        <div>Process</div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #A3E4D7;"></div>
                        <div>Network</div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #F9E79F;"></div>
                        <div>File</div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #F5B7B1;"></div>
                        <div>Registry</div>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background-color: #D7BDE2;"></div>
                        <div>Technique</div>
                    </div>
                </div>
                <div id="node-info">
                    <h4>Select a node to see details</h4>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Graph data will be inserted here
        const graphData = {{GRAPH_DATA}};
        
        // Node color mapping
        const nodeColors = {
            'process': '#AED6F1',
            'network': '#A3E4D7',
            'file': '#F9E79F',
            'registry': '#F5B7B1',
            'technique': '#D7BDE2',
            'default': '#D3D3D3'
        };
        
        // Update graph statistics
        document.getElementById('node-count').textContent = graphData.nodes.length;
        document.getElementById('edge-count').textContent = graphData.links.length;
        document.getElementById('technique-count').textContent = 
            graphData.nodes.filter(n => n.type === 'technique').length;
        
        // Set up the SVG
        const width = document.getElementById('graph').clientWidth;
        const height = document.getElementById('graph').clientHeight;
        
        const svg = d3.select('#graph')
            .append('svg')
            .attr('width', '100%')
            .attr('height', '100%')
            .attr('viewBox', [0, 0, width, height])
            .call(d3.zoom().on('zoom', (event) => {
                g.attr('transform', event.transform);
            }));
            
        const g = svg.append('g');
        
        // Create the simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2));
            
        // Create the links
        const link = g.append('g')
            .selectAll('line')
            .data(graphData.links)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('stroke-width', 1.5);
            
        // Create the nodes
        const node = g.append('g')
            .selectAll('.node')
            .data(graphData.nodes)
            .enter()
            .append('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
                
        // Add circles to nodes
        node.append('circle')
            .attr('r', d => d.type === 'technique' ? 12 : 8)
            .attr('fill', d => nodeColors[d.type] || nodeColors.default);
            
        // Add labels to nodes
        node.append('text')
            .attr('dx', 12)
            .attr('dy', '.35em')
            .text(d => {
                if (d.type === 'process') return d.name || d.id;
                if (d.type === 'network') return `${d.ip || ''}:${d.port || ''}`;
                if (d.type === 'technique') return d.id || '';
                return d.id;
            });
            
        // Add title for hover
        node.append('title')
            .text(d => {
                if (d.type === 'process') return `${d.name || ''} (PID: ${d.pid || ''})`;
                if (d.type === 'network') return `${d.ip || ''}:${d.port || ''}`;
                if (d.type === 'technique') return `${d.id || ''}: ${d.name || ''}`;
                return d.id;
            });
            
        // Node click handler
        node.on('click', function(event, d) {
            // Show node details in sidebar
            const nodeInfo = document.getElementById('node-info');
            let html = `<h4>${d.id}</h4><ul>`;
            
            for (const [key, value] of Object.entries(d)) {
                if (key !== 'id' && key !== 'index' && key !== 'x' && key !== 'y' && key !== 'vx' && key !== 'vy') {
                    html += `<li><strong>${key}:</strong> ${value}</li>`;
                }
            }
            
            html += '</ul>';
            nodeInfo.innerHTML = html;
            
            // Highlight connected nodes
            const connectedNodeIds = new Set();
            graphData.links.forEach(link => {
                if (link.source.id === d.id) connectedNodeIds.add(link.target.id);
                if (link.target.id === d.id) connectedNodeIds.add(link.source.id);
            });
            
            node.select('circle')
                .attr('stroke', n => {
                    if (n.id === d.id) return '#000';
                    if (connectedNodeIds.has(n.id)) return '#666';
                    return 'none';
                })
                .attr('stroke-width', n => {
                    if (n.id === d.id) return 3;
                    if (connectedNodeIds.has(n.id)) return 2;
                    return 0;
                });
                
            link.attr('stroke', l => {
                if (l.source.id === d.id || l.target.id === d.id) return '#666';
                return '#999';
            })
            .attr('stroke-width', l => {
                if (l.source.id === d.id || l.target.id === d.id) return 2;
                return 1;
            });
        });
        
        // Update positions on simulation tick
        simulation.on('tick', () => {
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
                
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });
        
        // Drag functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }
        
        // Layout change handler
        document.getElementById('layout-select').addEventListener('change', function() {
            const layout = this.value;
            
            // Reset forces
            simulation
                .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(100))
                .force('charge', d3.forceManyBody().strength(-300))
                .force('center', d3.forceCenter(width / 2, height / 2))
                .force('x', null)
                .force('y', null);
                
            // Apply selected layout
            if (layout === 'radial') {
                simulation
                    .force('x', d3.forceX(width / 2).strength(0.1))
                    .force('y', d3.forceY(height / 2).strength(0.1))
                    .force('charge', d3.forceManyBody().strength(-500));
            } else if (layout === 'tree') {
                simulation
                    .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(50).strength(1))
                    .force('charge', d3.forceManyBody().strength(-1000));
            } else if (layout === 'circle') {
                const radius = Math.min(width, height) / 2 - 50;
                const angleStep = 2 * Math.PI / graphData.nodes.length;
                
                graphData.nodes.forEach((node, i) => {
                    const angle = i * angleStep;
                    node.x = width / 2 + radius * Math.cos(angle);
                    node.y = height / 2 + radius * Math.sin(angle);
                    node.fx = node.x;
                    node.fy = node.y;
                });
                
                simulation.alpha(0.3).restart();
                
                // Release fixed positions after a delay
                setTimeout(() => {
                    graphData.nodes.forEach(node => {
                        node.fx = null;
                        node.fy = null;
                    });
                    simulation.alpha(0.3).restart();
                }, 2000);
            }
            
            // Restart simulation
            simulation.alpha(1).restart();
        });
        
        // Zoom controls
        document.getElementById('zoom-in').addEventListener('click', function() {
            svg.transition().call(
                d3.zoom().transform,
                d3.zoomIdentity.translate(width/2, height/2).scale(
                    d3.zoomTransform(svg.node()).k * 1.5
                ).translate(-width/2, -height/2)
            );
        });
        
        document.getElementById('zoom-out').addEventListener('click', function() {
            svg.transition().call(
                d3.zoom().transform,
                d3.zoomIdentity.translate(width/2, height/2).scale(
                    d3.zoomTransform(svg.node()).k / 1.5
                ).translate(-width/2, -height/2)
            );
        });
        
        document.getElementById('reset-zoom').addEventListener('click', function() {
            svg.transition().call(
                d3.zoom().transform,
                d3.zoomIdentity
            );
        });
        
        // Toggle sidebar
        document.getElementById('toggle-sidebar').addEventListener('click', function() {
            const sidebar = document.getElementById('sidebar');
            sidebar.style.display = sidebar.style.display === 'none' ? 'block' : 'none';
        });
    </script>
</body>
</html>
"""
            with open(template_path, 'w') as f:
                f.write(template_html)
                
            self.logger.info(f"Created default HTML template at {template_path}")
            
    def create_interactive_visualization(self, graph: nx.DiGraph, 
                                        filename: str = "", 
                                        title: str = "Cyber Attack Knowledge Graph") -> str:
        """
        Create an interactive HTML visualization of the knowledge graph.
        
        Args:
            graph: NetworkX directed graph to visualize
            filename: Output filename (without extension)
            title: Title for the visualization
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"interactive_graph_{timestamp}"
                
            # Ensure filename has .html extension
            if not filename.endswith('.html'):
                filename += '.html'
                
            # Convert graph to D3.js compatible format
            graph_data = {
                "nodes": [],
                "links": []
            }
            
            # Add nodes
            for node_id, node_data in graph.nodes(data=True):
                node_entry = {
                    "id": str(node_id),
                    "type": node_data.get("type", "unknown")
                }
                
                # Add all node attributes
                for key, value in node_data.items():
                    if key != "type":
                        node_entry[key] = str(value)
                        
                graph_data["nodes"].append(node_entry)
                
            # Add edges
            for source, target, edge_data in graph.edges(data=True):
                edge_entry = {
                    "source": str(source),
                    "target": str(target)
                }
                
                # Add all edge attributes
                for key, value in edge_data.items():
                    edge_entry[key] = str(value)
                    
                graph_data["links"].append(edge_entry)
                
            # Load template
            template_path = os.path.join(self.template_dir, "graph_template.html")
            with open(template_path, 'r') as f:
                template_html = f.read()
                
            # Replace placeholders
            html_content = template_html.replace("{{GRAPH_DATA}}", json.dumps(graph_data))
            html_content = html_content.replace("Cyber Attack Knowledge Graph", title)
            
            # Save to file
            output_path = os.path.join(self.output_dir, filename)
            with open(output_path, 'w') as f:
                f.write(html_content)
                
            self.logger.info(f"Interactive visualization saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error creating interactive visualization: {str(e)}")
            return ""
            
    def create_technique_visualization(self, graph: nx.DiGraph, technique_id: str, 
                                      technique_name: str, filename: str = "") -> str:
        """
        Create an interactive visualization focused on a specific technique.
        
        Args:
            graph: NetworkX directed graph to visualize
            technique_id: MITRE ATT&CK technique ID
            technique_name: Name of the technique
            filename: Output filename (without extension)
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"technique_{technique_id}_{timestamp}.html"
                
            # Create title
            title = f"Technique: {technique_id} - {technique_name}"
            
            # Create the visualization
            return self.create_interactive_visualization(
                graph=graph,
                filename=filename,
                title=title
            )
        except Exception as e:
            self.logger.error(f"Error creating technique visualization: {str(e)}")
            return ""
            
    def create_attack_path_visualization(self, graph: nx.DiGraph, path: List[str], 
                                        filename: str = "") -> str:
        """
        Create an interactive visualization of a specific attack path.
        
        Args:
            graph: NetworkX directed graph to visualize
            path: List of node IDs representing the attack path
            filename: Output filename (without extension)
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"attack_path_{timestamp}.html"
                
            # Create a subgraph containing only the path nodes and their edges
            subgraph = graph.subgraph(path)
            
            # Create title
            title = f"Attack Path ({len(path)} steps)"
            
            # Create the visualization
            return self.create_interactive_visualization(
                graph=subgraph,
                filename=filename,
                title=title
            )
        except Exception as e:
            self.logger.error(f"Error creating attack path visualization: {str(e)}")
            return ""
            
    def create_attribution_visualization(self, graph: nx.DiGraph, attribution_data: Dict[str, Any],
                                        filename: str = "") -> str:
        """
        Create an interactive visualization with attribution information.
        
        Args:
            graph: NetworkX directed graph to visualize
            attribution_data: Dictionary containing attribution information
            filename: Output filename (without extension)
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Create a copy of the graph to add attribution data
            enhanced_graph = graph.copy()
            
            # Add attribution nodes and connect to techniques
            for actor, techniques in attribution_data.get("actor_techniques", {}).items():
                actor_node = f"actor_{actor}"
                enhanced_graph.add_node(actor_node, type="actor", name=actor)
                
                # Connect actor to techniques
                for technique in techniques:
                    # Find technique node
                    technique_node = None
                    for node, data in enhanced_graph.nodes(data=True):
                        if data.get("type") == "technique" and (
                            data.get("technique_id") == technique or 
                            str(node) == technique
                        ):
                            technique_node = node
                            break
                            
                    if technique_node:
                        enhanced_graph.add_edge(actor_node, technique_node, 
                                              relationship="uses", 
                                              weight=attribution_data.get("confidence", {}).get(technique, 0.5))
            
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"attribution_{timestamp}.html"
                
            # Create visualization with custom title
            title = f"Attack Attribution Visualization"
            return self.create_interactive_visualization(enhanced_graph, filename, title)
        except Exception as e:
            self.logger.error(f"Error creating attribution visualization: {str(e)}")
            return ""
            
    def create_trend_visualization(self, trend_data: Dict[str, Any], filename: str = "") -> str:
        """
        Create an interactive visualization of attack trends.
        
        Args:
            trend_data: Dictionary containing trend information
            filename: Output filename (without extension)
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Create a graph from trend data
            trend_graph = nx.DiGraph()
            
            # Add technique nodes
            for technique, data in trend_data.get("techniques", {}).items():
                trend_graph.add_node(technique, 
                                   type="technique", 
                                   technique_id=technique,
                                   name=data.get("name", ""),
                                   count=data.get("count", 0),
                                   trend=data.get("trend", "stable"))
                
            # Add time period nodes
            for period in trend_data.get("time_periods", []):
                trend_graph.add_node(f"period_{period}", 
                                   type="time_period",
                                   period=period)
                
                # Connect techniques to time periods
                for technique, data in trend_data.get("techniques", {}).items():
                    if period in data.get("periods", []):
                        trend_graph.add_edge(technique, f"period_{period}", 
                                          count=data.get("period_counts", {}).get(period, 0))
            
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"trend_{timestamp}.html"
                
            # Create visualization with custom title
            title = f"Attack Trend Visualization"
            return self.create_interactive_visualization(trend_graph, filename, title)
        except Exception as e:
            self.logger.error(f"Error creating trend visualization: {str(e)}")
            return ""
            
    def create_malware_similarity_visualization(self, similarity_data: Dict[str, Any], filename: str = "") -> str:
        """
        Create an interactive visualization of malware similarity.
        
        Args:
            similarity_data: Dictionary containing malware similarity information
            filename: Output filename (without extension)
            
        Returns:
            Path to the saved HTML file
        """
        try:
            # Create a graph from similarity data
            similarity_graph = nx.Graph()  # Undirected graph for similarity
            
            # Add malware nodes
            for malware_id, data in similarity_data.get("malware", {}).items():
                similarity_graph.add_node(malware_id, 
                                        type="malware", 
                                        name=data.get("name", ""),
                                        family=data.get("family", ""),
                                        detection_rate=data.get("detection_rate", 0),
                                        severity=data.get("severity", "UNKNOWN"))
            
            # Add similarity edges
            for edge in similarity_data.get("similarities", []):
                source = edge.get("source")
                target = edge.get("target")
                similarity = edge.get("similarity", 0)
                
                if source and target and source in similarity_graph and target in similarity_graph:
                    similarity_graph.add_edge(source, target, 
                                           weight=similarity,
                                           similarity=similarity)
            
            # Generate filename if not provided
            if not filename:
                timestamp = int(datetime.now().timestamp())
                filename = f"malware_similarity_{timestamp}.html"
                
            # Create visualization with custom title
            title = f"Malware Similarity Visualization"
            return self.create_interactive_visualization(similarity_graph, filename, title)
        except Exception as e:
            self.logger.error(f"Error creating malware similarity visualization: {str(e)}")
            return ""
