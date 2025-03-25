import os
import logging
from typing import Dict, Any, List, Optional
import networkx as nx
from pathlib import Path
from datetime import datetime
from ..interactive_visualizer import InteractiveVisualizer

class UIIntegrator:
    """Integrates all visualization templates into a cohesive UI experience."""
    
    def __init__(self, output_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "ui"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize visualizer
        self.visualizer = InteractiveVisualizer(output_dir=self.output_dir)
        
    def create_dashboard(self, 
                        graph: nx.DiGraph, 
                        attribution_data: Dict[str, Any] = None,
                        trend_data: Dict[str, Any] = None,
                        similarity_data: Dict[str, Any] = None) -> Dict[str, str]:
        """
        Create a complete dashboard with all visualization types.
        
        Args:
            graph: NetworkX directed graph to visualize
            attribution_data: Optional attribution data
            trend_data: Optional trend data
            similarity_data: Optional similarity data
            
        Returns:
            Dictionary with paths to all created visualizations
        """
        try:
            timestamp = int(datetime.now().timestamp())
            result = {}
            
            # Create main knowledge graph visualization
            result["main_graph"] = self.visualizer.create_interactive_visualization(
                graph=graph,
                filename=f"dashboard_main_{timestamp}.html",
                title="Cyber Attack Knowledge Graph"
            )
            
            # Create attribution visualization if data provided
            if attribution_data:
                result["attribution"] = self.visualizer.create_attribution_visualization(
                    graph=graph,
                    attribution_data=attribution_data,
                    filename=f"dashboard_attribution_{timestamp}.html"
                )
            
            # Create trend visualization if data provided
            if trend_data:
                result["trends"] = self.visualizer.create_trend_visualization(
                    trend_data=trend_data,
                    filename=f"dashboard_trends_{timestamp}.html"
                )
            
            # Create similarity visualization if data provided
            if similarity_data:
                result["similarity"] = self.visualizer.create_malware_similarity_visualization(
                    similarity_data=similarity_data,
                    filename=f"dashboard_similarity_{timestamp}.html"
                )
            
            # Create index page that links to all visualizations
            index_path = self._create_index_page(result, timestamp)
            result["index"] = index_path
            
            return result
        except Exception as e:
            self.logger.error(f"Error creating dashboard: {str(e)}")
            return {}
    
    def _create_index_page(self, visualization_paths: Dict[str, str], timestamp: int) -> str:
        """
        Create an index HTML page that links to all visualizations.
        
        Args:
            visualization_paths: Dictionary with paths to visualizations
            timestamp: Timestamp for filename
            
        Returns:
            Path to the created index page
        """
        try:
            # Create relative paths for links
            links = {}
            for key, path in visualization_paths.items():
                if path:
                    links[key] = os.path.basename(path)
            
            # Create HTML content
            html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Cyber Attack Trace Analyzer Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .dashboard-links {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }
        .dashboard-card {
            flex: 1;
            min-width: 250px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            background-color: #f9f9f9;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .dashboard-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        .dashboard-card h2 {
            margin-top: 0;
            color: #333;
        }
        .dashboard-card p {
            color: #666;
            margin-bottom: 15px;
        }
        .dashboard-card a {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
        }
        .dashboard-card a:hover {
            background-color: #45a049;
        }
        .timestamp {
            color: #999;
            font-size: 0.8em;
            margin-top: 30px;
            text-align: center;
        }
        .platform-note {
            background-color: #e8f4f8;
            border-left: 5px solid #3498db;
            padding: 10px 15px;
            margin: 20px 0;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cyber Attack Trace Analyzer Dashboard</h1>
        
        <div class="platform-note">
            <p><strong>Note:</strong> This dashboard is optimized for both Windows and Mac environments. The visualizations will automatically adapt to your platform.</p>
        </div>
        
        <div class="dashboard-links">
"""
            
            # Add card for main graph
            if "main_graph" in links:
                html_content += f"""
            <div class="dashboard-card">
                <h2>Knowledge Graph</h2>
                <p>Interactive visualization of the cyber attack knowledge graph showing relationships between entities and techniques.</p>
                <a href="{links['main_graph']}" target="_blank">View Graph</a>
            </div>
"""
            
            # Add card for attribution
            if "attribution" in links:
                html_content += f"""
            <div class="dashboard-card">
                <h2>Attack Attribution</h2>
                <p>Visualization of attack attribution data showing relationships between threat actors and techniques.</p>
                <a href="{links['attribution']}" target="_blank">View Attribution</a>
            </div>
"""
            
            # Add card for trends
            if "trends" in links:
                html_content += f"""
            <div class="dashboard-card">
                <h2>Attack Trends</h2>
                <p>Visualization of attack trends over time, showing frequency and patterns of different techniques.</p>
                <a href="{links['trends']}" target="_blank">View Trends</a>
            </div>
"""
            
            # Add card for similarity
            if "similarity" in links:
                html_content += f"""
            <div class="dashboard-card">
                <h2>Malware Similarity</h2>
                <p>Visualization of malware similarity relationships, helping identify related malware families.</p>
                <a href="{links['similarity']}" target="_blank">View Similarity</a>
            </div>
"""
            
            # Close HTML
            html_content += f"""
        </div>
        
        <p class="timestamp">Generated on: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <script>
        // Detect platform
        const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
        document.body.classList.add(isMac ? 'platform-mac' : 'platform-windows');
    </script>
</body>
</html>
"""
            
            # Save to file
            filename = f"dashboard_index_{timestamp}.html"
            output_path = os.path.join(self.output_dir, filename)
            with open(output_path, 'w') as f:
                f.write(html_content)
                
            self.logger.info(f"Dashboard index page saved to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Error creating index page: {str(e)}")
            return ""
