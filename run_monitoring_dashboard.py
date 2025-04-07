"""
Run Monitoring Dashboard

This script launches the comprehensive monitoring dashboard for the Cyber Attack Tracer,
connecting all components including report generation and knowledge graph visualization.
"""

import os
import sys
import logging
import argparse
from pathlib import Path
import uvicorn
import threading
import time
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("dashboard.log")
    ]
)

logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.alerting.alert_dashboard import AlertDashboard
from src.alerting.enhanced_real_time_monitor import EnhancedRealTimeMonitor
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.templates.ui_integration import UIIntegrator
from src.reporting.report_generator import ReportGenerator

def main():
    """Run the comprehensive monitoring dashboard."""
    parser = argparse.ArgumentParser(description='Cyber Attack Tracer - Monitoring Dashboard')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to run the dashboard on')
    parser.add_argument('--port', type=int, default=8081, help='Port to run the dashboard on')
    parser.add_argument('--samples-dir', type=str, 
                       default=os.path.join(os.path.expanduser("~"), "samples", "malwarebazaa", "metadata"),
                       help='Directory containing malware samples metadata')
    args = parser.parse_args()
    
    os.makedirs("logs", exist_ok=True)
    os.makedirs("output/dashboard_graphs", exist_ok=True)
    os.makedirs("output/dashboard_reports", exist_ok=True)
    
    logger.info("Initializing dashboard components...")
    
    dashboard = AlertDashboard(host=args.host, port=args.port)
    
    graph_builder = KnowledgeGraphBuilder()
    
    output_dir = os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "dashboard")
    os.makedirs(output_dir, exist_ok=True)
    ui_integrator = UIIntegrator(output_dir=output_dir)
    
    report_generator = ReportGenerator()
    
    monitor = EnhancedRealTimeMonitor()
    
    if not os.path.exists(args.samples_dir):
        logger.warning(f"Samples directory not found: {args.samples_dir}")
        os.makedirs(args.samples_dir, exist_ok=True)
    
    dashboard.register_report_generator(report_generator)
    
    dashboard.register_knowledge_graph_builder(graph_builder, ui_integrator)
    
    logger.info(f"Starting dashboard on http://{args.host}:{args.port}")
    dashboard.start()
    
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping dashboard...")
        dashboard.stop()
        logger.info("Dashboard stopped")

if __name__ == "__main__":
    main()
