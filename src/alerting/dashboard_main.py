"""
Dashboard Main Module.

This module provides the main entry point for the monitoring dashboard application.
"""

import logging
import argparse
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.alerting.monitoring_dashboard import MonitoringDashboard

def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join('logs', 'dashboard.log'), mode='a')
        ]
    )
    
    os.makedirs('logs', exist_ok=True)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Cyber Attack Tracer - Monitoring Dashboard')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind the dashboard server to')
    parser.add_argument('--port', type=int, default=8081, help='Port to bind the dashboard server to')
    
    return parser.parse_args()

def main():
    """Main entry point for the dashboard application."""
    setup_logging()
    
    args = parse_arguments()
    
    dashboard = MonitoringDashboard()
    dashboard.host = args.host
    dashboard.port = args.port
    
    try:
        dashboard.start()
        print(f"Dashboard started at http://{dashboard.host}:{dashboard.port}")
        print("Press Ctrl+C to stop the dashboard")
        
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping dashboard...")
        dashboard.stop()
        print("Dashboard stopped")
    except Exception as e:
        logging.error(f"Error running dashboard: {str(e)}")
        dashboard.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()
