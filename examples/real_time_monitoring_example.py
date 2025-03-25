#!/usr/bin/env python3
"""
Real-time Monitoring Example.

This script demonstrates how to use the enhanced real-time monitoring and alerting system
with platform-specific capabilities for Windows and Mac environments.
"""

import time
import logging
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.alerting.enhanced_real_time_monitor import EnhancedRealTimeMonitor
from src.utils.platform_detector import PlatformDetector
from src.alerting.alert_dashboard import AlertDashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("real_time_monitoring_example.log")
    ]
)

logger = logging.getLogger(__name__)

def main():
    """Run the real-time monitoring example."""
    parser = argparse.ArgumentParser(description='Enhanced Real-time Monitoring Example')
    parser.add_argument('--interval', type=int, default=30, 
                        help='Monitoring interval (in seconds)')
    parser.add_argument('--adaptive', action='store_true', 
                        help='Enable adaptive monitoring')
    parser.add_argument('--monitor-dir', type=str, action='append', 
                        help='Directory to monitor for changes')
    args = parser.parse_args()
    
    # Detect platform
    platform_detector = PlatformDetector()
    platform = platform_detector.get_platform()
    logger.info(f"Detected platform: {platform}")
    
    logger.info("Starting enhanced real-time monitoring example")
    
    # Initialize components
    monitor = EnhancedRealTimeMonitor()
    dashboard = AlertDashboard()
    
    # Configure monitoring
    monitor.set_monitoring_interval(args.interval)
    monitor.set_adaptive_monitoring(args.adaptive)
    
    # Add directories to monitor
    if args.monitor_dir:
        for directory in args.monitor_dir:
            if os.path.isdir(directory):
                logger.info(f"Adding directory to monitor: {directory}")
                monitor.add_directory_to_monitor(directory)
            else:
                logger.warning(f"Directory does not exist: {directory}")
    
    try:
        # Start monitoring
        monitor.start_monitoring()
        logger.info(f"Enhanced real-time monitoring started on {platform} platform")
        
        # Start dashboard
        dashboard.start()
        logger.info("Alert dashboard started")
        
        # Wait for monitoring to run
        logger.info("Monitoring system is running. Press Ctrl+C to stop.")
        
        # Keep the script running
        while True:
            # Get monitoring status
            status = monitor.get_monitoring_status()
            logger.info(f"Monitoring status: {status}")
            
            # Get recent alerts
            alerts = monitor.get_recent_alerts(limit=5)
            if alerts:
                logger.info(f"Recent alerts: {len(alerts)}")
                for alert in alerts:
                    logger.info(f"  - {alert.get('severity')} - {alert.get('title')}")
                    logger.info(f"    {alert.get('description')}")
            
            # Get platform info
            platform_info = monitor.get_platform_info()
            logger.info(f"Platform info: {platform_info}")
            
            # Sleep for a while
            time.sleep(30)
    except KeyboardInterrupt:
        logger.info("Stopping enhanced real-time monitoring example")
    finally:
        # Stop monitoring
        monitor.stop_monitoring()
        logger.info("Enhanced real-time monitoring stopped")
        
        # Stop dashboard
        dashboard.stop()
        logger.info("Alert dashboard stopped")

if __name__ == "__main__":
    main()
