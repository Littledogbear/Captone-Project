"""
Test Monitoring Dashboard Script.

This script tests the monitoring dashboard functionality.
"""

import os
import sys
import time
import logging
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.alerting.dashboard_integrator import DashboardIntegrator
from src.alerting.enhanced_real_time_monitor import EnhancedRealTimeMonitor
from src.utils.system_monitor import SystemMonitor

def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join('logs', 'test_dashboard.log'), mode='a')
        ]
    )
    
    os.makedirs('logs', exist_ok=True)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Test Monitoring Dashboard')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind the dashboard server to')
    parser.add_argument('--port', type=int, default=8081, help='Port to bind the dashboard server to')
    parser.add_argument('--duration', type=int, default=300, help='Test duration in seconds')
    
    return parser.parse_args()

def simulate_suspicious_activity(monitor):
    """Simulate suspicious activity for testing."""
    logging.info("Simulating suspicious activity...")
    
    import multiprocessing
    
    def cpu_intensive_task():
        """CPU intensive task to simulate high CPU usage."""
        for _ in range(10000000):
            _ = 1 + 1
    
    processes = []
    for _ in range(min(4, multiprocessing.cpu_count())):
        p = multiprocessing.Process(target=cpu_intensive_task)
        p.start()
        processes.append(p)
    
    for p in processes:
        p.join(timeout=5)
        if p.is_alive():
            p.terminate()
    
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", 8081))
        sock.close()
    except Exception as e:
        logging.error(f"Error simulating network connection: {str(e)}")
    
    try:
        with open("suspicious_test_file.exe", "w") as f:
            f.write("This is a test file to simulate suspicious activity")
        os.remove("suspicious_test_file.exe")
    except Exception as e:
        logging.error(f"Error simulating file activity: {str(e)}")
    
    logging.info("Suspicious activity simulation completed")

def main():
    """Main entry point for the test script."""
    setup_logging()
    
    args = parse_arguments()
    
    logging.info("Starting monitoring dashboard test")
    
    os.makedirs("logs", exist_ok=True)
    os.makedirs("output/dashboard_graphs", exist_ok=True)
    os.makedirs("output/dashboard_reports", exist_ok=True)
    
    dashboard_integrator = DashboardIntegrator()
    enhanced_monitor = EnhancedRealTimeMonitor()
    system_monitor = SystemMonitor()
    
    try:
        dashboard_result = dashboard_integrator.start_dashboard(args.host, args.port)
        logging.info(f"Dashboard started: {dashboard_result}")
        
        enhanced_monitor.start_monitoring()
        logging.info("Enhanced monitoring started")
        
        time.sleep(5)
        
        simulate_suspicious_activity(enhanced_monitor)
        
        time.sleep(5)
        
        system_status = system_monitor.get_system_status()
        logging.info(f"System status: {system_status}")
        
        monitoring_status = enhanced_monitor.get_monitoring_status()
        logging.info(f"Monitoring status: {monitoring_status}")
        
        alerts = enhanced_monitor.get_recent_alerts(limit=10)
        logging.info(f"Recent alerts: {alerts}")
        
        logging.info(f"Dashboard will run for {args.duration} seconds")
        logging.info(f"Access the dashboard at http://{args.host}:{args.port}")
        
        end_time = time.time() + args.duration
        while time.time() < end_time:
            if int(time.time()) % 60 == 0:
                simulate_suspicious_activity(enhanced_monitor)
            
            time.sleep(1)
        
        enhanced_monitor.stop_monitoring()
        logging.info("Enhanced monitoring stopped")
        
        dashboard_integrator.stop_dashboard()
        logging.info("Dashboard stopped")
        
        logging.info("Monitoring dashboard test completed successfully")
    except Exception as e:
        logging.error(f"Error in monitoring dashboard test: {str(e)}")
        
        try:
            enhanced_monitor.stop_monitoring()
        except:
            pass
        
        try:
            dashboard_integrator.stop_dashboard()
        except:
            pass

if __name__ == "__main__":
    main()
