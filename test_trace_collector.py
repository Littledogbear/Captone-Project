"""Test script for the TraceCollector component."""

import logging
import sys
from src.trace_collector.collector import TraceCollector

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_trace_collector():
    """Test the TraceCollector component."""
    try:
        logger.info("Initializing TraceCollector...")
        collector = TraceCollector()
        
        logger.info("Collecting system traces...")
        traces = collector.collect_system_traces()
        
        logger.info("Trace collection successful:")
        logger.info(f"- Processes: {len(traces.get('processes', []))}")
        logger.info(f"- Network connections: {len(traces.get('network_connections', []))}")
        logger.info(f"- System resources: CPU {traces.get('system_resources', {}).get('cpu_percent', 0)}%")
        
        if traces.get('ai_analysis'):
            logger.info("AI analysis results:")
            logger.info(f"- Status: {traces.get('ai_analysis', {}).get('status', 'unknown')}")
        
        if traces.get('patterns'):
            logger.info("Pattern detection results:")
            logger.info(f"- Patterns: {len(traces.get('patterns', {}).get('patterns', []))}")
            logger.info(f"- Anomalies: {len(traces.get('patterns', {}).get('anomalies', []))}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing TraceCollector: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_trace_collector()
    sys.exit(0 if success else 1)
