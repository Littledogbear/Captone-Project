"""
Test UI Integration Fix

This script tests the UI integration fix by importing the necessary modules
and verifying that the dashboard can start without import errors.
"""

import os
import sys
import logging
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all necessary imports work without errors."""
    logger.info("Testing imports...")
    
    try:
        from src.knowledge_graph.templates.ui_integration import UIIntegrator
        logger.info("✅ Successfully imported UIIntegrator")
        
        from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
        logger.info("✅ Successfully imported KnowledgeGraphBuilder")
        
        from src.reporting.report_generator import ReportGenerator
        logger.info("✅ Successfully imported ReportGenerator")
        
        from src.alerting.alert_dashboard import AlertDashboard
        logger.info("✅ Successfully imported AlertDashboard")
        
        return True
    except ImportError as e:
        logger.error(f"❌ Import error: {str(e)}")
        return False

def test_dashboard_initialization():
    """Test that the dashboard can be initialized without errors."""
    logger.info("Testing dashboard initialization...")
    
    try:
        from src.alerting.alert_dashboard import AlertDashboard
        from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
        from src.knowledge_graph.templates.ui_integration import UIIntegrator
        from src.reporting.report_generator import ReportGenerator
        
        dashboard = AlertDashboard(host="127.0.0.1", port=8082)
        logger.info("✅ Successfully created AlertDashboard instance")
        
        graph_builder = KnowledgeGraphBuilder()
        logger.info("✅ Successfully created KnowledgeGraphBuilder instance")
        
        output_dir = os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "dashboard")
        os.makedirs(output_dir, exist_ok=True)
        ui_integrator = UIIntegrator(output_dir=output_dir)
        logger.info("✅ Successfully created UIIntegrator instance")
        
        report_generator = ReportGenerator()
        logger.info("✅ Successfully created ReportGenerator instance")
        
        dashboard.register_report_generator(report_generator)
        logger.info("✅ Successfully registered report generator")
        
        dashboard.register_knowledge_graph_builder(graph_builder, ui_integrator)
        logger.info("✅ Successfully registered knowledge graph builder")
        
        return True
    except Exception as e:
        logger.error(f"❌ Dashboard initialization error: {str(e)}")
        return False

def main():
    """Run all tests."""
    logger.info("Starting UI integration fix tests...")
    
    imports_success = test_imports()
    if not imports_success:
        logger.error("Import tests failed")
        return False
    
    initialization_success = test_dashboard_initialization()
    if not initialization_success:
        logger.error("Dashboard initialization tests failed")
        return False
    
    logger.info("✅ All tests passed! The UI integration fix is working correctly.")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
