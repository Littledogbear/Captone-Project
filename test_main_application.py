"""Test script for the main application API endpoints."""

import logging
import sys
import os
import json
import asyncio
from pathlib import Path
import uvicorn
import threading
import time
import requests
from fastapi import FastAPI

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Test server configuration
TEST_HOST = "127.0.0.1"
TEST_PORT = 8000
BASE_URL = f"http://{TEST_HOST}:{TEST_PORT}"

def start_server():
    """Start the FastAPI server in a separate thread."""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Import the app after changing directory
    from src.main import app
    
    # Start the server
    uvicorn.run(app, host=TEST_HOST, port=TEST_PORT)

def test_health_check():
    """Test the health check endpoint."""
    try:
        logger.info("Testing health check endpoint...")
        response = requests.get(f"{BASE_URL}/health")
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert response.json().get("status") == "healthy"
        
        logger.info("Health check test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing health check: {str(e)}")
        return False

def test_system_status():
    """Test the system status endpoint."""
    try:
        logger.info("Testing system status endpoint...")
        response = requests.get(f"{BASE_URL}/status")
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "cpu_percent" in response.json()
        assert "memory_percent" in response.json()
        
        logger.info("System status test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing system status: {str(e)}")
        return False

def test_collect_traces():
    """Test the collect traces endpoint."""
    try:
        logger.info("Testing collect traces endpoint...")
        response = requests.post(f"{BASE_URL}/traces/collect")
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "processes" in response.json()
        assert "network_connections" in response.json()
        assert "system_resources" in response.json()
        
        logger.info("Collect traces test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing collect traces: {str(e)}")
        return False

def test_analyze_traces():
    """Test the analyze traces endpoint."""
    try:
        logger.info("Testing analyze traces endpoint...")
        
        # First collect traces
        collect_response = requests.post(f"{BASE_URL}/traces/collect")
        traces = collect_response.json()
        
        # Then analyze them
        response = requests.post(f"{BASE_URL}/traces/analyze", json=traces)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "analysis_id" in response.json()
        assert "timestamp" in response.json()
        
        logger.info("Analyze traces test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing analyze traces: {str(e)}")
        return False

def test_build_knowledge_graph():
    """Test the build knowledge graph endpoint."""
    try:
        logger.info("Testing build knowledge graph endpoint...")
        
        # First collect traces
        collect_response = requests.post(f"{BASE_URL}/traces/collect")
        traces = collect_response.json()
        
        # Then build knowledge graph
        response = requests.post(f"{BASE_URL}/knowledge/build", json=traces)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "graph" in response.json()
        assert "techniques" in response.json()
        
        logger.info("Build knowledge graph test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing build knowledge graph: {str(e)}")
        return False

def test_analyze_trends():
    """Test the analyze trends endpoint."""
    try:
        logger.info("Testing analyze trends endpoint...")
        response = requests.get(f"{BASE_URL}/trends/analyze")
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "time_window" in response.json()
        
        logger.info("Analyze trends test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing analyze trends: {str(e)}")
        return False

def test_generate_trend_report():
    """Test the generate trend report endpoint."""
    try:
        logger.info("Testing generate trend report endpoint...")
        response = requests.get(f"{BASE_URL}/trends/report")
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response body: {response.json()}")
        
        assert response.status_code == 200
        assert "time_window" in response.json()
        assert "top_techniques" in response.json()
        
        logger.info("Generate trend report test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing generate trend report: {str(e)}")
        return False

def run_tests():
    """Run all tests."""
    # Start server in a separate thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    logger.info("Waiting for server to start...")
    time.sleep(5)
    
    # Run tests
    tests = [
        test_health_check,
        test_system_status,
        test_collect_traces,
        test_analyze_traces,
        test_build_knowledge_graph,
        test_analyze_trends,
        test_generate_trend_report
    ]
    
    results = []
    for test in tests:
        results.append(test())
        
    # Print summary
    logger.info("Test summary:")
    for i, test in enumerate(tests):
        logger.info(f"- {test.__name__}: {'PASSED' if results[i] else 'FAILED'}")
        
    return all(results)

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
