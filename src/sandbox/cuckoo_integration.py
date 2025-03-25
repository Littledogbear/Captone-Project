import logging
import requests
import os
import json
import time
from typing import Dict, Any, List, Optional

class CuckooSandbox:
    """Integrates with Cuckoo Sandbox for malware analysis."""
    
    def __init__(self, api_url: str = "http://localhost:8090", results_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.api_url = api_url
        self.results_dir = results_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "cuckoo_results"
        )
        os.makedirs(self.results_dir, exist_ok=True)
        
    def test_connection(self) -> bool:
        """Test connection to Cuckoo Sandbox."""
        try:
            response = requests.get(f"{self.api_url}/cuckoo/status")
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Error connecting to Cuckoo: {str(e)}")
            return False
            
    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """Submit a file for analysis to Cuckoo Sandbox."""
        try:
            with open(file_path, "rb") as sample:
                files = {"file": (os.path.basename(file_path), sample)}
                response = requests.post(
                    f"{self.api_url}/tasks/create/file",
                    files=files
                )
                
            if response.status_code == 200:
                task_id = response.json().get("task_id")
                return {"task_id": task_id, "status": "submitted"}
            else:
                return {"error": f"Error submitting file to Cuckoo: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error submitting file to Cuckoo: {str(e)}")
            return {"error": str(e)}
            
    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        """Get status of a Cuckoo analysis task."""
        try:
            response = requests.get(f"{self.api_url}/tasks/view/{task_id}")
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Error getting task status: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error getting task status: {str(e)}")
            return {"error": str(e)}
            
    def get_task_report(self, task_id: int) -> Dict[str, Any]:
        """Get report for a completed Cuckoo analysis task."""
        try:
            response = requests.get(f"{self.api_url}/tasks/report/{task_id}")
            
            if response.status_code == 200:
                report = response.json()
                
                # Save report to file
                report_file = os.path.join(self.results_dir, f"task_{task_id}.json")
                with open(report_file, "w") as f:
                    json.dump(report, f, indent=2)
                    
                return self._process_cuckoo_report(report)
            else:
                return {"error": f"Error getting task report: {response.status_code}"}
        except Exception as e:
            self.logger.error(f"Error getting task report: {str(e)}")
            return {"error": str(e)}
            
    def wait_for_completion(self, task_id: int, timeout: int = 600) -> Dict[str, Any]:
        """Wait for task completion and get report."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_task_status(task_id)
            
            if status.get("task", {}).get("status") == "reported":
                return self.get_task_report(task_id)
            elif "error" in status:
                return status
                
            time.sleep(15)  # Check every 15 seconds
            
        return {"error": "Task timeout"}
        
    def _process_cuckoo_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Process Cuckoo report to extract relevant information."""
        processed_report = {
            "score": report.get("info", {}).get("score", 0),
            "duration": report.get("info", {}).get("duration", 0),
            "behavior": {
                "processes": len(report.get("behavior", {}).get("processes", [])),
                "api_calls": sum(len(proc.get("calls", [])) for proc in report.get("behavior", {}).get("processes", [])),
                "network_connections": len(report.get("network", {}).get("hosts", []))
            },
            "network": {
                "domains": report.get("network", {}).get("domains", []),
                "hosts": report.get("network", {}).get("hosts", []),
                "http_requests": report.get("network", {}).get("http", [])
            },
            "signatures": [
                {
                    "name": sig.get("name"),
                    "description": sig.get("description"),
                    "severity": sig.get("severity")
                }
                for sig in report.get("signatures", [])
            ],
            "severity": self._calculate_cuckoo_severity(report)
        }
        
        return processed_report
        
    def _calculate_cuckoo_severity(self, report: Dict[str, Any]) -> str:
        """Calculate severity based on Cuckoo report."""
        score = report.get("info", {}).get("score", 0)
        
        if score > 7:
            return "HIGH"
        elif score > 4:
            return "MEDIUM"
        elif score > 2:
            return "LOW"
        else:
            return "SAFE"
