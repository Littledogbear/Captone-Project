import os
import logging
from typing import Dict, Any, Optional, List
import importlib.util

class FileAnalyzer:
    """Analyzes files for malware using multiple analysis engines."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.analyzers = {}
        
        # Initialize analyzers based on configuration
        self._initialize_analyzers()
        
    def _initialize_analyzers(self) -> None:
        """Initialize available analyzers."""
        # Try to initialize VirusTotal analyzer
        if self.config.get("virustotal", {}).get("enabled", True):
            try:
                vt_spec = importlib.util.find_spec("src.virustotal_integration.virustotal_analyzer")
                if vt_spec:
                    vt_module = importlib.util.module_from_spec(vt_spec)
                    vt_spec.loader.exec_module(vt_module)
                    
                    self.analyzers["virustotal"] = vt_module.VirusTotalAnalyzer(
                        api_key=self.config.get("virustotal", {}).get("api_key", ""),
                        cache_dir=self.config.get("virustotal", {}).get("cache_dir", "")
                    )
                    self.logger.info("VirusTotal analyzer initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize VirusTotal analyzer: {str(e)}")
                
        # Try to initialize EMBER analyzer
        if self.config.get("ember", {}).get("enabled", True):
            try:
                ember_spec = importlib.util.find_spec("src.ember_integration.ember_analyzer")
                if ember_spec:
                    ember_module = importlib.util.module_from_spec(ember_spec)
                    ember_spec.loader.exec_module(ember_module)
                    
                    self.analyzers["ember"] = ember_module.EmberAnalyzer(
                        model_path=self.config.get("ember", {}).get("model_path", ""),
                        ember_data_path=self.config.get("ember", {}).get("data_path", "")
                    )
                    self.logger.info("EMBER analyzer initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize EMBER analyzer: {str(e)}")
                
    def analyze_file(self, file_path: str, analyzer_name: str = None) -> Dict[str, Any]:
        """Analyze a file using the specified analyzer or all available analyzers."""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
            
        results = {}
        
        # If specific analyzer requested
        if analyzer_name:
            if analyzer_name in self.analyzers:
                try:
                    results[analyzer_name] = self.analyzers[analyzer_name].analyze_file(file_path)
                except Exception as e:
                    self.logger.error(f"Error analyzing file with {analyzer_name}: {str(e)}")
                    results[analyzer_name] = {"error": str(e)}
            else:
                results["error"] = f"Analyzer '{analyzer_name}' not available"
        else:
            # Use all available analyzers
            for name, analyzer in self.analyzers.items():
                try:
                    results[name] = analyzer.analyze_file(file_path)
                except Exception as e:
                    self.logger.error(f"Error analyzing file with {name}: {str(e)}")
                    results[name] = {"error": str(e)}
                    
        # Combine results to determine overall severity
        results["combined"] = self._combine_results(results)
        
        return results
        
    def _combine_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from multiple analyzers."""
        # Initialize combined results
        combined = {
            "severity": "UNKNOWN",
            "threat_categories": set(),
            "detection_count": 0,
            "total_engines": 0
        }
        
        # Severity levels for comparison
        severity_levels = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "SAFE": 0,
            "UNKNOWN": -1
        }
        
        # Process each analyzer's results
        for analyzer, result in results.items():
            if analyzer == "combined" or "error" in result:
                continue
                
            # Update severity (take highest)
            result_severity = result.get("severity", "UNKNOWN")
            if severity_levels.get(result_severity, -1) > severity_levels.get(combined["severity"], -1):
                combined["severity"] = result_severity
                
            # Collect threat categories
            if "threat_category" in result:
                if isinstance(result["threat_category"], list):
                    combined["threat_categories"].update(result["threat_category"])
                else:
                    combined["threat_categories"].add(result["threat_category"])
                    
            # Update detection counts
            if "stats" in result:
                combined["detection_count"] += result["stats"].get("malicious", 0)
                combined["total_engines"] += sum(result["stats"].values())
                
        # Convert set to list for JSON serialization
        combined["threat_categories"] = list(combined["threat_categories"])
        
        # Calculate detection ratio
        if combined["total_engines"] > 0:
            combined["detection_ratio"] = combined["detection_count"] / combined["total_engines"]
        else:
            combined["detection_ratio"] = 0
            
        return combined
        
    def get_available_analyzers(self) -> List[str]:
        """Get list of available analyzers."""
        return list(self.analyzers.keys())
