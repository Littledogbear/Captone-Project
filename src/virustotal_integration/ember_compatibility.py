"""
Compatibility layer for EMBER integration.

This module provides backward compatibility for code that still expects EMBER interfaces.
"""

import logging
from typing import Dict, Any, List, Optional
import os
from pathlib import Path

from src.virustotal_integration.virustotal_analyzer import VirusTotalAnalyzer

class EmberAnalyzer:
    """
    Compatibility wrapper for EMBER analyzer that redirects to VirusTotal analyzer.
    
    This class provides the same interface as the original EmberAnalyzer but uses
    VirusTotal underneath for more up-to-date malware analysis.
    """
    
    def __init__(self, model_path: str = "", ember_data_path: str = ""):
        """
        Initialize EmberAnalyzer compatibility wrapper.
        
        Args:
            model_path: Path to EMBER model (ignored, kept for compatibility)
            ember_data_path: Path to EMBER data (ignored, kept for compatibility)
        """
        self.logger = logging.getLogger(__name__)
        self.is_initialized = True
        self.initialization_error = None
        
        # Log compatibility layer usage
        self.logger.info("Using EmberAnalyzer compatibility wrapper with VirusTotal")
        if model_path or ember_data_path:
            self.logger.warning("EMBER paths are ignored in compatibility layer")
        
        # Initialize VirusTotal analyzer
        try:
            self.vt_analyzer = VirusTotalAnalyzer()
            self.logger.info("Initialized VirusTotal analyzer for EMBER compatibility")
        except Exception as e:
            self.initialization_error = str(e)
            self.is_initialized = False
            self.logger.error(f"Error initializing VirusTotal analyzer: {str(e)}")
            
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a file using VirusTotal (compatible with original EmberAnalyzer API).
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Analysis results in a format compatible with the original EmberAnalyzer
        """
        if not self.is_initialized:
            return {
                "status": "error", 
                "message": f"Analyzer not initialized: {self.initialization_error}"
            }
            
        try:
            # Get analysis from VirusTotal
            vt_result = self.vt_analyzer.analyze_file(file_path)
            
            # Convert to EMBER-compatible format
            return self._convert_to_ember_format(vt_result, file_path)
        except Exception as e:
            self.logger.error(f"Error analyzing file: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def _convert_to_ember_format(self, vt_result: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """
        Convert VirusTotal result to EMBER-compatible format.
        
        Args:
            vt_result: VirusTotal analysis result
            file_path: Path to the analyzed file
            
        Returns:
            EMBER-compatible analysis result
        """
        # Handle error case
        if "error" in vt_result:
            return {
                "status": "error",
                "message": vt_result["error"]
            }
        
        # Extract file info
        file_info = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": vt_result.get("file_size", 0),
            "md5": vt_result.get("md5", ""),
            "sha1": vt_result.get("sha1", ""),
            "sha256": vt_result.get("sha256", "")
        }
        
        # Map severity levels
        severity_map = {
            "CRITICAL": "malicious",
            "HIGH": "malicious",
            "MEDIUM": "suspicious",
            "LOW": "suspicious",
            "SAFE": "benign",
            "UNKNOWN": "unknown"
        }
        
        # Create EMBER-compatible result
        ember_result = {
            "status": "success",
            "file_info": file_info,
            "analysis": {
                "prediction": severity_map.get(vt_result.get("severity", "UNKNOWN"), "unknown"),
                "confidence": vt_result.get("detection_ratio", 0) * 100,  # Convert to percentage
                "malware_type": vt_result.get("threat_category", []),
                "detection_count": vt_result.get("stats", {}).get("malicious", 0) if "stats" in vt_result else 0,
                "total_engines": sum(vt_result.get("stats", {}).values()) if "stats" in vt_result else 0
            }
        }
        
        return ember_result
        
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the analyzer.
        
        Returns:
            Status information
        """
        return {
            "is_initialized": self.is_initialized,
            "initialization_error": self.initialization_error,
            "backend": "VirusTotal"
        }
        
    def batch_analyze(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple files.
        
        Args:
            file_paths: List of paths to files to analyze
            
        Returns:
            List of analysis results
        """
        results = []
        for file_path in file_paths:
            results.append(self.analyze_file(file_path))
        return results
