import sys
import os
import logging
import numpy as np
from typing import Dict, Any, List
import lief
import json
from pathlib import Path

# Add EMBER to Python path
sys.path.append(os.path.expanduser("~/ember"))

# Import EMBER modules
from ember.features import PEFeatureExtractor

class EmberAnalyzer:
    """Integrates with EMBER database for malware analysis."""
    
    def __init__(self, model_path: str = "", ember_data_path: str = ""):
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path
        self.ember_data_path = ember_data_path
        self.model = None
        self.feature_extractor = PEFeatureExtractor()
        self.is_initialized = False
        self.initialization_error = None
        
        # Initialize model in background
        import threading
        thread = threading.Thread(target=self._initialize_model, daemon=True)
        thread.start()
        
    def _initialize_model(self):
        """Initialize EMBER model."""
        try:
            # For now, we'll just initialize the feature extractor
            # In a real implementation, we would load a pre-trained model
            self.is_initialized = True
            self.logger.info("EMBER feature extractor initialized")
        except Exception as e:
            self.initialization_error = str(e)
            self.logger.error(f"Failed to initialize EMBER model: {str(e)}")
            
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file using EMBER feature extraction."""
        if not self.is_initialized:
            return {"status": "initializing", "message": "EMBER analyzer is still initializing"}
            
        try:
            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()
                
            # Extract features
            features = self._extract_features(file_data)
            
            # For now, we'll use a simple heuristic for classification
            # In a real implementation, we would use the trained model
            score = self._calculate_heuristic_score(features)
            
            return {
                "file_path": file_path,
                "score": float(score),
                "classification": "malicious" if score > 0.5 else "benign",
                "features": features
            }
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {str(e)}")
            return {"error": str(e)}
            
    def _extract_features(self, file_data: bytes) -> Dict[str, Any]:
        """Extract features from a PE file using EMBER feature extractor."""
        try:
            # Parse PE file with LIEF
            lief_binary = lief.parse(list(file_data))
            
            if lief_binary is None:
                return {"error": "Not a valid PE file"}
                
            # Extract raw features
            raw_features = self.feature_extractor.raw_features(file_data, lief_binary)
            
            # Process features
            processed_features = {}
            
            # Extract byte histogram
            if "histogram" in raw_features:
                processed_features["byte_histogram"] = raw_features["histogram"]
                
            # Extract header information
            if "general" in raw_features:
                processed_features["general"] = raw_features["general"]
                
            # Extract section information
            if "section" in raw_features:
                processed_features["sections"] = raw_features["section"]
                
            # Extract import information
            if "imports" in raw_features:
                processed_features["imports"] = raw_features["imports"]
                
            # Extract export information
            if "exports" in raw_features:
                processed_features["exports"] = raw_features["exports"]
                
            return processed_features
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return {"error": str(e)}
            
    def _calculate_heuristic_score(self, features: Dict[str, Any]) -> float:
        """Calculate a heuristic score based on extracted features."""
        score = 0.0
        
        # Check for suspicious section names
        suspicious_sections = ["UPX", "nsp0", ".ndata", ".aspack", ".adata"]
        if "sections" in features:
            for section in features["sections"]:
                if section.get("name", "") in suspicious_sections:
                    score += 0.2
                    
        # Check for high entropy
        if "general" in features and "file_entropy" in features["general"]:
            entropy = features["general"]["file_entropy"]
            if entropy > 7.0:  # High entropy often indicates packing or encryption
                score += 0.3
                
        # Check for suspicious imports
        suspicious_imports = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "HttpSendRequest"]
        if "imports" in features:
            for imp in features["imports"]:
                if imp in suspicious_imports:
                    score += 0.1
                    
        return min(score, 1.0)  # Cap score at 1.0
            
    def batch_analyze(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple files using EMBER feature extraction."""
        results = []
        for file_path in file_paths:
            results.append(self.analyze_file(file_path))
        return results
        
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the EMBER analyzer."""
        return {
            "is_initialized": self.is_initialized,
            "initialization_error": self.initialization_error,
            "model_path": self.model_path,
            "ember_data_path": self.ember_data_path
        }
