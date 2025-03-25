import os
import hashlib
import json
import time
import logging
import requests
from typing import Dict, Any, Optional, List

class VirusTotalAnalyzer:
    """Integrates with VirusTotal API for malware analysis."""
    
    def __init__(self, api_key: str = "", cache_dir: str = ""):
        self.logger = logging.getLogger(__name__)
        self.api_key = api_key
        self.cache_dir = cache_dir or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "virustotal_cache"
        )
        os.makedirs(self.cache_dir, exist_ok=True)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a file using VirusTotal."""
        try:
            # Validate file path
            if not file_path or not isinstance(file_path, str):
                return {"error": "Invalid file path provided"}
                
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
                
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            if not file_hash:
                return {"error": "Failed to calculate file hash"}
                
            # Check cache
            cached_result = self._check_cache(file_hash)
            if cached_result:
                self.logger.info(f"Using cached VirusTotal result for {file_path}")
                return cached_result
                
            # Query VirusTotal for existing analysis
            vt_response = self._query_virustotal(file_hash)
            
            # If file not found on VirusTotal, upload it
            if "error" in vt_response and vt_response.get("error", {}).get("code") == "NotFoundError":
                self.logger.info(f"File not found on VirusTotal, uploading {file_path}")
                vt_response = self._upload_to_virustotal(file_path)
                
                # If upload successful, poll for analysis results
                if "data" in vt_response and "id" in vt_response["data"]:
                    analysis_id = vt_response["data"]["id"]
                    vt_response = self._poll_analysis_result(analysis_id)
            
            # Process response
            result = self._process_vt_response(vt_response)
            
            # Save to cache
            self._save_to_cache(file_hash, result)
            
            return result
        except Exception as e:
            self.logger.error(f"Error analyzing file with VirusTotal: {str(e)}")
            return {"error": str(e)}
            
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating file hash: {str(e)}")
            return None
            
    def _check_cache(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check if analysis result is in cache."""
        cache_file = os.path.join(self.cache_dir, f"{file_hash}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                    
                # Check if cache is expired (older than 7 days)
                cache_time = cached_data.get("cache_timestamp", 0)
                if time.time() - cache_time > 7 * 24 * 60 * 60:
                    return None
                    
                return cached_data
            except Exception as e:
                self.logger.error(f"Error reading cache: {str(e)}")
        return None
        
    def _save_to_cache(self, file_hash: str, result: Dict[str, Any]) -> None:
        """Save analysis result to cache."""
        try:
            cache_file = os.path.join(self.cache_dir, f"{file_hash}.json")
            
            # Add cache timestamp
            result["cache_timestamp"] = time.time()
            
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving to cache: {str(e)}")
            
    def _query_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal API for file analysis."""
        try:
            if not self.api_key:
                return {"error": "VirusTotal API key not provided"}
                
            url = f"{self.base_url}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": {"code": response.reason, "message": response.text}}
        except Exception as e:
            self.logger.error(f"Error querying VirusTotal: {str(e)}")
            return {"error": str(e)}
            
    def _upload_to_virustotal(self, file_path: str) -> Dict[str, Any]:
        """Upload file to VirusTotal for analysis."""
        try:
            if not self.api_key:
                return {"error": "VirusTotal API key not provided"}
                
            url = f"{self.base_url}/files"
            
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(url, headers=self.headers, files=files)
                
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": {"code": response.reason, "message": response.text}}
        except Exception as e:
            self.logger.error(f"Error uploading to VirusTotal: {str(e)}")
            return {"error": str(e)}
            
    def _poll_analysis_result(self, analysis_id: str, max_attempts: int = 10) -> Dict[str, Any]:
        """Poll VirusTotal for analysis results."""
        try:
            if not self.api_key:
                return {"error": "VirusTotal API key not provided"}
                
            url = f"{self.base_url}/analyses/{analysis_id}"
            
            for attempt in range(max_attempts):
                response = requests.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    
                    if status == "completed":
                        return data
                    elif status == "failed":
                        return {"error": "Analysis failed on VirusTotal"}
                        
                # Wait before next attempt
                time.sleep(15)  # Wait 15 seconds between polls
                
            return {"error": "Analysis timed out"}
        except Exception as e:
            self.logger.error(f"Error polling VirusTotal: {str(e)}")
            return {"error": str(e)}
            
    def _process_vt_response(self, vt_response: Dict[str, Any]) -> Dict[str, Any]:
        """Process VirusTotal API response."""
        try:
            # Validate vt_response is a dictionary
            if not isinstance(vt_response, dict):
                self.logger.error(f"Invalid vt_response type: {type(vt_response)}")
                return {"error": f"Invalid response type: {type(vt_response)}"}
                
            if "error" in vt_response:
                return vt_response
                
            # Safely get attributes
            data = vt_response.get("data", {})
            if not isinstance(data, dict):
                data = {}
                
            attributes = data.get("attributes", {})
            if not isinstance(attributes, dict):
                attributes = {}
                
            stats = attributes.get("stats", {})
            if not isinstance(stats, dict):
                stats = {}
            
            # Calculate detection ratio
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            # Ensure values are numeric
            try:
                malicious = int(malicious)
                suspicious = int(suspicious)
                total = sum(stats.values())
                detection_ratio = (malicious + suspicious) / total if total > 0 else 0
            except (ValueError, TypeError):
                malicious = 0
                suspicious = 0
                total = 0
                detection_ratio = 0
            
            # Determine severity
            severity = self._calculate_severity(detection_ratio)
            
            # Determine threat category
            threat_category = self._determine_threat_category(attributes)
            
            result = {
                "scan_id": str(data.get("id", "")),
                "scan_date": attributes.get("last_analysis_date", ""),
                "stats": stats,
                "detection_ratio": detection_ratio,
                "severity": severity,
                "threat_category": threat_category,
                "file_type": attributes.get("type_description", ""),
                "file_size": attributes.get("size", 0),
                "md5": attributes.get("md5", ""),
                "sha1": attributes.get("sha1", ""),
                "sha256": attributes.get("sha256", ""),
                "tags": attributes.get("tags", []) if isinstance(attributes.get("tags"), list) else [],
                "names": attributes.get("names", []) if isinstance(attributes.get("names"), list) else [],
                "last_analysis_results": attributes.get("last_analysis_results", {}) if isinstance(attributes.get("last_analysis_results"), dict) else {}
            }
            
            return result
        except Exception as e:
            self.logger.error(f"Error processing VirusTotal response: {str(e)}")
            return {"error": str(e)}
            
    def _calculate_severity(self, detection_ratio: float) -> str:
        """Calculate severity level based on detection ratio."""
        if detection_ratio >= 0.7:
            return "CRITICAL"
        elif detection_ratio >= 0.5:
            return "HIGH"
        elif detection_ratio >= 0.3:
            return "MEDIUM"
        elif detection_ratio > 0:
            return "LOW"
        else:
            return "SAFE"
            
    def _determine_threat_category(self, attributes: Dict[str, Any]) -> List[str]:
        """Determine threat category based on VirusTotal data."""
        categories = []
        
        # Validate attributes is a dictionary
        if not isinstance(attributes, dict):
            self.logger.error(f"Invalid attributes type: {type(attributes)}")
            return ["Unknown"]
        
        # Check popular threat names
        popular_threat_classification = attributes.get("popular_threat_classification", {})
        if isinstance(popular_threat_classification, dict):
            popular_threat_names = popular_threat_classification.get("suggested_threat_label", "")
            if popular_threat_names:
                categories.append(popular_threat_names)
            
        # Check sandbox verdicts
        sandbox_verdicts = attributes.get("sandbox_verdicts", {})
        if isinstance(sandbox_verdicts, dict):
            for verdict in sandbox_verdicts.values():
                if isinstance(verdict, dict) and verdict.get("category") and verdict.get("category") not in categories:
                    categories.append(verdict.get("category"))
                
        # Check tags
        tags = attributes.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and any(keyword in tag.lower() for keyword in ["trojan", "ransomware", "backdoor", "worm", "spyware", "adware"]):
                    categories.append(tag)
                
        # If no categories found, check AV labels
        if not categories:
            av_labels = []
            last_analysis_results = attributes.get("last_analysis_results", {})
            if isinstance(last_analysis_results, dict):
                for av_result in last_analysis_results.values():
                    if isinstance(av_result, dict) and av_result.get("category") == "malicious" and av_result.get("result"):
                        av_labels.append(av_result.get("result").lower())
                    
                # Extract common malware types from AV labels
                for label in av_labels:
                    if isinstance(label, str):
                        if "trojan" in label:
                            categories.append("Trojan")
                        elif "ransomware" in label:
                            categories.append("Ransomware")
                        elif "backdoor" in label:
                            categories.append("Backdoor")
                        elif "worm" in label:
                            categories.append("Worm")
                        elif "spyware" in label:
                            categories.append("Spyware")
                        elif "adware" in label:
                            categories.append("Adware")
                    
        # Remove duplicates and return
        return list(set(categories)) if categories else ["Unknown"]
        
    def get_status(self) -> Dict[str, Any]:
        """Get the status of the VirusTotal analyzer (compatibility method for legacy code)."""
        return {
            "is_initialized": True,
            "initialization_error": None,
            "api_key": bool(self.api_key)  # Just indicate if we have an API key, not the actual key
        }
        
    def batch_analyze(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple files using VirusTotal (compatibility method for legacy code)."""
        results = []
        for file_path in file_paths:
            results.append(self.analyze_file(file_path))
        return results
        
    def _extract_features(self, file_data: bytes) -> Dict[str, Any]:
        """Extract features from file data (compatibility method for EmberAnalyzer API)."""
        # This is a stub for compatibility - we handle feature extraction differently
        # in VirusTotal integration
        return {"message": "Feature extraction handled during file analysis"}
