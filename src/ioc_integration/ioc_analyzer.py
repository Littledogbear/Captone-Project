import logging
from typing import Dict, Any, List, Optional
import json
import os
import re
from datetime import datetime
import hashlib
import requests
from pathlib import Path

class IOCAnalyzer:
    """Analyzes Indicators of Compromise (IOCs) from security reports and compares them with detected malware."""
    
    def __init__(self, db_path: str = ""):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "data", "ioc_db")
        self.ioc_db = {}
        
        os.makedirs(self.db_path, exist_ok=True)
        
        self._load_database()
        
    def _load_database(self):
        """Load IOC database from disk."""
        db_file = os.path.join(self.db_path, "ioc_db.json")
        if os.path.exists(db_file):
            try:
                with open(db_file, "r") as f:
                    self.ioc_db = json.load(f)
                self.logger.info(f"Loaded IOC database with {len(self.ioc_db)} entries")
            except Exception as e:
                self.logger.error(f"Error loading IOC database: {str(e)}")
                self.ioc_db = {}
                
    def _save_database(self):
        """Save IOC database to disk."""
        db_file = os.path.join(self.db_path, "ioc_db.json")
        try:
            with open(db_file, "w") as f:
                json.dump(self.ioc_db, f, indent=2)
            self.logger.info(f"Saved IOC database with {len(self.ioc_db)} entries")
        except Exception as e:
            self.logger.error(f"Error saving IOC database: {str(e)}")
            
    def add_ioc_report(self, report_id: str, report_data: Dict[str, Any]):
        """Add an IOC report to the database."""
        self.ioc_db[report_id] = {
            "report_data": report_data,
            "added_timestamp": datetime.now().isoformat()
        }
        self._save_database()
        
    def extract_iocs_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text using regex patterns."""
        iocs = {
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            },
            "domains": [],
            "ips": [],
            "urls": [],
            "emails": [],
            "file_paths": []
        }
        
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        iocs["hashes"]["md5"] = re.findall(md5_pattern, text)
        
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        iocs["hashes"]["sha1"] = re.findall(sha1_pattern, text)
        
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        iocs["hashes"]["sha256"] = re.findall(sha256_pattern, text)
        
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        filtered_domains = [d for d in domains if not any(fp in d for fp in [".png", ".jpg", ".gif", ".css", ".js"])]
        iocs["domains"] = filtered_domains
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        filtered_ips = [ip for ip in ips if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
        iocs["ips"] = filtered_ips
        
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w./%?=&+#]*)?'
        iocs["urls"] = re.findall(url_pattern, text)
        
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["emails"] = re.findall(email_pattern, text)
        
        file_path_pattern = r'(?:[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)|(?:/(?:[^/\\:*?"<>|\r\n]+/)*[^/\\:*?"<>|\r\n]*)'
        iocs["file_paths"] = re.findall(file_path_pattern, text)
        
        return iocs
        
    def compare_malware_with_iocs(self, malware_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compare malware data with IOCs from security reports."""
        if not self.ioc_db or not malware_data:
            return []
            
        matches = []
        
        malware_hashes = {
            "md5": malware_data.get("md5", ""),
            "sha1": malware_data.get("sha1", ""),
            "sha256": malware_data.get("sha256", "")
        }
        
        malware_domains = []
        malware_ips = []
        malware_urls = []
        
        if "behavior" in malware_data:
            behavior = malware_data["behavior"]
            
            if "network_connections" in behavior:
                for conn in behavior["network_connections"]:
                    if "domain" in conn:
                        malware_domains.append(conn["domain"])
                    if "ip" in conn:
                        malware_ips.append(conn["ip"])
                    if "url" in conn:
                        malware_urls.append(conn["url"])
        
        for report_id, report_data in self.ioc_db.items():
            iocs = report_data["report_data"].get("iocs", {})
            
            match_details = {
                "report_id": report_id,
                "matches": [],
                "match_score": 0.0
            }
            
            for hash_type in ["md5", "sha1", "sha256"]:
                if malware_hashes[hash_type] and malware_hashes[hash_type] in iocs.get("hashes", {}).get(hash_type, []):
                    match_details["matches"].append({
                        "type": f"{hash_type}_hash",
                        "value": malware_hashes[hash_type]
                    })
            
            for domain in malware_domains:
                if domain in iocs.get("domains", []):
                    match_details["matches"].append({
                        "type": "domain",
                        "value": domain
                    })
            
            for ip in malware_ips:
                if ip in iocs.get("ips", []):
                    match_details["matches"].append({
                        "type": "ip",
                        "value": ip
                    })
            
            for url in malware_urls:
                if url in iocs.get("urls", []):
                    match_details["matches"].append({
                        "type": "url",
                        "value": url
                    })
            
            if match_details["matches"]:
                hash_matches = sum(1 for m in match_details["matches"] if "hash" in m["type"])
                other_matches = len(match_details["matches"]) - hash_matches
                
                match_details["match_score"] = (hash_matches * 2 + other_matches) / (2 * 3 + 3)  # Max possible score
                matches.append(match_details)
        
        matches.sort(key=lambda x: x["match_score"], reverse=True)
        
        return matches
        
    def get_report_details(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific IOC report."""
        if report_id in self.ioc_db:
            return self.ioc_db[report_id]
        return None
        
    def search_iocs(self, query: str) -> List[Dict[str, Any]]:
        """Search for IOCs matching the query."""
        results = []
        
        for report_id, report_data in self.ioc_db.items():
            iocs = report_data["report_data"].get("iocs", {})
            
            for hash_type in ["md5", "sha1", "sha256"]:
                for hash_value in iocs.get("hashes", {}).get(hash_type, []):
                    if query.lower() in hash_value.lower():
                        results.append({
                            "report_id": report_id,
                            "ioc_type": f"{hash_type}_hash",
                            "value": hash_value
                        })
            
            for domain in iocs.get("domains", []):
                if query.lower() in domain.lower():
                    results.append({
                        "report_id": report_id,
                        "ioc_type": "domain",
                        "value": domain
                    })
            
            for ip in iocs.get("ips", []):
                if query in ip:
                    results.append({
                        "report_id": report_id,
                        "ioc_type": "ip",
                        "value": ip
                    })
            
            for url in iocs.get("urls", []):
                if query.lower() in url.lower():
                    results.append({
                        "report_id": report_id,
                        "ioc_type": "url",
                        "value": url
                    })
        
        return results
        
    def analyze_behavior_patterns(self, behaviors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze behavior patterns across multiple malware samples.
        
        Args:
            behaviors: List of behavior dictionaries from multiple malware samples
            
        Returns:
            Dictionary containing behavior pattern analysis results
        """
        try:
            if not behaviors:
                return {
                    "timestamp": datetime.now().isoformat(),
                    "sample_count": 0,
                    "common_patterns": [],
                    "techniques": {},
                    "operations": {
                        "process_operations": [],
                        "file_operations": [],
                        "network_operations": [],
                        "registry_operations": []
                    }
                }
                
            self.logger.info(f"Analyzing behavior patterns across {len(behaviors)} samples")
            
            process_operations = set()
            file_operations = set()
            network_operations = set()
            registry_operations = set()
            
            for behavior in behaviors:
                if not isinstance(behavior, dict):
                    continue
                    
                processes = behavior.get("processes", [])
                if processes:
                    for process in processes:
                        if isinstance(process, dict):
                            process_name = process.get("name", "")
                            if process_name:
                                process_operations.add(f"execute_{process_name}")
                
                files = behavior.get("files", [])
                if files:
                    for file in files:
                        if isinstance(file, dict):
                            operation = file.get("operation", "")
                            if operation:
                                file_operations.add(operation)
                
                network = behavior.get("network", [])
                if network:
                    for conn in network:
                        if isinstance(conn, dict):
                            remote_addr = conn.get("remote_addr", "")
                            remote_port = conn.get("remote_port", "")
                            if remote_addr and remote_port:
                                network_operations.add("connect")
                                network_operations.add(f"connect_to_{remote_addr}:{remote_port}")
                
                registry = behavior.get("registry", [])
                if registry:
                    for reg in registry:
                        if isinstance(reg, dict):
                            operation = reg.get("operation", "")
                            key = reg.get("key", "")
                            if operation and key:
                                registry_operations.add(operation)
                                registry_operations.add(f"{operation}_{key}")
            
            common_patterns = []
            
            if any("execute_" in op for op in process_operations):
                common_patterns.append({
                    "name": "Process execution",
                    "description": "Executes processes, possibly to perform malicious activities",
                    "severity": "medium"
                })
            
            if any("encrypt" in op for op in file_operations):
                common_patterns.append({
                    "name": "File encryption",
                    "description": "Encrypts files, typical of ransomware behavior",
                    "severity": "high"
                })
            
            if "connect" in network_operations:
                common_patterns.append({
                    "name": "Network communication",
                    "description": "Establishes network connections, typical of command and control behavior",
                    "severity": "high"
                })
            
            if any("set" in op and "Run" in op for op in registry_operations):
                common_patterns.append({
                    "name": "Persistence mechanism",
                    "description": "Modifies registry to establish persistence, typical of malware that wants to survive reboots",
                    "severity": "medium"
                })
            
            techniques = {}
            
            if any("inject" in op for op in process_operations):
                techniques["T1055"] = {
                    "name": "Process Injection",
                    "confidence": 0.85,
                    "description": "Injects code into other processes to evade detection or gain privileges"
                }
            
            if "connect" in network_operations:
                techniques["T1071"] = {
                    "name": "Command and Control",
                    "confidence": 0.8,
                    "description": "Establishes command and control communications with remote servers"
                }
            
            if any("encrypt" in op for op in file_operations):
                techniques["T1486"] = {
                    "name": "Data Encrypted for Impact",
                    "confidence": 0.9,
                    "description": "Encrypts files on the system, potentially for ransomware purposes"
                }
            
            if any("Run" in op for op in registry_operations):
                techniques["T1547"] = {
                    "name": "Boot or Logon Autostart Execution",
                    "confidence": 0.75,
                    "description": "Establishes persistence through registry or startup folder modifications"
                }
            
            return {
                "timestamp": datetime.now().isoformat(),
                "sample_count": len(behaviors),
                "common_patterns": common_patterns,
                "techniques": techniques,
                "operations": {
                    "process_operations": list(process_operations),
                    "file_operations": list(file_operations),
                    "network_operations": list(network_operations),
                    "registry_operations": list(registry_operations)
                }
            }
        except Exception as e:
            self.logger.error(f"Error analyzing behavior patterns: {str(e)}")
            return {
                "timestamp": datetime.now().isoformat(),
                "sample_count": len(behaviors) if isinstance(behaviors, list) else 0,
                "common_patterns": [],
                "techniques": {},
                "operations": {
                    "process_operations": [],
                    "file_operations": [],
                    "network_operations": [],
                    "registry_operations": []
                },
                "error": str(e),
                "status": "failed"
            }
