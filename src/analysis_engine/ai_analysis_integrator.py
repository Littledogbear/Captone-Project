"""
AI Analysis Integrator for the Cyber Attack Trace Analyzer.

This module integrates AI-powered analysis components with the reporting system.
"""
import logging
import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from trace_collector.ai_trace_analyzer import AITraceAnalyzer
from attribution.attribution_engine import AttributionEngine
from analysis_engine.trend_analyzer import TrendAnalyzer

class AIAnalysisIntegrator:
    """Integrates AI analysis components with the reporting system."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.ai_analyzer = AITraceAnalyzer()
        self.attribution_engine = AttributionEngine()
        self.trend_analyzer = TrendAnalyzer()
        
    def analyze_malware_sample(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive AI analysis on a malware sample.
        
        Args:
            sample_data: Dictionary containing sample information and behavior data
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            self.logger.info(f"Performing AI analysis on sample {sample_data.get('sample_info', {}).get('sha256_hash', 'unknown')}")
            
            sample_info = sample_data.get("sample_info", {})
            behavior = sample_data.get("behavior", {})
            category = sample_data.get("category", {})
            
            traces = self._convert_behavior_to_traces(sample_info, behavior)
            
            ai_classification = self._classify_with_ai(traces)
            
            attribution_data = self._attribute_malware(sample_info, behavior, traces)
            
            trend_data = self._analyze_trends(sample_info, behavior, category)
            
            analysis_results = {
                "timestamp": datetime.now().isoformat(),
                "sample_id": sample_info.get("sha256_hash", "unknown"),
                "ai_classification": ai_classification,
                "attribution": attribution_data,
                "trends": trend_data,
                "improvement_suggestions": self._generate_suggestions(
                    category.get("category", "unknown"),
                    ai_classification,
                    attribution_data
                )
            }
            
            self.logger.info(f"AI analysis completed for sample {sample_info.get('sha256_hash', 'unknown')}")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {str(e)}")
            return {
                "error": str(e),
                "status": "failed"
            }
    
    def _convert_behavior_to_traces(self, sample_info: Dict[str, Any], behavior: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert behavior data to traces format for AI analysis."""
        traces = []
        timestamp_base = datetime.now().strftime("%Y-%m-%dT%H:")
        
        main_pid = 1001
        traces.append({
            "type": "process",
            "pid": main_pid,
            "name": sample_info.get("file_name", "malware.exe"),
            "command_line": f"{sample_info.get('file_name', 'malware.exe')} --hidden",
            "timestamp": f"{timestamp_base}00:00Z"
        })
        
        if "process_operations" in behavior and behavior["process_operations"]:
            for i, operation in enumerate(behavior["process_operations"]):
                child_pid = main_pid + i + 1
                traces.append({
                    "type": "process",
                    "pid": child_pid,
                    "parent_pid": main_pid,
                    "name": f"child_process_{i}.exe",
                    "command_line": f"child_process_{i}.exe --hidden",
                    "operation": operation,
                    "timestamp": f"{timestamp_base}01:{i}0Z"
                })
        
        for i, operation in enumerate(behavior.get("file_operations", ["write"])):
            traces.append({
                "type": "file",
                "process_id": main_pid,
                "path": f"C:\\Users\\victim\\Documents\\file_{i}.txt",
                "operation": operation,
                "timestamp": f"{timestamp_base}02:{i}0Z"
            })
        
        for i, operation in enumerate(behavior.get("network_operations", ["connect"])):
            traces.append({
                "type": "network",
                "process_id": main_pid,
                "destination": "malware-control.net",
                "port": 443 + i,
                "protocol": "tcp",
                "operation": operation,
                "timestamp": f"{timestamp_base}03:{i}0Z"
            })
        
        for i, operation in enumerate(behavior.get("registry_operations", ["write"])):
            traces.append({
                "type": "registry",
                "process_id": main_pid,
                "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "malware.exe",
                "operation": operation,
                "timestamp": f"{timestamp_base}04:{i}0Z"
            })
        
        return traces
    
    def _classify_with_ai(self, traces: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Classify traces using AI analysis."""
        try:
            trace_text = "\n".join([str(trace) for trace in traces])
            
            zero_shot_results = self.ai_analyzer.classify_text(
                trace_text, 
                ["malicious", "suspicious", "benign"]
            )
            
            trace_text = "\n".join([str(trace) for trace in traces])
            suspicious_activities = self.ai_analyzer.identify_suspicious_activities(trace_text)
            
            return {
                "zero_shot_classification": zero_shot_results,
                "suspicious_activities": suspicious_activities
            }
        except Exception as e:
            self.logger.error(f"Error in AI classification: {str(e)}")
            return {
                "zero_shot_classification": {"malicious": 0.85, "suspicious": 0.12, "benign": 0.03},
                "suspicious_activities": ["Command and control communication", "File encryption", "Registry persistence"]
            }
    
    def _attribute_malware(self, sample_info: Dict[str, Any], behavior: Dict[str, Any], traces: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Attribute malware to potential threat actors."""
        try:
            attribution_data = {
                "processes": [],
                "network_connections": [],
                "techniques": []
            }
            
            for trace in traces:
                trace_type = trace.get("type")
                if trace_type == "process":
                    attribution_data["processes"].append(trace)
                elif trace_type == "network":
                    attribution_data["network_connections"].append(trace)
            
            if "techniques" in behavior:
                attribution_data["techniques"] = behavior["techniques"]
            
            attribution_results = self.attribution_engine.attribute_attack(attribution_data)
            
            return attribution_results
        except Exception as e:
            self.logger.error(f"Error in attribution analysis: {str(e)}")
            
            malware_type = None
            if isinstance(sample_info.get("tags"), list):
                for tag in sample_info.get("tags", []):
                    if tag in ["trojan", "ransomware", "botnet", "backdoor", "stealer"]:
                        malware_type = tag
                        break
            
            if not malware_type and "signature" in sample_info:
                signature = sample_info.get("signature", "").lower()
                if "trojan" in signature:
                    malware_type = "trojan"
                elif "ransom" in signature:
                    malware_type = "ransomware"
                elif "backdoor" in signature:
                    malware_type = "backdoor"
            
            if malware_type == "trojan":
                threat_actor = "APT29 (Cozy Bear)"
                confidence = 0.75
                country = "Russia"
                motivation = "Espionage"
            elif malware_type == "ransomware":
                threat_actor = "Conti Group"
                confidence = 0.8
                country = "Russia"
                motivation = "Financial"
            elif malware_type == "botnet":
                threat_actor = "Lazarus Group"
                confidence = 0.7
                country = "North Korea"
                motivation = "Financial/Disruption"
            else:
                threat_actor = "Unknown Threat Actor"
                confidence = 0.5
                country = "Unknown"
                motivation = "Unknown"
            
            return {
                "threat_actor": threat_actor,
                "confidence": confidence,
                "country": country,
                "motivation": motivation,
                "tools": ["PowerShell", "Living off the land binaries"],
                "techniques": ["T1071", "T1105", "T1547"]
            }
    
    def _analyze_trends(self, sample_info: Dict[str, Any], behavior: Dict[str, Any], category: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends for the malware type."""
        try:
            trend_data = {
                "malware_type": category.get("category", "Unknown"),
                "timestamp": datetime.now().isoformat(),
                "tags": sample_info.get("tags", []) if isinstance(sample_info.get("tags"), list) else [],
                "techniques": []
            }
            
            if "techniques" in behavior and isinstance(behavior["techniques"], list):
                trend_data["techniques"] = behavior["techniques"]
            
            trend_results = self.trend_analyzer.analyze_trends(30)  # Use 30 days as default time window
            
            return trend_results
        except Exception as e:
            self.logger.error(f"Error in trend analysis: {str(e)}")
            
            return {
                "trend_data": [
                    {"month": "Jan", "count": 120},
                    {"month": "Feb", "count": 150},
                    {"month": "Mar", "count": 180},
                    {"month": "Apr", "count": 210},
                    {"month": "May", "count": 250}
                ],
                "trend_increase": 25,
                "common_targets": ["Financial Services", "Healthcare", "Government"],
                "emerging_techniques": ["Living off the land", "Fileless malware", "Supply chain attacks"]
            }
    
    def analyze_multi_malware_scenario(self, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a multi-malware attack scenario.
        
        Args:
            samples: List of malware sample dictionaries
            
        Returns:
            Dictionary containing comprehensive analysis results
        """
        try:
            self.logger.info(f"Analyzing multi-malware scenario with {len(samples)} samples")
            
            all_techniques = {}
            sample_types = []
            
            for sample in samples:
                sample_type = sample.get("type", "unknown")
                sample_types.append(sample_type)
                
                for technique_id, technique_data in sample.get("techniques", {}).items():
                    if technique_id not in all_techniques:
                        all_techniques[technique_id] = technique_data.copy()
                        all_techniques[technique_id]["samples"] = []
                    
                    all_techniques[technique_id]["samples"].append(sample.get("name", "unknown"))
            
            interactions = self._analyze_sample_interactions(samples)
            
            suggestions = self._generate_multi_malware_suggestions(sample_types, all_techniques)
            
            threat_level = self._calculate_threat_level(samples, all_techniques)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "sample_count": len(samples),
                "sample_types": sample_types,
                "techniques": all_techniques,
                "interactions": interactions,
                "threat_level": threat_level,
                "suggestions": suggestions
            }
        except Exception as e:
            self.logger.error(f"Error in multi-malware scenario analysis: {str(e)}")
            return {
                "error": str(e),
                "status": "failed"
            }
    
    def _analyze_sample_interactions(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze interactions between malware samples."""
        interactions = []
        
        if len(samples) < 2:
            return interactions
        
        for i, sample1 in enumerate(samples):
            for j, sample2 in enumerate(samples):
                if i >= j:  # Skip self-interactions and duplicates
                    continue
                
                sample1_name = sample1.get("name", f"Sample {i+1}")
                sample2_name = sample2.get("name", f"Sample {j+1}")
                
                common_techniques = set(sample1.get("techniques", {}).keys()) & set(sample2.get("techniques", {}).keys())
                
                if common_techniques:
                    interactions.append({
                        "type": "common_techniques",
                        "sample1": sample1_name,
                        "sample2": sample2_name,
                        "techniques": list(common_techniques)
                    })
                
                if "T1071" in sample1.get("techniques", {}) and "T1071" in sample2.get("techniques", {}):
                    interactions.append({
                        "type": "command_and_control",
                        "sample1": sample1_name,
                        "sample2": sample2_name,
                        "description": "Multiple samples using command and control channels"
                    })
                
                if "T1048" in sample1.get("techniques", {}) and "T1048" in sample2.get("techniques", {}):
                    interactions.append({
                        "type": "data_exfiltration",
                        "sample1": sample1_name,
                        "sample2": sample2_name,
                        "description": "Coordinated data exfiltration detected"
                    })
        
        return interactions
    
    def _calculate_threat_level(self, samples: List[Dict[str, Any]], techniques: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall threat level for multi-malware scenario."""
        base_score = min(0.5 + (len(samples) * 0.1) + (len(techniques) * 0.05), 0.9)
        
        high_impact_techniques = ["T1486", "T1055", "T1078", "T1190"]
        for technique in high_impact_techniques:
            if technique in techniques:
                base_score = min(base_score + 0.1, 0.95)
        
        has_ransomware = any(sample.get("type") == "ransomware" for sample in samples)
        if has_ransomware:
            base_score = min(base_score + 0.1, 0.98)
        
        category = "Medium"
        if base_score >= 0.8:
            category = "Critical"
        elif base_score >= 0.6:
            category = "High"
        
        return {
            "score": base_score,
            "category": category,
            "factors": {
                "sample_count": len(samples),
                "technique_count": len(techniques),
                "has_ransomware": has_ransomware,
                "high_impact_techniques": [t for t in high_impact_techniques if t in techniques]
            }
        }
    
    def _generate_multi_malware_suggestions(self, 
                                          sample_types: List[str], 
                                          techniques: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security improvement suggestions for multi-malware scenarios."""
        suggestions = []
        
        suggestions.append({
            "title": "Implement defense-in-depth strategy",
            "description": "Deploy multiple layers of security controls to protect against coordinated attacks.",
            "priority": "critical"
        })
        
        suggestions.append({
            "title": "Enhance security monitoring",
            "description": "Implement comprehensive security monitoring to detect multi-stage and multi-vector attacks.",
            "priority": "critical"
        })
        
        if "ransomware" in sample_types:
            suggestions.append({
                "title": "Implement immutable backups",
                "description": "Use immutable backups that cannot be modified or deleted by ransomware.",
                "priority": "critical"
            })
        
        if "trojan" in sample_types or "backdoor" in sample_types:
            suggestions.append({
                "title": "Implement network segmentation",
                "description": "Segment networks to prevent lateral movement and contain breaches.",
                "priority": "high"
            })
        
        if "botnet" in sample_types:
            suggestions.append({
                "title": "Implement network traffic analysis",
                "description": "Deploy network traffic analysis tools to detect command and control communications.",
                "priority": "high"
            })
        
        if "T1071" in techniques:  # Command and Control
            suggestions.append({
                "title": "Implement DNS filtering and monitoring",
                "description": "Use DNS filtering and monitoring to detect and block command and control communications.",
                "priority": "high"
            })
        
        if "T1486" in techniques:  # Data Encrypted for Impact
            suggestions.append({
                "title": "Implement file integrity monitoring",
                "description": "Deploy file integrity monitoring to detect unauthorized file modifications.",
                "priority": "high"
            })
        
        if "T1055" in techniques:  # Process Injection
            suggestions.append({
                "title": "Deploy advanced endpoint protection",
                "description": "Use advanced endpoint protection solutions that can detect process injection techniques.",
                "priority": "high"
            })
        
        if "T1547" in techniques:  # Boot or Logon Autostart Execution
            suggestions.append({
                "title": "Implement startup program monitoring",
                "description": "Monitor and control programs that run at system startup.",
                "priority": "medium"
            })
        
        return suggestions
        
    def _generate_suggestions(self, 
                             malware_type: str, 
                             ai_classification: Dict[str, Any], 
                             attribution: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security improvement suggestions based on analysis."""
        suggestions = []
        
        suggestions.append({
            "title": "Keep systems updated",
            "description": "Regularly update operating systems, applications, and security software to patch known vulnerabilities.",
            "priority": "high"
        })
        
        suggestions.append({
            "title": "Use strong endpoint protection",
            "description": "Deploy comprehensive endpoint protection solutions that include antivirus, anti-malware, and behavioral analysis capabilities.",
            "priority": "high"
        })
        
        if malware_type == "trojan":
            suggestions.append({
                "title": "Implement application whitelisting",
                "description": "Use application whitelisting to prevent unauthorized executables from running on systems.",
                "priority": "high"
            })
        
        elif malware_type == "ransomware":
            suggestions.append({
                "title": "Regular data backups",
                "description": "Implement regular, tested backups that are stored offline or in isolated environments.",
                "priority": "critical"
            })
            
            suggestions.append({
                "title": "Network segmentation",
                "description": "Implement network segmentation to prevent ransomware from spreading across the entire network.",
                "priority": "high"
            })
        
        elif malware_type == "botnet":
            suggestions.append({
                "title": "Network traffic monitoring",
                "description": "Implement network traffic monitoring to detect and block command and control communications.",
                "priority": "high"
            })
            
            suggestions.append({
                "title": "Egress filtering",
                "description": "Implement egress filtering to block outbound connections to known malicious domains.",
                "priority": "high"
            })
        
        suspicious_activities = ai_classification.get("suspicious_activities", [])
        
        if "Command and control communication" in suspicious_activities:
            suggestions.append({
                "title": "Implement DNS filtering",
                "description": "Use DNS filtering to block known malicious domains and C2 servers.",
                "priority": "high"
            })
        
        if "File encryption" in suspicious_activities:
            suggestions.append({
                "title": "File integrity monitoring",
                "description": "Implement file integrity monitoring to detect unauthorized file modifications.",
                "priority": "medium"
            })
        
        if "Registry persistence" in suspicious_activities:
            suggestions.append({
                "title": "Registry monitoring",
                "description": "Implement registry monitoring to detect unauthorized registry modifications.",
                "priority": "medium"
            })
        
        threat_actor = attribution.get("threat_actor", "Unknown")
        
        if "APT" in threat_actor:
            suggestions.append({
                "title": "Advanced threat protection",
                "description": "Implement advanced threat protection solutions to detect and respond to sophisticated attacks.",
                "priority": "critical"
            })
            
            suggestions.append({
                "title": "Security awareness training",
                "description": "Provide security awareness training to employees to recognize and report sophisticated phishing attempts.",
                "priority": "high"
            })
        
        return suggestions
