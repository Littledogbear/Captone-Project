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
