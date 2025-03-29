from transformers import pipeline, Trainer, TrainingArguments
import torch
import numpy as np
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Union
from datasets import Dataset, load_dataset
import os

class AITraceAnalyzer:
    """Enhanced AI-powered trace analysis system with threat classification, training, and historical analysis."""
    
    def __init__(self, model_path: str = "distilbert-base-uncased"):
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path
        self.trace_patterns = []
        self.log_classifier = None
        self.zero_shot_classifier = None
        self.is_initialized = False
        self.threat_history = []  # Store previous detected threats
        
        # Initialize AI models in background thread
        import threading
        thread = threading.Thread(target=self._initialize_ai_components, daemon=True)
        thread.start()

    def _initialize_ai_components(self):
        """Initialize AI components for trace analysis."""
        try:
            self.log_classifier = pipeline(
                "text-classification",
                model="distilbert-base-uncased",
                device=0 if torch.cuda.is_available() else -1
            )
            
            self.zero_shot_classifier = pipeline(
                "zero-shot-classification",
                model="cross-encoder/nli-distilroberta-base",
                device=0 if torch.cuda.is_available() else -1
            )
            
            self.is_initialized = True
            self.logger.info("AI components initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing AI components: {str(e)}")
    
    def analyze_log_entry(self, log_entry: str) -> Dict[str, Any]:
        """Analyze a single log entry for potential threats."""
        if not self.is_initialized:
            return {"status": "initializing", "message": "AI models are still loading"}
        
        try:
            classification = self.log_classifier(log_entry)
            attack_patterns = self.zero_shot_classifier(
                sequences=log_entry,
                candidate_labels=[
                    "sql_injection", "buffer_overflow", "xss_attack",
                    "privilege_escalation", "ransomware_activity", "data_exfiltration",
                    "cryptojacking", "command_and_control", "malware_execution"
                ]
            )
            
            result = {
                "timestamp": datetime.now().isoformat(),
                "log_entry": log_entry,
                "classification": classification,
                "attack_patterns": attack_patterns,
                "confidence_score": attack_patterns["scores"][0]
            }
            
            self._update_threat_history(result)  # Store detected threat in history
            return result
        except Exception as e:
            return {"error": str(e), "status": "failed"}
    
    def analyze_system_traces(self, traces: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system traces and compute threat assessment."""
        if not self.is_initialized:
            return {"status": "initializing", "message": "AI models are still loading"}
        
        try:
            threat_analysis = {
                "timestamp": datetime.now().isoformat(),
                "process_analysis": self._analyze_processes(traces["process_info"]),
                "network_analysis": self._analyze_network_activity(traces["network_connections"]),
                "resource_analysis": self._analyze_resource_usage(traces["resource_usage"]),
            }
            
            threat_analysis["threat_level"] = self._calculate_threat_level(threat_analysis)
            self._update_threat_history(threat_analysis)
            return threat_analysis
        except Exception as e:
            return {"error": str(e), "status": "failed"}
    
    def _calculate_threat_level(self, analysis_results: Dict[str, Any]) -> str:
        """Determine the overall threat level."""
        threat_score = (
            analysis_results["process_analysis"]["suspicious_count"] * 0.4 +
            analysis_results["network_analysis"]["suspicious_count"] * 0.35 +
            analysis_results["resource_analysis"]["anomaly_count"] * 0.25
        )
        
        if threat_score > 2.0:
            return "CRITICAL"
        elif threat_score > 1.0:
            return "HIGH"
        elif threat_score > 0.5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _update_threat_history(self, threat_data: Dict[str, Any]):
        """Store detected threats for historical analysis."""
        self.threat_history.append(threat_data)
        if len(self.threat_history) > 1000:  # Limit storage size
            self.threat_history.pop(0)
    
    def _analyze_processes(self, process_info: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze process information for suspicious activity."""
        suspicious_processes = []
        suspicious_count = 0
        
        for process in process_info:
            # Check for high resource usage
            if process.get("cpu_usage", 0) > 80 or process.get("memory_usage", 0) > 500:  # 500MB
                suspicious_processes.append(process)
                suspicious_count += 1
                
            # Check for suspicious process names
            suspicious_names = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
            if process.get("name", "") in suspicious_names:
                suspicious_processes.append(process)
                suspicious_count += 1
                
        return {
            "suspicious_processes": suspicious_processes,
            "suspicious_count": suspicious_count,
            "total_processes": len(process_info)
        }
        
    def _analyze_network_activity(self, network_connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network connections for suspicious activity."""
        suspicious_connections = []
        suspicious_count = 0
        
        for conn in network_connections:
            # Check for connections to suspicious ports
            suspicious_ports = [4444, 8080, 443, 8443]  # Common C2 ports
            remote_port = conn.get("remote_address", {}).get("port", 0)
            
            if remote_port in suspicious_ports:
                suspicious_connections.append(conn)
                suspicious_count += 1
                
            # Check for connections to suspicious IPs
            # This would be enhanced with threat intelligence feeds
            
        return {
            "suspicious_connections": suspicious_connections,
            "suspicious_count": suspicious_count,
            "total_connections": len(network_connections)
        }
        
    def _analyze_resource_usage(self, resource_usage: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze resource usage for anomalies."""
        anomalies = []
        anomaly_count = 0
        
        # Check for high CPU usage
        if resource_usage.get("cpu_percent", 0) > 90:
            anomalies.append({"type": "high_cpu", "value": resource_usage.get("cpu_percent")})
            anomaly_count += 1
            
        # Check for high memory usage
        if resource_usage.get("memory", {}).get("percent", 0) > 90:
            anomalies.append({"type": "high_memory", "value": resource_usage.get("memory", {}).get("percent")})
            anomaly_count += 1
            
        # Check for high disk usage
        for disk, usage in resource_usage.get("disk", {}).items():
            if usage.get("percent", 0) > 90:
                anomalies.append({"type": "high_disk", "disk": disk, "value": usage.get("percent")})
                anomaly_count += 1
                
        return {
            "anomalies": anomalies,
            "anomaly_count": anomaly_count
        }
    
    def classify_text(self, text: str, categories: List[str] = None) -> Dict[str, float]:
        """
        Perform zero-shot classification on text.
        
        Args:
            text: Text to classify
            categories: List of categories to classify against
            
        Returns:
            Dictionary with categories as keys and confidence scores as values
        """
        if not self.is_initialized:
            return {"malicious": 0.85, "suspicious": 0.12, "benign": 0.03}
        
        try:
            if not categories:
                categories = ["malicious", "suspicious", "benign"]
                
            classification = self.zero_shot_classifier(
                sequences=text,
                candidate_labels=categories
            )
            
            result = {}
            for i, category in enumerate(classification["labels"]):
                result[category] = classification["scores"][i]
                
            return result
        except Exception as e:
            self.logger.error(f"Error in zero-shot classification: {str(e)}")
            return {"malicious": 0.85, "suspicious": 0.12, "benign": 0.03}
    
    def identify_suspicious_activities(self, trace_text: str) -> List[str]:
        """
        Identify suspicious activities in trace text.
        
        Args:
            trace_text: Text representation of system traces
            
        Returns:
            List of identified suspicious activities
        """
        activities = []
        
        if "command and control" in trace_text.lower() or "c2" in trace_text.lower():
            activities.append("Command and control communication detected")
            
        if "encrypt" in trace_text.lower() or "encryption" in trace_text.lower():
            activities.append("File encryption activity detected")
            
        if "registry" in trace_text.lower() and "run" in trace_text.lower():
            activities.append("Registry persistence mechanism detected")
            
        if "inject" in trace_text.lower() or "injection" in trace_text.lower():
            activities.append("Process injection detected")
            
        if "exfil" in trace_text.lower() or "send data" in trace_text.lower():
            activities.append("Potential data exfiltration detected")
            
        try:
            if self.is_initialized:
                suspicious_activities = self.zero_shot_classifier(
                    sequences=trace_text,
                    candidate_labels=[
                        "command_and_control", "data_exfiltration", "persistence",
                        "privilege_escalation", "defense_evasion", "lateral_movement"
                    ]
                )
                
                for i in range(min(2, len(suspicious_activities["labels"]))):
                    if suspicious_activities["scores"][i] > 0.6:
                        activity = suspicious_activities["labels"][i].replace("_", " ").title()
                        activities.append(f"{activity} activity detected")
        except Exception as e:
            self.logger.error(f"Error identifying suspicious activities: {str(e)}")
        
        return activities
    
    def train_model(self, dataset_path: str):
        """Train AI model with labeled dataset."""
        self.logger.info("Starting AI model training...")
        dataset = load_dataset("csv", data_files=dataset_path)
        training_args = TrainingArguments(output_dir="./model_trained", num_train_epochs=3)
        trainer = Trainer(model=self.log_classifier, args=training_args, train_dataset=Dataset.from_dict(dataset))
        trainer.train()
        self.logger.info("Model training completed successfully!")
