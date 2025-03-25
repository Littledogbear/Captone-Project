"""
Severity Manager Module.

This module provides functionality for managing and calculating severity levels
for different types of cyber threats and malware.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Union, Tuple
from enum import Enum, auto
from datetime import datetime

from src.alerting.alert_types import AlertSeverity
from src.utils.config import load_config

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """Categories of cyber threats."""
    MALWARE = auto()
    NETWORK_ATTACK = auto()
    PRIVILEGE_ESCALATION = auto()
    DATA_EXFILTRATION = auto()
    PERSISTENCE = auto()
    DEFENSE_EVASION = auto()
    CREDENTIAL_ACCESS = auto()
    DISCOVERY = auto()
    LATERAL_MOVEMENT = auto()
    EXECUTION = auto()
    COMMAND_AND_CONTROL = auto()
    IMPACT = auto()
    UNKNOWN = auto()
    
    @classmethod
    def from_string(cls, category_str: str) -> 'ThreatCategory':
        """Convert string to ThreatCategory enum."""
        category_map = {
            "MALWARE": cls.MALWARE,
            "NETWORK_ATTACK": cls.NETWORK_ATTACK,
            "PRIVILEGE_ESCALATION": cls.PRIVILEGE_ESCALATION,
            "DATA_EXFILTRATION": cls.DATA_EXFILTRATION,
            "PERSISTENCE": cls.PERSISTENCE,
            "DEFENSE_EVASION": cls.DEFENSE_EVASION,
            "CREDENTIAL_ACCESS": cls.CREDENTIAL_ACCESS,
            "DISCOVERY": cls.DISCOVERY,
            "LATERAL_MOVEMENT": cls.LATERAL_MOVEMENT,
            "EXECUTION": cls.EXECUTION,
            "COMMAND_AND_CONTROL": cls.COMMAND_AND_CONTROL,
            "IMPACT": cls.IMPACT
        }
        return category_map.get(category_str.upper(), cls.UNKNOWN)
    
    def to_string(self) -> str:
        """Convert ThreatCategory enum to string."""
        return self.name

class SeverityManager:
    """
    Manages severity levels for different types of cyber threats.
    
    This class is responsible for:
    1. Calculating severity levels for different types of threats
    2. Providing severity-based warning messages
    3. Managing severity thresholds and configurations
    4. Tracking severity history for trend analysis
    """
    
    def __init__(self):
        """Initialize the SeverityManager."""
        self.config = load_config().get("severity", {})
        self.severity_history = []
        self.max_history = self.config.get("max_history", 1000)
        
        # Load severity thresholds
        self._load_severity_thresholds()
        
        # Initialize severity indicators
        self._init_severity_indicators()
    
    def _load_severity_thresholds(self):
        """Load severity thresholds from configuration."""
        self.malware_thresholds = self.config.get("malware_thresholds", {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.4,
            "LOW": 0.1
        })
        
        self.technique_thresholds = self.config.get("technique_thresholds", {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.4,
            "LOW": 0.1
        })
        
        self.resource_thresholds = self.config.get("resource_thresholds", {
            "CRITICAL": 95,
            "HIGH": 90,
            "MEDIUM": 80,
            "LOW": 70
        })
        
        self.network_thresholds = self.config.get("network_thresholds", {
            "CRITICAL": 0.9,
            "HIGH": 0.7,
            "MEDIUM": 0.4,
            "LOW": 0.1
        })
    
    def _init_severity_indicators(self):
        """Initialize severity indicators for UI."""
        self.severity_indicators = {
            "CRITICAL": {
                "color": "#FF0000",  # Red
                "icon": "exclamation-triangle",
                "description": "Critical severity threats require immediate attention and pose significant risk to the system.",
                "recommended_action": "Immediately isolate affected systems and initiate incident response procedures."
            },
            "HIGH": {
                "color": "#FFA500",  # Orange
                "icon": "exclamation-circle",
                "description": "High severity threats pose substantial risk and should be addressed promptly.",
                "recommended_action": "Investigate and remediate as soon as possible, following security protocols."
            },
            "MEDIUM": {
                "color": "#FFFF00",  # Yellow
                "icon": "exclamation",
                "description": "Medium severity threats pose moderate risk and should be addressed in a timely manner.",
                "recommended_action": "Investigate and plan for remediation according to security policies."
            },
            "LOW": {
                "color": "#00BFFF",  # Light Blue
                "icon": "info-circle",
                "description": "Low severity threats pose minimal immediate risk but should be monitored.",
                "recommended_action": "Monitor and address during regular maintenance cycles."
            },
            "INFO": {
                "color": "#808080",  # Gray
                "icon": "info",
                "description": "Informational alerts provide context but do not indicate a threat.",
                "recommended_action": "No action required, for informational purposes only."
            }
        }
    
    def calculate_malware_severity(self, malware_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for malware.
        
        Args:
            malware_data: Dictionary containing malware analysis data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        detection_ratio = malware_data.get("detection_ratio", 0.0)
        confidence = malware_data.get("confidence", 0.0)
        capabilities = malware_data.get("capabilities", [])
        family = malware_data.get("family", "")
        
        # Start with base score from detection ratio
        base_score = detection_ratio
        
        # Adjust based on confidence
        base_score = base_score * (0.5 + (confidence * 0.5))
        
        # Adjust based on capabilities
        high_risk_capabilities = [
            "persistence", "privilege_escalation", "defense_evasion",
            "credential_access", "lateral_movement", "data_exfiltration"
        ]
        
        capability_score = 0
        for capability in capabilities:
            if capability.lower() in high_risk_capabilities:
                capability_score += 0.1
        
        # Cap capability adjustment
        capability_score = min(capability_score, 0.5)
        
        # Adjust based on known malware families
        high_risk_families = self.config.get("high_risk_families", [
            "emotet", "trickbot", "ryuk", "wannacry", "petya", "notpetya",
            "locky", "cerber", "cryptolocker", "maze", "revil", "darkside"
        ])
        
        family_adjustment = 0.2 if any(f.lower() in family.lower() for f in high_risk_families) else 0
        
        # Calculate final score
        final_score = min(base_score + capability_score + family_adjustment, 1.0)
        
        # Determine severity level
        if final_score >= self.malware_thresholds.get("CRITICAL", 0.9):
            return AlertSeverity.CRITICAL
        elif final_score >= self.malware_thresholds.get("HIGH", 0.7):
            return AlertSeverity.HIGH
        elif final_score >= self.malware_thresholds.get("MEDIUM", 0.4):
            return AlertSeverity.MEDIUM
        elif final_score >= self.malware_thresholds.get("LOW", 0.1):
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_technique_severity(self, technique_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for attack techniques.
        
        Args:
            technique_data: Dictionary containing attack technique data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        confidence = technique_data.get("confidence", 0.0)
        tactic = technique_data.get("tactic", "")
        subtechniques = technique_data.get("subtechniques", [])
        
        # Start with base score from confidence
        base_score = confidence
        
        # Adjust based on tactic
        high_risk_tactics = [
            "privilege-escalation", "defense-evasion", "credential-access",
            "exfiltration", "impact", "command-and-control"
        ]
        
        tactic_adjustment = 0.2 if any(t.lower() in tactic.lower() for t in high_risk_tactics) else 0
        
        # Adjust based on number of subtechniques
        subtechnique_adjustment = min(len(subtechniques) * 0.05, 0.2)
        
        # Calculate final score
        final_score = min(base_score + tactic_adjustment + subtechnique_adjustment, 1.0)
        
        # Determine severity level
        if final_score >= self.technique_thresholds.get("CRITICAL", 0.9):
            return AlertSeverity.CRITICAL
        elif final_score >= self.technique_thresholds.get("HIGH", 0.7):
            return AlertSeverity.HIGH
        elif final_score >= self.technique_thresholds.get("MEDIUM", 0.4):
            return AlertSeverity.MEDIUM
        elif final_score >= self.technique_thresholds.get("LOW", 0.1):
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_resource_severity(self, resource_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for resource anomalies.
        
        Args:
            resource_data: Dictionary containing resource usage data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        resource_type = resource_data.get("resource", "")
        value = resource_data.get("value", 0)
        duration = resource_data.get("duration", 0)  # Duration in seconds
        
        # Adjust based on duration
        duration_factor = min(duration / 300, 1.0)  # Normalize to max of 5 minutes
        
        # Calculate adjusted value
        adjusted_value = value * (1 + (duration_factor * 0.2))
        
        # Determine severity level
        if adjusted_value >= self.resource_thresholds.get("CRITICAL", 95):
            return AlertSeverity.CRITICAL
        elif adjusted_value >= self.resource_thresholds.get("HIGH", 90):
            return AlertSeverity.HIGH
        elif adjusted_value >= self.resource_thresholds.get("MEDIUM", 80):
            return AlertSeverity.MEDIUM
        elif adjusted_value >= self.resource_thresholds.get("LOW", 70):
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_network_severity(self, network_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for network anomalies.
        
        Args:
            network_data: Dictionary containing network anomaly data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        connection_type = network_data.get("connection_type", "")
        remote_ip = network_data.get("remote_ip", "")
        remote_port = network_data.get("remote_port", 0)
        payload_size = network_data.get("payload_size", 0)
        protocol = network_data.get("protocol", "")
        
        # Start with base score
        base_score = 0.0
        
        # Adjust based on connection type
        if connection_type.lower() == "outbound":
            base_score += 0.3
        
        # Adjust based on port
        high_risk_ports = [4444, 1337, 31337, 8080, 6666, 6667, 6668, 6669]
        if remote_port in high_risk_ports:
            base_score += 0.3
        
        # Adjust based on protocol
        if protocol.lower() in ["http", "https"] and remote_port not in [80, 443, 8080, 8443]:
            base_score += 0.2
        
        # Adjust based on payload size
        if payload_size > 1000000:  # 1MB
            base_score += 0.2
        
        # Calculate final score
        final_score = min(base_score, 1.0)
        
        # Determine severity level
        if final_score >= self.network_thresholds.get("CRITICAL", 0.9):
            return AlertSeverity.CRITICAL
        elif final_score >= self.network_thresholds.get("HIGH", 0.7):
            return AlertSeverity.HIGH
        elif final_score >= self.network_thresholds.get("MEDIUM", 0.4):
            return AlertSeverity.MEDIUM
        elif final_score >= self.network_thresholds.get("LOW", 0.1):
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_file_severity(self, file_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for suspicious file activities.
        
        Args:
            file_data: Dictionary containing file activity data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        path = file_data.get("path", "").lower()
        operation = file_data.get("operation", "").lower()
        process = file_data.get("process", {})
        
        # Start with base score
        base_score = 0.0
        
        # Adjust based on operation
        if operation in ["write", "modify", "delete"]:
            base_score += 0.3
        elif operation in ["create", "rename"]:
            base_score += 0.2
        
        # Adjust based on file extension
        high_risk_extensions = [".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js"]
        if any(path.endswith(ext) for ext in high_risk_extensions):
            base_score += 0.3
        
        # Adjust based on path
        sensitive_paths = [
            "system32", "drivers", "boot", 
            "windows\\security", "program files", 
            "hosts", "lsass.exe"
        ]
        if any(p in path for p in sensitive_paths):
            base_score += 0.3
        
        # Adjust based on process
        suspicious_processes = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
        process_name = process.get("name", "").lower()
        if any(p in process_name for p in suspicious_processes):
            base_score += 0.2
        
        # Calculate final score
        final_score = min(base_score, 1.0)
        
        # Determine severity level
        if final_score >= 0.9:
            return AlertSeverity.CRITICAL
        elif final_score >= 0.7:
            return AlertSeverity.HIGH
        elif final_score >= 0.4:
            return AlertSeverity.MEDIUM
        elif final_score >= 0.1:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_registry_severity(self, registry_data: Dict[str, Any]) -> AlertSeverity:
        """
        Calculate severity level for suspicious registry activities.
        
        Args:
            registry_data: Dictionary containing registry activity data
            
        Returns:
            AlertSeverity enum representing the severity level
        """
        # Extract relevant data
        key = registry_data.get("key", "").lower()
        operation = registry_data.get("operation", "").lower()
        value = str(registry_data.get("value", "")).lower()
        process = registry_data.get("process", {})
        
        # Start with base score
        base_score = 0.0
        
        # Adjust based on operation
        if operation in ["set", "create"]:
            base_score += 0.3
        elif operation in ["delete"]:
            base_score += 0.2
        
        # Adjust based on key
        high_risk_keys = [
            "run", "runonce", "userinit", "shell", "winlogon",
            "currentversion\\image file execution options",
            "policies\\explorer\\run", "windows\\system\\scripts",
            "currentcontrolset\\services"
        ]
        if any(k in key for k in high_risk_keys):
            base_score += 0.3
        
        # Adjust based on value
        suspicious_values = [".exe", "cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe"]
        if any(v in value for v in suspicious_values):
            base_score += 0.3
        
        # Adjust based on process
        suspicious_processes = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
        process_name = process.get("name", "").lower()
        if any(p in process_name for p in suspicious_processes):
            base_score += 0.2
        
        # Calculate final score
        final_score = min(base_score, 1.0)
        
        # Determine severity level
        if final_score >= 0.9:
            return AlertSeverity.CRITICAL
        elif final_score >= 0.7:
            return AlertSeverity.HIGH
        elif final_score >= 0.4:
            return AlertSeverity.MEDIUM
        elif final_score >= 0.1:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def calculate_overall_severity(self, alerts: List[Dict[str, Any]]) -> Tuple[AlertSeverity, Dict[str, int]]:
        """
        Calculate overall severity level based on multiple alerts.
        
        Args:
            alerts: List of alert dictionaries
            
        Returns:
            Tuple containing overall AlertSeverity and count by severity
        """
        if not alerts:
            return AlertSeverity.INFO, {}
        
        # Count alerts by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for alert in alerts:
            severity = alert.get("severity", "INFO")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Determine overall severity
        if severity_counts["CRITICAL"] > 0:
            return AlertSeverity.CRITICAL, severity_counts
        elif severity_counts["HIGH"] > 0:
            return AlertSeverity.HIGH, severity_counts
        elif severity_counts["MEDIUM"] > 0:
            return AlertSeverity.MEDIUM, severity_counts
        elif severity_counts["LOW"] > 0:
            return AlertSeverity.LOW, severity_counts
        else:
            return AlertSeverity.INFO, severity_counts
    
    def get_severity_indicator(self, severity: Union[str, AlertSeverity]) -> Dict[str, Any]:
        """
        Get UI indicator information for a severity level.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            
        Returns:
            Dictionary with UI indicator information
        """
        if isinstance(severity, AlertSeverity):
            severity = severity.to_string()
        
        return self.severity_indicators.get(severity, self.severity_indicators["INFO"])
    
    def get_severity_description(self, severity: Union[str, AlertSeverity]) -> str:
        """
        Get description for a severity level.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            
        Returns:
            Description string
        """
        indicator = self.get_severity_indicator(severity)
        return indicator.get("description", "")
    
    def get_recommended_action(self, severity: Union[str, AlertSeverity]) -> str:
        """
        Get recommended action for a severity level.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            
        Returns:
            Recommended action string
        """
        indicator = self.get_severity_indicator(severity)
        return indicator.get("recommended_action", "")
    
    def record_severity(self, severity: Union[str, AlertSeverity], 
                       category: Union[str, ThreatCategory],
                       details: Dict[str, Any] = None):
        """
        Record a severity level for historical tracking.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            category: Threat category as string or ThreatCategory enum
            details: Additional details about the severity
        """
        if isinstance(severity, AlertSeverity):
            severity = severity.to_string()
        
        if isinstance(category, ThreatCategory):
            category = category.to_string()
        
        record = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "details": details or {}
        }
        
        self.severity_history.append(record)
        
        # Trim history if needed
        if len(self.severity_history) > self.max_history:
            self.severity_history = self.severity_history[-self.max_history:]
    
    def get_severity_history(self, limit: int = 100, 
                            category: Optional[Union[str, ThreatCategory]] = None) -> List[Dict[str, Any]]:
        """
        Get severity history with optional filtering.
        
        Args:
            limit: Maximum number of records to return
            category: Filter by threat category
            
        Returns:
            List of severity history records
        """
        filtered_history = self.severity_history
        
        # Filter by category
        if category:
            if isinstance(category, ThreatCategory):
                category = category.to_string()
            
            filtered_history = [
                record for record in filtered_history
                if record.get("category") == category
            ]
        
        # Sort by timestamp (newest first)
        filtered_history = sorted(
            filtered_history,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
        
        # Limit results
        return filtered_history[:limit]
    
    def get_severity_trend(self, days: int = 7) -> Dict[str, Any]:
        """
        Get severity trend over time.
        
        Args:
            days: Number of days to include in trend
            
        Returns:
            Dictionary with severity trend data
        """
        from datetime import datetime, timedelta
        
        # Calculate start date
        start_date = datetime.now() - timedelta(days=days)
        start_date_str = start_date.isoformat()
        
        # Filter history by date
        filtered_history = [
            record for record in self.severity_history
            if record.get("timestamp", "") >= start_date_str
        ]
        
        # Group by day and severity
        trend_data = {}
        for record in filtered_history:
            timestamp = datetime.fromisoformat(record.get("timestamp", datetime.now().isoformat()))
            day_str = timestamp.strftime("%Y-%m-%d")
            severity = record.get("severity", "INFO")
            
            if day_str not in trend_data:
                trend_data[day_str] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                    "total": 0
                }
            
            trend_data[day_str][severity] += 1
            trend_data[day_str]["total"] += 1
        
        # Fill in missing days
        current_date = start_date
        end_date = datetime.now()
        while current_date <= end_date:
            day_str = current_date.strftime("%Y-%m-%d")
            if day_str not in trend_data:
                trend_data[day_str] = {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                    "total": 0
                }
            current_date += timedelta(days=1)
        
        # Convert to list format for easier consumption
        trend_list = [
            {
                "date": day,
                "CRITICAL": data["CRITICAL"],
                "HIGH": data["HIGH"],
                "MEDIUM": data["MEDIUM"],
                "LOW": data["LOW"],
                "INFO": data["INFO"],
                "total": data["total"]
            }
            for day, data in sorted(trend_data.items())
        ]
        
        return {
            "days": days,
            "trend": trend_list
        }
