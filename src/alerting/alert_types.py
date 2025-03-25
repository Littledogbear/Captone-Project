"""
Alert Types Module.

This module defines the different types of alerts that can be generated
by the real-time monitoring system.
"""

from enum import Enum, auto
from typing import Dict, Any, List

class AlertSeverity(Enum):
    """Severity levels for alerts."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()
    
    @classmethod
    def from_string(cls, severity_str: str) -> 'AlertSeverity':
        """Convert string to AlertSeverity enum."""
        severity_map = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
            "INFO": cls.INFO
        }
        return severity_map.get(severity_str.upper(), cls.INFO)
    
    def to_string(self) -> str:
        """Convert AlertSeverity enum to string."""
        return self.name

class AlertType(Enum):
    """Types of alerts that can be generated."""
    SUSPICIOUS_PROCESS = auto()
    SUSPICIOUS_NETWORK = auto()
    SUSPICIOUS_FILE = auto()
    SUSPICIOUS_REGISTRY = auto()
    RESOURCE_ANOMALY = auto()
    MALWARE_DETECTED = auto()
    ATTACK_TECHNIQUE = auto()
    SYSTEM_CHANGE = auto()
    
    @classmethod
    def from_string(cls, type_str: str) -> 'AlertType':
        """Convert string to AlertType enum."""
        type_map = {
            "SUSPICIOUS_PROCESS": cls.SUSPICIOUS_PROCESS,
            "SUSPICIOUS_NETWORK": cls.SUSPICIOUS_NETWORK,
            "SUSPICIOUS_FILE": cls.SUSPICIOUS_FILE,
            "SUSPICIOUS_REGISTRY": cls.SUSPICIOUS_REGISTRY,
            "RESOURCE_ANOMALY": cls.RESOURCE_ANOMALY,
            "MALWARE_DETECTED": cls.MALWARE_DETECTED,
            "ATTACK_TECHNIQUE": cls.ATTACK_TECHNIQUE,
            "SYSTEM_CHANGE": cls.SYSTEM_CHANGE
        }
        return type_map.get(type_str.upper(), cls.SYSTEM_CHANGE)
    
    def to_string(self) -> str:
        """Convert AlertType enum to string."""
        return self.name

class Alert:
    """
    Alert class representing a security alert.
    
    This class encapsulates all information related to a security alert,
    including its type, severity, description, and related data.
    """
    
    def __init__(self, 
                alert_type: AlertType,
                severity: AlertSeverity,
                title: str,
                description: str,
                timestamp: str,
                source: str,
                data: Dict[str, Any] = None):
        """
        Initialize an Alert.
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            title: Alert title
            description: Detailed description
            timestamp: ISO format timestamp
            source: Source of the alert (e.g., "real_time_monitor")
            data: Additional data related to the alert
        """
        self.alert_type = alert_type
        self.severity = severity
        self.title = title
        self.description = description
        self.timestamp = timestamp
        self.source = source
        self.data = data or {}
        self.acknowledged = False
        self.resolved = False
        self.resolution_notes = ""
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert Alert to dictionary."""
        return {
            "alert_type": self.alert_type.to_string(),
            "severity": self.severity.to_string(),
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp,
            "source": self.source,
            "data": self.data,
            "acknowledged": self.acknowledged,
            "resolved": self.resolved,
            "resolution_notes": self.resolution_notes
        }
    
    @classmethod
    def from_dict(cls, alert_dict: Dict[str, Any]) -> 'Alert':
        """Create Alert from dictionary."""
        alert = cls(
            alert_type=AlertType.from_string(alert_dict.get("alert_type", "SYSTEM_CHANGE")),
            severity=AlertSeverity.from_string(alert_dict.get("severity", "INFO")),
            title=alert_dict.get("title", "Unknown Alert"),
            description=alert_dict.get("description", ""),
            timestamp=alert_dict.get("timestamp", ""),
            source=alert_dict.get("source", "unknown"),
            data=alert_dict.get("data", {})
        )
        alert.acknowledged = alert_dict.get("acknowledged", False)
        alert.resolved = alert_dict.get("resolved", False)
        alert.resolution_notes = alert_dict.get("resolution_notes", "")
        return alert
