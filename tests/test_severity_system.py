"""
Test module for the severity-based warning system.

This module contains tests for the severity manager, severity UI, and severity notifier
components of the cyber attack trace analyzer.
"""

import os
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.alerting.alert_types import Alert, AlertType, AlertSeverity
from src.alerting.severity_manager import SeverityManager, ThreatCategory
from src.alerting.severity_ui import SeverityUI
from src.alerting.severity_notifier import SeverityNotifier
from src.utils.platform_detector import PlatformDetector

class TestSeverityManager(unittest.TestCase):
    """Test cases for the SeverityManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.severity_manager = SeverityManager()
    
    def test_calculate_malware_severity(self):
        """Test calculating malware severity levels."""
        # Test critical severity
        malware_data = {
            "detection_ratio": 0.9,
            "confidence": 0.95,
            "capabilities": ["persistence", "privilege_escalation", "defense_evasion"],
            "family": "emotet"
        }
        severity = self.severity_manager.calculate_malware_severity(malware_data)
        self.assertEqual(severity, AlertSeverity.CRITICAL)
        
        # Test high severity
        malware_data = {
            "detection_ratio": 0.7,
            "confidence": 0.8,
            "capabilities": ["persistence"],
            "family": "unknown"
        }
        severity = self.severity_manager.calculate_malware_severity(malware_data)
        self.assertEqual(severity, AlertSeverity.HIGH)
        
        # Test medium severity
        malware_data = {
            "detection_ratio": 0.4,
            "confidence": 0.5,
            "capabilities": [],
            "family": "unknown"
        }
        severity = self.severity_manager.calculate_malware_severity(malware_data)
        self.assertEqual(severity, AlertSeverity.MEDIUM)
        
        # Test low severity
        malware_data = {
            "detection_ratio": 0.1,
            "confidence": 0.3,
            "capabilities": [],
            "family": "unknown"
        }
        severity = self.severity_manager.calculate_malware_severity(malware_data)
        self.assertEqual(severity, AlertSeverity.LOW)
    
    def test_calculate_technique_severity(self):
        """Test calculating technique severity levels."""
        # Test critical severity
        technique_data = {
            "confidence": 0.95,
            "tactic": "privilege-escalation",
            "subtechniques": ["T1234.001", "T1234.002", "T1234.003"]
        }
        severity = self.severity_manager.calculate_technique_severity(technique_data)
        self.assertEqual(severity, AlertSeverity.CRITICAL)
        
        # Test high severity
        technique_data = {
            "confidence": 0.7,
            "tactic": "defense-evasion",
            "subtechniques": ["T1234.001"]
        }
        severity = self.severity_manager.calculate_technique_severity(technique_data)
        self.assertEqual(severity, AlertSeverity.HIGH)
        
        # Test medium severity
        technique_data = {
            "confidence": 0.5,
            "tactic": "discovery",
            "subtechniques": []
        }
        severity = self.severity_manager.calculate_technique_severity(technique_data)
        self.assertEqual(severity, AlertSeverity.MEDIUM)
        
        # Test low severity
        technique_data = {
            "confidence": 0.2,
            "tactic": "discovery",
            "subtechniques": []
        }
        severity = self.severity_manager.calculate_technique_severity(technique_data)
        self.assertEqual(severity, AlertSeverity.LOW)
    
    def test_calculate_overall_severity(self):
        """Test calculating overall severity from multiple alerts."""
        # Test with critical alerts
        alerts = [
            {"severity": "CRITICAL", "type": "malware"},
            {"severity": "HIGH", "type": "technique"},
            {"severity": "MEDIUM", "type": "network"}
        ]
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.CRITICAL)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 1)
        self.assertEqual(counts["MEDIUM"], 1)
        
        # Test with high alerts but no critical
        alerts = [
            {"severity": "HIGH", "type": "technique"},
            {"severity": "MEDIUM", "type": "network"},
            {"severity": "LOW", "type": "file"}
        ]
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.HIGH)
        
        # Test with medium alerts but no high or critical
        alerts = [
            {"severity": "MEDIUM", "type": "network"},
            {"severity": "LOW", "type": "file"},
            {"severity": "INFO", "type": "system"}
        ]
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.MEDIUM)
        
        # Test with only low alerts
        alerts = [
            {"severity": "LOW", "type": "file"},
            {"severity": "INFO", "type": "system"}
        ]
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.LOW)
        
        # Test with only info alerts
        alerts = [
            {"severity": "INFO", "type": "system"}
        ]
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.INFO)
        
        # Test with empty alerts
        alerts = []
        overall_severity, counts = self.severity_manager.calculate_overall_severity(alerts)
        self.assertEqual(overall_severity, AlertSeverity.INFO)
        self.assertEqual(counts, {})

class TestSeverityUI(unittest.TestCase):
    """Test cases for the SeverityUI class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.severity_ui = SeverityUI()
    
    def test_create_severity_indicator(self):
        """Test creating severity indicators."""
        # Test critical severity indicator
        html = self.severity_ui.create_severity_indicator(
            AlertSeverity.CRITICAL,
            "Malware Detected",
            "Critical malware detected in system"
        )
        self.assertIsInstance(html, str)
        self.assertIn("critical", html.lower())
        self.assertIn("Malware Detected", html)
        
        # Test high severity indicator
        html = self.severity_ui.create_severity_indicator(
            "HIGH",
            "Suspicious Network Activity",
            "High risk network activity detected"
        )
        self.assertIsInstance(html, str)
        self.assertIn("high", html.lower())
        self.assertIn("Suspicious Network Activity", html)
    
    def test_get_severity_color(self):
        """Test getting severity colors."""
        # Test critical severity color
        color = self.severity_ui.get_severity_color(AlertSeverity.CRITICAL)
        self.assertIsInstance(color, str)
        self.assertTrue(color.startswith("#"))
        
        # Test high severity color
        color = self.severity_ui.get_severity_color("HIGH")
        self.assertIsInstance(color, str)
        self.assertTrue(color.startswith("#"))
        
        # Test medium severity color
        color = self.severity_ui.get_severity_color(AlertSeverity.MEDIUM)
        self.assertIsInstance(color, str)
        self.assertTrue(color.startswith("#"))
        
        # Test low severity color
        color = self.severity_ui.get_severity_color("LOW")
        self.assertIsInstance(color, str)
        self.assertTrue(color.startswith("#"))
        
        # Test info severity color
        color = self.severity_ui.get_severity_color(AlertSeverity.INFO)
        self.assertIsInstance(color, str)
        self.assertTrue(color.startswith("#"))

class TestSeverityNotifier(unittest.TestCase):
    """Test cases for the SeverityNotifier class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.severity_notifier = SeverityNotifier()
        
        # Create test alerts
        self.critical_alert = Alert(
            alert_type=AlertType.MALWARE_DETECTED,
            severity=AlertSeverity.CRITICAL,
            title="Critical Malware Detected",
            description="A critical malware has been detected in the system",
            timestamp=datetime.now().isoformat(),
            source="test",
            data={"malware_name": "test_malware"}
        )
        
        self.high_alert = Alert(
            alert_type=AlertType.SUSPICIOUS_NETWORK,
            severity=AlertSeverity.HIGH,
            title="Suspicious Network Activity",
            description="High risk network activity detected",
            timestamp=datetime.now().isoformat(),
            source="test",
            data={"connection": {"remote_ip": "192.168.1.1"}}
        )
    
    @patch('subprocess.run')
    def test_notify_windows(self, mock_subprocess):
        """Test Windows notification."""
        # Mock platform detector to return Windows
        with patch('src.utils.platform_detector.PlatformDetector.is_windows', return_value=True):
            with patch('src.utils.platform_detector.PlatformDetector.is_mac', return_value=False):
                # Test notification
                result = self.severity_notifier._notify_windows(self.critical_alert)
                self.assertTrue(result)
                mock_subprocess.assert_called_once()
    
    @patch('subprocess.run')
    def test_notify_mac(self, mock_subprocess):
        """Test Mac notification."""
        # Mock platform detector to return Mac
        with patch('src.utils.platform_detector.PlatformDetector.is_windows', return_value=False):
            with patch('src.utils.platform_detector.PlatformDetector.is_mac', return_value=True):
                # Test notification
                result = self.severity_notifier._notify_mac(self.high_alert)
                self.assertTrue(result)
                mock_subprocess.assert_called_once()
    
    def test_create_severity_summary(self):
        """Test creating severity summary."""
        # Create test alerts
        alerts = [
            self.critical_alert,
            self.high_alert,
            Alert(
                alert_type=AlertType.SUSPICIOUS_FILE,
                severity=AlertSeverity.MEDIUM,
                title="Suspicious File Activity",
                description="Medium risk file activity detected",
                timestamp=datetime.now().isoformat(),
                source="test",
                data={"file_path": "/tmp/test.exe"}
            )
        ]
        
        # Test summary creation
        summary = self.severity_notifier.create_severity_summary(alerts)
        self.assertIsInstance(summary, dict)
        self.assertEqual(summary["overall_severity"], "CRITICAL")
        self.assertEqual(summary["counts"]["CRITICAL"], 1)
        self.assertEqual(summary["counts"]["HIGH"], 1)
        self.assertEqual(summary["counts"]["MEDIUM"], 1)
        self.assertEqual(summary["total"], 3)

class TestCrossPlatformSupport(unittest.TestCase):
    """Test cases for cross-platform support."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.platform_detector = PlatformDetector()
        self.severity_manager = SeverityManager()
        self.severity_ui = SeverityUI()
        self.severity_notifier = SeverityNotifier()
    
    def test_platform_detection(self):
        """Test platform detection."""
        platform = self.platform_detector.get_platform()
        self.assertIn(platform, ["windows", "mac", "linux", "unknown"])
        
        # Test platform-specific methods
        is_windows = self.platform_detector.is_windows()
        is_mac = self.platform_detector.is_mac()
        
        # One of these should be True if we're on Windows or Mac
        if platform in ["windows", "mac"]:
            self.assertTrue(is_windows or is_mac)
    
    def test_platform_specific_ui(self):
        """Test platform-specific UI elements."""
        # Test platform-specific warning
        warning = self.severity_ui.get_platform_specific_warning(
            AlertSeverity.CRITICAL,
            "Test Warning",
            "This is a test warning"
        )
        
        self.assertIsInstance(warning, dict)
        self.assertEqual(warning["severity"], "CRITICAL")
        self.assertEqual(warning["title"], "Test Warning")
        self.assertEqual(warning["description"], "This is a test warning")
        
        # Platform should be one of these
        self.assertIn(warning["platform"], ["windows", "mac", "unknown"])
        
        # Notification type should be platform-specific
        if warning["platform"] == "windows":
            self.assertEqual(warning["notification_type"], "toast")
        elif warning["platform"] == "mac":
            self.assertEqual(warning["notification_type"], "notification-center")
        else:
            self.assertEqual(warning["notification_type"], "console")

if __name__ == "__main__":
    unittest.main()
