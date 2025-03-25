"""
Severity Notifier Module.

This module provides functionality for sending notifications based on
severity levels of detected threats.
"""

import logging
import os
import json
import platform
import subprocess
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

from src.alerting.alert_types import AlertSeverity, AlertType, Alert
from src.alerting.severity_manager import SeverityManager, ThreatCategory
from src.alerting.severity_ui import SeverityUI
from src.utils.platform_detector import PlatformDetector

logger = logging.getLogger(__name__)

class SeverityNotifier:
    """
    Sends notifications based on severity levels of detected threats.
    
    This class is responsible for:
    1. Sending platform-specific notifications for different severity levels
    2. Managing notification thresholds and frequency
    3. Providing visual and audible alerts based on severity
    4. Integrating with the system's native notification mechanisms
    """
    
    def __init__(self):
        """Initialize the SeverityNotifier."""
        self.severity_manager = SeverityManager()
        self.severity_ui = SeverityUI()
        self.platform_detector = PlatformDetector()
        self.platform = self.platform_detector.get_platform()
        
        # Initialize notification history
        self.notification_history = []
        self.max_history = 100
        
        # Initialize notification thresholds
        self._init_notification_thresholds()
    
    def _init_notification_thresholds(self):
        """Initialize notification thresholds."""
        self.notification_thresholds = {
            "CRITICAL": 0,    # Always notify
            "HIGH": 0,        # Always notify
            "MEDIUM": 1,      # Notify if count >= 1
            "LOW": 3,         # Notify if count >= 3
            "INFO": 10        # Notify if count >= 10
        }
        
        self.notification_cooldown = {
            "CRITICAL": 0,    # No cooldown
            "HIGH": 60,       # 1 minute
            "MEDIUM": 300,    # 5 minutes
            "LOW": 900,       # 15 minutes
            "INFO": 3600      # 1 hour
        }
    
    def notify(self, alert: Alert) -> bool:
        """
        Send a notification based on alert severity.
        
        Args:
            alert: Alert object to notify about
            
        Returns:
            True if notification was sent, False otherwise
        """
        try:
            # Check if notification should be sent based on thresholds and cooldown
            if not self._should_notify(alert):
                return False
            
            # Get severity as string
            severity = alert.severity.to_string()
            
            # Add to notification history
            self._add_to_history(alert)
            
            # Send platform-specific notification
            if self.platform_detector.is_windows():
                return self._notify_windows(alert)
            elif self.platform_detector.is_mac():
                return self._notify_mac(alert)
            else:
                return self._notify_console(alert)
        
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    def _should_notify(self, alert: Alert) -> bool:
        """
        Check if a notification should be sent for an alert.
        
        Args:
            alert: Alert to check
            
        Returns:
            True if notification should be sent, False otherwise
        """
        severity = alert.severity.to_string()
        
        # Get threshold for this severity
        threshold = self.notification_thresholds.get(severity, 0)
        
        # Get cooldown for this severity
        cooldown = self.notification_cooldown.get(severity, 0)
        
        # Count recent alerts of this severity
        count = 0
        last_notification_time = None
        
        for notification in self.notification_history:
            if notification.get("severity") == severity:
                count += 1
                if notification.get("notified", False):
                    last_notification_time = notification.get("timestamp")
        
        # Check if threshold is met
        if count < threshold:
            return False
        
        # Check if cooldown has passed
        if last_notification_time is not None and cooldown > 0:
            last_time = datetime.fromisoformat(last_notification_time)
            now = datetime.now()
            elapsed_seconds = (now - last_time).total_seconds()
            
            if elapsed_seconds < cooldown:
                return False
        
        return True
    
    def _add_to_history(self, alert: Alert):
        """
        Add an alert to notification history.
        
        Args:
            alert: Alert to add
        """
        notification = {
            "timestamp": datetime.now().isoformat(),
            "severity": alert.severity.to_string(),
            "alert_type": alert.alert_type.to_string(),
            "title": alert.title,
            "description": alert.description,
            "notified": False
        }
        
        self.notification_history.append(notification)
        
        # Trim history if needed
        if len(self.notification_history) > self.max_history:
            self.notification_history = self.notification_history[-self.max_history:]
    
    def _mark_as_notified(self, alert: Alert):
        """
        Mark an alert as notified in history.
        
        Args:
            alert: Alert that was notified
        """
        for notification in self.notification_history:
            if (notification.get("title") == alert.title and 
                notification.get("description") == alert.description and
                not notification.get("notified", False)):
                notification["notified"] = True
                notification["notification_time"] = datetime.now().isoformat()
                break
    
    def _notify_windows(self, alert: Alert) -> bool:
        """
        Send a Windows notification.
        
        Args:
            alert: Alert to notify about
            
        Returns:
            True if notification was sent, False otherwise
        """
        try:
            severity = alert.severity.to_string()
            title = alert.title
            message = alert.description
            
            # Get severity information
            severity_info = self.severity_manager.get_severity_indicator(severity)
            icon = severity_info.get("icon", "info")
            
            # Create PowerShell script for notification
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

            $app_id = 'CyberAttackTracer'

            $template = @"
            <toast>
                <visual>
                    <binding template="ToastGeneric">
                        <text>{severity} Alert</text>
                        <text>{title}</text>
                        <text>{message}</text>
                    </binding>
                </visual>
            </toast>
            "@

            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($template)
            $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app_id).Show($toast)
            """
            
            # Save script to temporary file
            temp_script = Path(os.path.expanduser("~")) / "cyber_attack_tracer" / "temp" / "notification.ps1"
            temp_script.parent.mkdir(parents=True, exist_ok=True)
            
            with open(temp_script, "w") as f:
                f.write(ps_script)
            
            # Execute PowerShell script
            subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", str(temp_script)], 
                          capture_output=True, text=True, check=False)
            
            # Mark as notified
            self._mark_as_notified(alert)
            
            logger.info(f"Sent Windows notification for {severity} alert: {title}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Windows notification: {str(e)}")
            return False
    
    def _notify_mac(self, alert: Alert) -> bool:
        """
        Send a Mac notification.
        
        Args:
            alert: Alert to notify about
            
        Returns:
            True if notification was sent, False otherwise
        """
        try:
            severity = alert.severity.to_string()
            title = alert.title
            message = alert.description
            
            # Escape quotes in title and message
            title = title.replace('"', '\\"')
            message = message.replace('"', '\\"')
            
            # Determine sound based on severity
            sound = "default"
            if severity == "CRITICAL":
                sound = "Basso"
            elif severity == "HIGH":
                sound = "Sosumi"
            
            # Create AppleScript for notification
            script = f'''
            display notification "{message}" with title "{severity} Alert" subtitle "{title}" sound name "{sound}"
            '''
            
            # Execute AppleScript
            subprocess.run(["osascript", "-e", script], capture_output=True, text=True, check=False)
            
            # Mark as notified
            self._mark_as_notified(alert)
            
            logger.info(f"Sent Mac notification for {severity} alert: {title}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Mac notification: {str(e)}")
            return False
    
    def _notify_console(self, alert: Alert) -> bool:
        """
        Send a console notification.
        
        Args:
            alert: Alert to notify about
            
        Returns:
            True if notification was sent, False otherwise
        """
        try:
            severity = alert.severity.to_string()
            title = alert.title
            message = alert.description
            
            # Get severity color
            color = self.severity_ui.get_severity_color(severity)
            
            # Print to console
            logger.warning(f"[{severity}] {title}")
            logger.warning(f"  {message}")
            
            # Mark as notified
            self._mark_as_notified(alert)
            
            return True
        
        except Exception as e:
            logger.error(f"Error sending console notification: {str(e)}")
            return False
    
    def notify_batch(self, alerts: List[Alert]) -> int:
        """
        Send notifications for a batch of alerts.
        
        Args:
            alerts: List of alerts to notify about
            
        Returns:
            Number of notifications sent
        """
        sent_count = 0
        
        for alert in alerts:
            if self.notify(alert):
                sent_count += 1
        
        return sent_count
    
    def create_severity_summary(self, alerts: List[Alert]) -> Dict[str, Any]:
        """
        Create a summary of alerts by severity.
        
        Args:
            alerts: List of alerts to summarize
            
        Returns:
            Dictionary with severity summary
        """
        # Count alerts by severity
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for alert in alerts:
            severity = alert.severity.to_string()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate overall severity
        overall_severity, _ = self.severity_manager.calculate_overall_severity(
            [alert.to_dict() for alert in alerts]
        )
        
        # Create summary
        summary = {
            "timestamp": datetime.now().isoformat(),
            "overall_severity": overall_severity.to_string(),
            "counts": severity_counts,
            "total": sum(severity_counts.values()),
            "platform": self.platform
        }
        
        return summary
    
    def get_notification_history(self, limit: int = 100, 
                                severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get notification history with optional filtering.
        
        Args:
            limit: Maximum number of records to return
            severity: Filter by severity level
            
        Returns:
            List of notification history records
        """
        filtered_history = self.notification_history
        
        # Filter by severity
        if severity:
            filtered_history = [
                record for record in filtered_history
                if record.get("severity") == severity
            ]
        
        # Sort by timestamp (newest first)
        filtered_history = sorted(
            filtered_history,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
        
        # Limit results
        return filtered_history[:limit]
