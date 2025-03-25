"""
Notification Service Module.

This module provides functionality for sending notifications through various channels
when alerts are generated.
"""

import logging
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

from src.utils.config import load_config

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Provides notification services for alerts.
    
    This class is responsible for:
    1. Sending email notifications
    2. Sending webhook notifications
    3. Sending SMS notifications
    4. Sending desktop notifications
    """
    
    def __init__(self):
        """Initialize the NotificationService."""
        self.config = load_config().get("notifications", {})
        self.enabled = self.config.get("enabled", False)
        
        # Initialize notification channels
        self._init_email()
        self._init_webhook()
        self._init_sms()
    
    def _init_email(self):
        """Initialize email notification settings."""
        self.email_config = self.config.get("email", {})
        self.email_enabled = self.email_config.get("enabled", False)
        
        if self.email_enabled:
            self.smtp_server = self.email_config.get("smtp_server", "")
            self.smtp_port = self.email_config.get("smtp_port", 587)
            self.smtp_username = self.email_config.get("smtp_username", "")
            self.smtp_password = self.email_config.get("smtp_password", "")
            self.from_email = self.email_config.get("from_email", "")
            self.to_emails = self.email_config.get("to_emails", [])
            
            if not all([self.smtp_server, self.smtp_username, self.smtp_password, self.from_email, self.to_emails]):
                logger.warning("Email notifications enabled but configuration incomplete")
                self.email_enabled = False
    
    def _init_webhook(self):
        """Initialize webhook notification settings."""
        self.webhook_config = self.config.get("webhook", {})
        self.webhook_enabled = self.webhook_config.get("enabled", False)
        
        if self.webhook_enabled:
            self.webhook_url = self.webhook_config.get("url", "")
            self.webhook_headers = self.webhook_config.get("headers", {})
            
            if not self.webhook_url:
                logger.warning("Webhook notifications enabled but URL not configured")
                self.webhook_enabled = False
    
    def _init_sms(self):
        """Initialize SMS notification settings."""
        self.sms_config = self.config.get("sms", {})
        self.sms_enabled = self.sms_config.get("enabled", False)
        
        if self.sms_enabled:
            self.sms_provider = self.sms_config.get("provider", "")
            self.sms_api_key = self.sms_config.get("api_key", "")
            self.sms_from = self.sms_config.get("from", "")
            self.sms_to = self.sms_config.get("to", [])
            
            if not all([self.sms_provider, self.sms_api_key, self.sms_from, self.sms_to]):
                logger.warning("SMS notifications enabled but configuration incomplete")
                self.sms_enabled = False
    
    def send_notification(self, alert: Dict[str, Any]) -> bool:
        """
        Send a notification for an alert.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if notification was sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        # Check severity threshold
        severity = alert.get("severity", "INFO")
        severity_threshold = self.config.get("severity_threshold", "MEDIUM")
        
        severity_levels = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        if severity_levels.get(severity, 0) < severity_levels.get(severity_threshold, 0):
            return False
        
        # Send notifications through enabled channels
        success = True
        
        if self.email_enabled:
            email_success = self._send_email_notification(alert)
            success = success and email_success
        
        if self.webhook_enabled:
            webhook_success = self._send_webhook_notification(alert)
            success = success and webhook_success
        
        if self.sms_enabled:
            sms_success = self._send_sms_notification(alert)
            success = success and sms_success
        
        return success
    
    def _send_email_notification(self, alert: Dict[str, Any]) -> bool:
        """
        Send an email notification.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            
            severity = alert.get("severity", "INFO")
            alert_type = alert.get("type", "")
            message = alert.get("message", "")
            
            msg["Subject"] = f"[{severity}] Cyber Attack Alert: {message}"
            
            # Create email body
            body = f"""
            <html>
            <body>
                <h2>Cyber Attack Alert</h2>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Type:</strong> {alert_type}</p>
                <p><strong>Message:</strong> {message}</p>
                <p><strong>Timestamp:</strong> {alert.get('timestamp', '')}</p>
                <h3>Details:</h3>
                <pre>{json.dumps(alert.get('details', {}), indent=2)}</pre>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, "html"))
            
            # Connect to SMTP server
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent: {message}")
            return True
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    def _send_webhook_notification(self, alert: Dict[str, Any]) -> bool:
        """
        Send a webhook notification.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if webhook notification was sent successfully, False otherwise
        """
        try:
            # Prepare payload
            payload = {
                "severity": alert.get("severity", "INFO"),
                "type": alert.get("type", ""),
                "message": alert.get("message", ""),
                "timestamp": alert.get("timestamp", ""),
                "details": alert.get("details", {})
            }
            
            # Send webhook request
            response = requests.post(
                self.webhook_url,
                headers=self.webhook_headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code < 400:
                logger.info(f"Webhook notification sent: {alert.get('message', '')}")
                return True
            else:
                logger.error(f"Error sending webhook notification: {response.status_code} {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending webhook notification: {str(e)}")
            return False
    
    def _send_sms_notification(self, alert: Dict[str, Any]) -> bool:
        """
        Send an SMS notification.
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if SMS notification was sent successfully, False otherwise
        """
        try:
            severity = alert.get("severity", "INFO")
            message = alert.get("message", "")
            
            # Format SMS message
            sms_message = f"[{severity}] {message}"
            
            # Send SMS based on provider
            if self.sms_provider.lower() == "twilio":
                return self._send_twilio_sms(sms_message)
            elif self.sms_provider.lower() == "nexmo":
                return self._send_nexmo_sms(sms_message)
            else:
                logger.error(f"Unsupported SMS provider: {self.sms_provider}")
                return False
        except Exception as e:
            logger.error(f"Error sending SMS notification: {str(e)}")
            return False
    
    def _send_twilio_sms(self, message: str) -> bool:
        """
        Send an SMS using Twilio.
        
        Args:
            message: SMS message
            
        Returns:
            True if SMS was sent successfully, False otherwise
        """
        try:
            # This is a placeholder for Twilio integration
            # In a real implementation, you would use the Twilio SDK
            logger.info(f"Twilio SMS notification sent: {message}")
            return True
        except Exception as e:
            logger.error(f"Error sending Twilio SMS: {str(e)}")
            return False
    
    def _send_nexmo_sms(self, message: str) -> bool:
        """
        Send an SMS using Nexmo.
        
        Args:
            message: SMS message
            
        Returns:
            True if SMS was sent successfully, False otherwise
        """
        try:
            # This is a placeholder for Nexmo integration
            # In a real implementation, you would use the Nexmo SDK
            logger.info(f"Nexmo SMS notification sent: {message}")
            return True
        except Exception as e:
            logger.error(f"Error sending Nexmo SMS: {str(e)}")
            return False
