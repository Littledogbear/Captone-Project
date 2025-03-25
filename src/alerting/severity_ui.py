"""
Severity UI Module.

This module provides UI components for displaying severity-based warnings
and alerts to users.
"""

import logging
import json
import os
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

from src.alerting.alert_types import AlertSeverity, AlertType
from src.alerting.severity_manager import SeverityManager
from src.utils.platform_detector import PlatformDetector

logger = logging.getLogger(__name__)

class SeverityUI:
    """
    Provides UI components for displaying severity-based warnings.
    
    This class is responsible for:
    1. Generating HTML/CSS for severity indicators
    2. Creating platform-specific warning displays
    3. Providing visualization components for severity levels
    4. Generating severity reports and summaries
    """
    
    def __init__(self):
        """Initialize the SeverityUI."""
        self.severity_manager = SeverityManager()
        self.platform_detector = PlatformDetector()
        self.platform = self.platform_detector.get_platform()
        
        # Initialize templates directory
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize output directory
        self.output_dir = Path(os.path.expanduser("~")) / "cyber_attack_tracer" / "data" / "severity_ui"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default templates if they don't exist."""
        # Create severity indicator template
        indicator_template_path = self.templates_dir / "severity_indicator.html"
        if not indicator_template_path.exists():
            indicator_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Severity Indicator</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        .severity-indicator {
            display: flex;
            align-items: center;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        .severity-icon {
            font-size: 24px;
            margin-right: 15px;
        }
        .severity-content {
            flex: 1;
        }
        .severity-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .severity-description {
            margin-bottom: 10px;
        }
        .severity-action {
            font-style: italic;
        }
        .severity-critical {
            background-color: #ffebee;
            border-left: 5px solid #f44336;
            color: #b71c1c;
        }
        .severity-high {
            background-color: #fff3e0;
            border-left: 5px solid #ff9800;
            color: #e65100;
        }
        .severity-medium {
            background-color: #fffde7;
            border-left: 5px solid #ffeb3b;
            color: #f57f17;
        }
        .severity-low {
            background-color: #e3f2fd;
            border-left: 5px solid #2196f3;
            color: #0d47a1;
        }
        .severity-info {
            background-color: #f5f5f5;
            border-left: 5px solid #9e9e9e;
            color: #424242;
        }
        .platform-windows .severity-icon::before {
            content: "🔒";
        }
        .platform-mac .severity-icon::before {
            content: "🔐";
        }
    </style>
</head>
<body class="platform-{platform}">
    <div class="severity-indicator severity-{severity_lower}">
        <div class="severity-icon"></div>
        <div class="severity-content">
            <div class="severity-title">{severity} Severity Alert: {title}</div>
            <div class="severity-description">{description}</div>
            <div class="severity-action">Recommended Action: {action}</div>
        </div>
    </div>
</body>
</html>"""
            
            with open(indicator_template_path, "w") as f:
                f.write(indicator_template)
            
            logger.info(f"Created default severity indicator template at {indicator_template_path}")
        
        # Create severity dashboard template
        dashboard_template_path = self.templates_dir / "severity_dashboard.html"
        if not dashboard_template_path.exists():
            dashboard_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Severity Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .dashboard {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #333;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .summary-box {
            flex: 1;
            padding: 15px;
            border-radius: 5px;
            margin: 0 5px;
            text-align: center;
        }
        .summary-box h2 {
            margin-top: 0;
            font-size: 18px;
        }
        .summary-box .count {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .critical {
            background-color: #ffebee;
            color: #b71c1c;
        }
        .high {
            background-color: #fff3e0;
            color: #e65100;
        }
        .medium {
            background-color: #fffde7;
            color: #f57f17;
        }
        .low {
            background-color: #e3f2fd;
            color: #0d47a1;
        }
        .info {
            background-color: #f5f5f5;
            color: #424242;
        }
        .alerts {
            margin-top: 20px;
        }
        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        .alert-icon {
            font-size: 24px;
            margin-right: 15px;
        }
        .alert-content {
            flex: 1;
        }
        .alert-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .alert-description {
            margin-bottom: 5px;
        }
        .alert-timestamp {
            font-size: 12px;
            color: #666;
        }
        .platform-windows .alert-icon::before {
            content: "🔒";
        }
        .platform-mac .alert-icon::before {
            content: "🔐";
        }
        .chart-container {
            margin-top: 30px;
            height: 300px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="platform-{platform}">
    <div class="dashboard">
        <h1>Severity Dashboard</h1>
        
        <div class="summary">
            <div class="summary-box critical">
                <h2>Critical</h2>
                <div class="count">{critical_count}</div>
            </div>
            <div class="summary-box high">
                <h2>High</h2>
                <div class="count">{high_count}</div>
            </div>
            <div class="summary-box medium">
                <h2>Medium</h2>
                <div class="count">{medium_count}</div>
            </div>
            <div class="summary-box low">
                <h2>Low</h2>
                <div class="count">{low_count}</div>
            </div>
            <div class="summary-box info">
                <h2>Info</h2>
                <div class="count">{info_count}</div>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="severityTrendChart"></canvas>
        </div>
        
        <div class="alerts">
            <h2>Recent Alerts</h2>
            {alerts_html}
        </div>
    </div>
    
    <script>
        // Initialize trend chart
        const ctx = document.getElementById('severityTrendChart').getContext('2d');
        const severityTrendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: {trend_labels},
                datasets: [
                    {
                        label: 'Critical',
                        data: {critical_trend},
                        borderColor: '#f44336',
                        backgroundColor: 'rgba(244, 67, 54, 0.1)',
                        tension: 0.1
                    },
                    {
                        label: 'High',
                        data: {high_trend},
                        borderColor: '#ff9800',
                        backgroundColor: 'rgba(255, 152, 0, 0.1)',
                        tension: 0.1
                    },
                    {
                        label: 'Medium',
                        data: {medium_trend},
                        borderColor: '#ffeb3b',
                        backgroundColor: 'rgba(255, 235, 59, 0.1)',
                        tension: 0.1
                    },
                    {
                        label: 'Low',
                        data: {low_trend},
                        borderColor: '#2196f3',
                        backgroundColor: 'rgba(33, 150, 243, 0.1)',
                        tension: 0.1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Alerts'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Date'
                        }
                    }
                }
            }
        });
        
        // Detect platform
        const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
        document.body.classList.add(isMac ? 'platform-mac' : 'platform-windows');
    </script>
</body>
</html>"""
            
            with open(dashboard_template_path, "w") as f:
                f.write(dashboard_template)
            
            logger.info(f"Created default severity dashboard template at {dashboard_template_path}")
    
    def create_severity_indicator(self, severity: Union[str, AlertSeverity], 
                                 title: str, description: str = None) -> str:
        """
        Create an HTML severity indicator.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            title: Title of the indicator
            description: Optional description
            
        Returns:
            HTML string for the severity indicator
        """
        try:
            # Convert severity to string if it's an enum
            if isinstance(severity, AlertSeverity):
                severity = severity.to_string()
            
            # Get severity information
            severity_info = self.severity_manager.get_severity_indicator(severity)
            
            # Use provided description or default
            if description is None:
                description = severity_info.get("description", "")
            
            # Get recommended action
            action = severity_info.get("recommended_action", "")
            
            # Load template
            template_path = self.templates_dir / "severity_indicator.html"
            with open(template_path, "r") as f:
                template = f.read()
            
            # Replace placeholders
            html = template.replace("{severity}", severity)
            html = html.replace("{severity_lower}", severity.lower())
            html = html.replace("{title}", title)
            html = html.replace("{description}", description)
            html = html.replace("{action}", action)
            html = html.replace("{platform}", self.platform)
            
            return html
        
        except Exception as e:
            logger.error(f"Error creating severity indicator: {str(e)}")
            return f"<div>Error creating severity indicator: {str(e)}</div>"
    
    def create_severity_dashboard(self, alerts: List[Dict[str, Any]], 
                                 trend_data: Dict[str, Any] = None) -> str:
        """
        Create an HTML severity dashboard.
        
        Args:
            alerts: List of alert dictionaries
            trend_data: Optional trend data
            
        Returns:
            HTML string for the severity dashboard
        """
        try:
            # Calculate severity counts
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
            
            # Get trend data if not provided
            if trend_data is None:
                trend_data = self.severity_manager.get_severity_trend()
            
            # Extract trend data for chart
            trend_labels = []
            critical_trend = []
            high_trend = []
            medium_trend = []
            low_trend = []
            
            for day_data in trend_data.get("trend", []):
                trend_labels.append(day_data.get("date"))
                critical_trend.append(day_data.get("CRITICAL", 0))
                high_trend.append(day_data.get("HIGH", 0))
                medium_trend.append(day_data.get("MEDIUM", 0))
                low_trend.append(day_data.get("LOW", 0))
            
            # Generate alerts HTML
            alerts_html = ""
            for alert in alerts[:10]:  # Show only the 10 most recent alerts
                severity = alert.get("severity", "INFO").lower()
                title = alert.get("title", "")
                description = alert.get("description", "")
                timestamp = alert.get("timestamp", "")
                
                alert_html = f"""
                <div class="alert {severity}">
                    <div class="alert-icon"></div>
                    <div class="alert-content">
                        <div class="alert-title">{title}</div>
                        <div class="alert-description">{description}</div>
                        <div class="alert-timestamp">{timestamp}</div>
                    </div>
                </div>
                """
                
                alerts_html += alert_html
            
            # Load template
            template_path = self.templates_dir / "severity_dashboard.html"
            with open(template_path, "r") as f:
                template = f.read()
            
            # Replace placeholders
            html = template.replace("{critical_count}", str(severity_counts["CRITICAL"]))
            html = html.replace("{high_count}", str(severity_counts["HIGH"]))
            html = html.replace("{medium_count}", str(severity_counts["MEDIUM"]))
            html = html.replace("{low_count}", str(severity_counts["LOW"]))
            html = html.replace("{info_count}", str(severity_counts["INFO"]))
            html = html.replace("{alerts_html}", alerts_html)
            html = html.replace("{trend_labels}", json.dumps(trend_labels))
            html = html.replace("{critical_trend}", json.dumps(critical_trend))
            html = html.replace("{high_trend}", json.dumps(high_trend))
            html = html.replace("{medium_trend}", json.dumps(medium_trend))
            html = html.replace("{low_trend}", json.dumps(low_trend))
            html = html.replace("{platform}", self.platform)
            
            return html
        
        except Exception as e:
            logger.error(f"Error creating severity dashboard: {str(e)}")
            return f"<div>Error creating severity dashboard: {str(e)}</div>"
    
    def save_severity_dashboard(self, alerts: List[Dict[str, Any]], 
                               trend_data: Dict[str, Any] = None,
                               filename: str = None) -> str:
        """
        Create and save an HTML severity dashboard.
        
        Args:
            alerts: List of alert dictionaries
            trend_data: Optional trend data
            filename: Optional filename
            
        Returns:
            Path to the saved dashboard file
        """
        try:
            # Generate dashboard HTML
            dashboard_html = self.create_severity_dashboard(alerts, trend_data)
            
            # Generate filename if not provided
            if filename is None:
                timestamp = int(datetime.now().timestamp())
                filename = f"severity_dashboard_{timestamp}.html"
            
            # Save to file
            output_path = self.output_dir / filename
            with open(output_path, "w") as f:
                f.write(dashboard_html)
            
            logger.info(f"Saved severity dashboard to {output_path}")
            return str(output_path)
        
        except Exception as e:
            logger.error(f"Error saving severity dashboard: {str(e)}")
            return ""
    
    def get_platform_specific_warning(self, severity: Union[str, AlertSeverity], 
                                     title: str, description: str = None) -> Dict[str, Any]:
        """
        Get platform-specific warning information.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            title: Title of the warning
            description: Optional description
            
        Returns:
            Dictionary with platform-specific warning information
        """
        # Convert severity to string if it's an enum
        if isinstance(severity, AlertSeverity):
            severity = severity.to_string()
        
        # Get severity information
        severity_info = self.severity_manager.get_severity_indicator(severity)
        
        # Use provided description or default
        if description is None:
            description = severity_info.get("description", "")
        
        # Get recommended action
        action = severity_info.get("recommended_action", "")
        
        # Create base warning info
        warning_info = {
            "severity": severity,
            "title": title,
            "description": description,
            "action": action,
            "color": severity_info.get("color", "#808080"),
            "icon": severity_info.get("icon", "info")
        }
        
        # Add platform-specific information
        if self.platform_detector.is_windows():
            warning_info["platform"] = "windows"
            warning_info["notification_type"] = "toast"
            warning_info["sound"] = severity in ["CRITICAL", "HIGH"]
        elif self.platform_detector.is_mac():
            warning_info["platform"] = "mac"
            warning_info["notification_type"] = "notification-center"
            warning_info["sound"] = severity in ["CRITICAL", "HIGH"]
        else:
            warning_info["platform"] = "unknown"
            warning_info["notification_type"] = "console"
            warning_info["sound"] = False
        
        return warning_info
    
    def get_severity_color(self, severity: Union[str, AlertSeverity]) -> str:
        """
        Get color for a severity level.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            
        Returns:
            Color string (hex code)
        """
        # Convert severity to string if it's an enum
        if isinstance(severity, AlertSeverity):
            severity = severity.to_string()
        
        # Get severity information
        severity_info = self.severity_manager.get_severity_indicator(severity)
        
        return severity_info.get("color", "#808080")
    
    def get_severity_icon(self, severity: Union[str, AlertSeverity]) -> str:
        """
        Get icon for a severity level.
        
        Args:
            severity: Severity level as string or AlertSeverity enum
            
        Returns:
            Icon string
        """
        # Convert severity to string if it's an enum
        if isinstance(severity, AlertSeverity):
            severity = severity.to_string()
        
        # Get severity information
        severity_info = self.severity_manager.get_severity_indicator(severity)
        
        return severity_info.get("icon", "info")
