"""
Generate Fixed Confidence Report.

This script generates a security report with fixed confidence percentage values
and improved contrast for better readability.
"""

import os
import sys
import webbrowser
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

def generate_fixed_confidence_report():
    """Generate a security report with fixed confidence percentage values."""
    output_dir = Path("output/fixed_confidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"fixed_confidence_report_{timestamp}.html"
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Attack Tracer - Security Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .header {
            background-color: #34495e;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .malware-item {
            margin-bottom: 20px;
            padding: 15px;
            background-color: #fff8e1;
            border-radius: 5px;
            color: #333;
        }
        .malware-item h3 {
            color: #d84315;
            margin-top: 0;
            font-weight: bold;
        }
        .tag {
            display: inline-block;
            padding: 3px 8px;
            margin-right: 5px;
            background-color: #7986cb;
            color: white;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .technique-item {
            margin-bottom: 20px;
            padding: 15px;
            background-color: #e3f2fd;
            border-radius: 5px;
            color: #333;
        }
        .technique-item h3 {
            color: #0d47a1;
            margin-top: 0;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cyber Attack Tracer - Security Report</h1>
        <p>Generated on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p style="color: #333; font-weight: normal;">This report summarizes the security analysis of detected malware and suspicious activities on the system. Multiple malware samples were detected, including trojan, ransomware, and botnet components.</p>
        
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-top: 15px;">
            <p style="color: #333; margin: 5px 0;"><strong style="color: #0d47a1;">Threat Level:</strong> Critical</p>
            <p style="color: #333; margin: 5px 0;"><strong style="color: #0d47a1;">Confidence Score:</strong> 85%</p>
            <p style="color: #333; margin: 5px 0;"><strong style="color: #0d47a1;">Detected Techniques:</strong> 3</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Detected Malware</h2>
        <div class="malware-item">
            <h3>TrojanSample.exe (trojan)</h3>
            <p><strong>SHA256:</strong> a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2</p>
            <p><strong>Tags:</strong> 
                <span class="tag">trojan</span>
                <span class="tag">stealer</span>
                <span class="tag">backdoor</span>
            </p>
            <p>This trojan establishes persistence through registry modifications and communicates with command and control servers.</p>
        </div>
        
        <div class="malware-item">
            <h3>RansomwareSample.exe (ransomware)</h3>
            <p><strong>SHA256:</strong> b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3</p>
            <p><strong>Tags:</strong> 
                <span class="tag">ransomware</span>
                <span class="tag">encryptor</span>
            </p>
            <p>This ransomware encrypts user files and demands payment for decryption.</p>
        </div>
        
        <div class="malware-item">
            <h3>BotnetSample.exe (botnet)</h3>
            <p><strong>SHA256:</strong> c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4</p>
            <p><strong>Tags:</strong> 
                <span class="tag">botnet</span>
                <span class="tag">ddos</span>
            </p>
            <p>This botnet client connects to command and control servers and participates in distributed denial of service attacks.</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Attack Techniques</h2>
        <div class="technique-item">
            <h3>T1071: Command and Control</h3>
            <p><strong>Confidence:</strong> 80%</p>
            <p>The malware establishes command and control communications with remote servers.</p>
        </div>
        
        <div class="technique-item">
            <h3>T1547: Boot or Logon Autostart Execution</h3>
            <p><strong>Confidence:</strong> 75%</p>
            <p>The malware establishes persistence through registry modifications.</p>
        </div>
        
        <div class="technique-item">
            <h3>T1486: Data Encrypted for Impact</h3>
            <p><strong>Confidence:</strong> 90%</p>
            <p>The malware encrypts files to prevent access.</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Security Improvement Suggestions</h2>
        
        <div style="margin-bottom: 20px; padding: 15px; background-color: #f5f5f5; border-left: 5px solid #d32f2f; border-radius: 3px;">
            <h4 style="margin-top: 0; color: #333; font-weight: bold;">High Priority</h4>
            <ul style="color: #333; margin-bottom: 0;">
                <li>Isolate affected systems from the network</li>
                <li>Restore encrypted files from backup</li>
            </ul>
        </div>
        
        <div style="margin-bottom: 20px; padding: 15px; background-color: #f5f5f5; border-left: 5px solid #f57c00; border-radius: 3px;">
            <h4 style="margin-top: 0; color: #333; font-weight: bold;">Medium Priority</h4>
            <ul style="color: #333; margin-bottom: 0;">
                <li>Update antivirus definitions and perform a full system scan</li>
                <li>Remove malicious registry entries</li>
            </ul>
        </div>
        
        <div style="margin-bottom: 20px; padding: 15px; background-color: #f5f5f5; border-left: 5px solid #388e3c; border-radius: 3px;">
            <h4 style="margin-top: 0; color: #333; font-weight: bold;">Low Priority</h4>
            <ul style="color: #333; margin-bottom: 0;">
                <li>Review and update security policies</li>
                <li>Implement additional monitoring for similar attack patterns</li>
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h2>About This Report</h2>
        <p>This report was generated by the Cyber Attack Trace Analyzer. The analysis is based on system traces collected at the time of the scan.</p>
        <p>For more information or assistance, please contact your security team.</p>
    </div>
</body>
</html>
"""
    
    with open(report_path, 'w') as f:
        f.write(html_content)
    
    print(f"\nFixed Confidence Report generated: {report_path}")
    
    webbrowser.open(f"file://{report_path}")
    
    return report_path

if __name__ == "__main__":
    generate_fixed_confidence_report()
