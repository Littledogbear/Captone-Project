# Dashboard Demonstration Guide for Cyber Attack Tracer

This guide provides step-by-step instructions for demonstrating the Cyber Attack Tracer dashboard in a VMware Fusion environment.

## 1. Dashboard Startup

### 1.1 Start the Dashboard
```bash
# Activate the virtual environment
source venv/bin/activate

# Start the monitoring dashboard
python run_monitoring_dashboard.py
```

The dashboard will be accessible at: http://127.0.0.1:8082

### 1.2 Verify Dashboard Initialization
The dashboard initialization follows this sequence:
1. FastAPI application and route initialization
2. WebSocket connection setup for real-time monitoring
3. Database table creation and setup
4. Uvicorn server startup
5. AI model and MITRE mapping loading
6. System monitoring activation

You should see console output confirming each step of the initialization process.

## 2. Dashboard UI Overview

### 2.1 Dashboard Layout
The dashboard has a consistent layout with these key elements:
- Title: "Cyber Attack Tracer - Real-time Monitoring Dashboard"
- Navigation tabs: System Monitoring, Alerts, Knowledge Graph, Reports
- Main content area: Displays the content for the selected tab
- Footer: Contains additional information and controls

### 2.2 Navigation Tabs
Demonstrate each tab and its functionality:

#### System Monitoring Tab
- Shows real-time CPU, memory, disk, and network metrics
- Updates automatically every 5 seconds
- Displays system resource usage graphs
- Highlights abnormal resource usage

#### Alerts Tab
- Displays security alerts with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Shows alert timestamps and descriptions
- Color-codes alerts based on severity
- Allows filtering and sorting of alerts

#### Knowledge Graph Tab
- Contains controls for generating knowledge graphs
- Displays interactive graph visualizations
- Shows relationships between malware, processes, files, and network connections
- Allows zooming, panning, and node selection

#### Reports Tab
- Provides controls for generating security reports
- Displays generated reports directly in the dashboard
- Includes a download button for saving reports
- Shows report history

## 3. Demonstrating Key Features

### 3.1 Real-time Monitoring Demonstration
1. Navigate to the System Monitoring tab
2. Point out the real-time CPU, memory, disk, and network metrics
3. Explain how the system detects abnormal resource usage
4. Show how the metrics update automatically

### 3.2 Alert Generation Demonstration
1. In a separate terminal, run:
   ```bash
   python run_attribution_dashboard_test.py
   ```
2. Navigate to the Alerts tab
3. Point out the newly generated alerts for detected malware
4. Explain the severity levels and color coding
5. Show how alerts include timestamps and descriptions

### 3.3 Knowledge Graph Generation Demonstration
1. Navigate to the Knowledge Graph tab
2. Click the "Generate Knowledge Graph" button
3. Select a malware sample from the dropdown (e.g., TrojanSample.exe)
4. Click "Generate"
5. When the graph appears, demonstrate:
   - Different node types (malware, processes, files, network)
   - Relationship lines between nodes
   - Interactive features (zoom, pan, node selection)
   - Node details on hover/click

### 3.4 Report Generation Demonstration
1. Navigate to the Reports tab
2. Click the "Generate Report" button
3. Select a malware sample from the dropdown (e.g., RansomwareSample.exe)
4. Click "Generate"
5. When the report appears, demonstrate:
   - Executive Summary section
   - Malware samples section with TrojanSample.exe, RansomwareSample.exe, and BotnetSample.exe
   - Attack Techniques section with confidence scores
   - Attribution section with potential threat actors
   - Security Improvement Suggestions section
   - Download button functionality

## 4. Demonstrating Attribution Features

### 4.1 Attribution Analysis Demonstration
1. In a separate terminal, run:
   ```bash
   python run_attribution_test_with_sample_data.py
   ```
2. Navigate to the Reports tab
3. Open the newly generated attribution report
4. Point out:
   - Confidence scores for attribution (displayed as whole numbers)
   - Potential threat actors identified
   - Matching techniques and tools
   - Overall attribution assessment

### 4.2 Integrated Attribution Dashboard Demonstration
1. In a separate terminal, run:
   ```bash
   python run_attribution_dashboard_test.py
   ```
2. Navigate to the Knowledge Graph tab
3. Generate a new knowledge graph
4. Point out:
   - Attribution nodes in the graph
   - Connections between threat actors and techniques
   - Confidence scores for attributions

## 5. Multi-Malware Analysis Demonstration

### 5.1 Multi-Malware Dashboard Demonstration
1. In a separate terminal, run:
   ```bash
   python test_multi_malware_dashboard.py
   ```
2. Navigate through all tabs to show:
   - Multiple malware alerts in the Alerts tab
   - Comprehensive knowledge graph with multiple malware samples
   - Integrated report showing all detected malware

### 5.2 Comprehensive System Demonstration
1. In a separate terminal, run:
   ```bash
   python test_comprehensive_system_with_specific_samples.py
   ```
2. This demonstrates the full system capabilities with predefined malware samples
3. Navigate through all dashboard tabs to show the comprehensive analysis results

## 6. Interactive Elements Demonstration

### 6.1 Button Functionality
Demonstrate that all buttons are functional and responsive:
- "Generate Knowledge Graph" button
- "Generate Report" button
- Tab navigation buttons
- Download buttons
- Filter and sort controls

### 6.2 Interactive Visualizations
Demonstrate the interactive features of the knowledge graph:
- Zoom in/out using mouse wheel
- Pan by clicking and dragging
- Select nodes to view details
- Hover over nodes to see tooltips
- Expand/collapse node groups

### 6.3 Real-time Updates
Demonstrate how the dashboard updates in real-time:
- System metrics updating automatically
- New alerts appearing as they are generated
- Knowledge graph updating with new data
- Reports reflecting the latest analysis results

## 7. Troubleshooting During Demonstration

### 7.1 Browser Issues
If the dashboard doesn't load properly:
- Refresh the browser page
- Try a different browser
- Check the console output for errors
- Verify the server is running on the correct port

### 7.2 Dashboard Responsiveness
If the dashboard becomes unresponsive:
- Check the terminal for error messages
- Restart the dashboard server
- Clear browser cache and reload
- Check system resource usage

### 7.3 Visualization Issues
If knowledge graphs don't render correctly:
- Check browser console for JavaScript errors
- Verify the graph data is being generated correctly
- Try a different browser
- Restart the dashboard server

## 8. Conclusion of Demonstration

### 8.1 Key Points to Emphasize
- Real-time monitoring capabilities
- AI-powered analysis of malware behavior
- Knowledge graph visualization of attack patterns
- Comprehensive security reporting
- Attribution of attacks to potential threat actors
- Integration with MITRE ATT&CK framework

### 8.2 Next Steps
- Discuss potential improvements and future features
- Explain how the system can be integrated with existing security tools
- Highlight the extensibility of the architecture
- Discuss deployment options for production environments
