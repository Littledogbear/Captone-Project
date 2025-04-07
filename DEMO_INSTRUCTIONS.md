# Cyber Attack Tracer - Demo Instructions

This document provides instructions for demonstrating the Cyber Attack Tracer system, including how to use malware samples to trigger monitoring and generate knowledge graphs and security reports.

## Prerequisites

- Python 3.8 or higher
- Required Python packages (install with `pip install -r requirements.txt`)
- Malware samples metadata in `~/samples/malwarebazaa/metadata` directory

## Running the Dashboard

There are two ways to run the dashboard:

### Option 1: Using the Monitoring Dashboard

```bash
python run_monitoring_dashboard.py
```

This will start the dashboard with default settings:
- Host: 127.0.0.1
- Port: 8081
- Samples directory: ~/samples/malwarebazaa/metadata

You can customize these settings with command-line arguments:

```bash
python run_monitoring_dashboard.py --host 0.0.0.0 --port 8082 --samples-dir /path/to/samples
```

### Option 2: Using the Comprehensive System Test

```bash
python test_comprehensive_system_with_specific_samples.py
```

This script will:
1. Start the dashboard
2. Load malware samples from the specified directory
3. Generate traces from the samples
4. Send alerts to the dashboard
5. Generate a knowledge graph and security report

## Demonstration Workflow

For a complete demonstration of the system's capabilities, follow these steps:

1. **Start the Dashboard**:
   ```bash
   python run_monitoring_dashboard.py
   ```

2. **Open the Dashboard in a Browser**:
   Navigate to http://127.0.0.1:8081 in your web browser.

3. **Introduce Malware Samples**:
   In a separate terminal, run:
   ```bash
   python test_comprehensive_system_with_specific_samples.py
   ```
   This will simulate the introduction of malware samples and generate alerts.

4. **View Alerts**:
   In the dashboard, click on the "Alerts" tab to see the generated alerts.

5. **Generate Knowledge Graph**:
   Click on the "Knowledge Graph" tab, then click the "Generate Knowledge Graph" button.
   The knowledge graph will be generated and displayed in the dashboard.

6. **Generate Security Report**:
   Click on the "Reports" tab, then click the "Generate Security Report" button.
   The security report will be generated and displayed in the dashboard.

## Recording a Demonstration Video

To record a demonstration video, follow these steps:

1. Start screen recording software.
2. Follow the demonstration workflow above.
3. Narrate the process, explaining:
   - How the dashboard monitors the system
   - How alerts are generated when malware is detected
   - How the knowledge graph visualizes the attack
   - How the security report provides detailed information about the attack
   - How the system helps identify and mitigate security threats

## Troubleshooting

### "Failed to establish a new connection" Error

If you see this error in the terminal, it may be due to:
- The dashboard is not running
- The dashboard is running on a different host/port
- Network connectivity issues

Make sure the dashboard is running and accessible before running the test script.

### No Alerts Showing

If no alerts are showing in the dashboard:
- Check that the test script is running
- Check the console for any error messages
- Try refreshing the dashboard page

### Buttons Not Working

If the buttons for generating knowledge graphs or reports are not working:
- Check the browser console for any JavaScript errors
- Make sure the dashboard has registered the report generator and knowledge graph builder
- Check that the WebSocket connection is established (status should show "Connected")

## Advanced Usage

### Using Real Malware Samples

To use real malware samples from MalwareBazaar:
1. Download sample metadata using the MalwareBazaar API
2. Place the metadata files in the samples directory
3. Run the dashboard and test script as described above

### Customizing the Dashboard

You can customize the dashboard by modifying:
- `src/alerting/alert_dashboard.py`: Dashboard UI and API endpoints
- `run_monitoring_dashboard.py`: Dashboard initialization and configuration
- `src/knowledge_graph/templates/ui_integration.py`: Knowledge graph visualization

## Security Considerations

When working with malware samples, even metadata:
- Use a secure, isolated environment
- Do not execute actual malware samples
- Follow proper security protocols
- Use caution when sharing results
