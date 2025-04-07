# Cyber Attack Tracer - Setup Guide

This guide provides step-by-step instructions for setting up and running the Cyber Attack Tracer application.

## Prerequisites

- Python 3.7+ (Python 3.12 recommended)
- Git
- Internet connection for API access
- MalwareBazaar API key

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/Littledogbear/Captone-Project.git
cd Captone-Project
```

### 2. Create and Activate Virtual Environment (Optional but Recommended)

```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install all required packages including:
- FastAPI for the backend API
- Uvicorn for the ASGI server
- NetworkX for knowledge graph generation
- Transformers for AI analysis
- PyTorch (CPU version) for ML operations
- Jinja2 for report templating
- Requests for API communication

### 4. Configure Environment Variables

Set up your MalwareBazaar API key as an environment variable:

```bash
# On Windows (Command Prompt)
set Malware_Bazzar_personal_key=your_api_key_here

# On Windows (PowerShell)
$env:Malware_Bazzar_personal_key="your_api_key_here"

# On macOS/Linux
export Malware_Bazzar_personal_key=your_api_key_here
```

### 5. Create Required Directories

The application needs several directories for storing outputs:

```bash
mkdir -p output/dashboard_graphs
mkdir -p output/dashboard_reports
mkdir -p logs
```

## Running the Application

### Start the Dashboard

```bash
python run_monitoring_dashboard.py
```

This command:
1. Initializes the FastAPI application and routes
2. Sets up WebSocket connections for real-time monitoring
3. Creates necessary database tables
4. Starts the Uvicorn server
5. Loads AI models and MITRE mappings
6. Begins system monitoring

### Access the Dashboard

Open your web browser and navigate to:
```
http://127.0.0.1:8081
```

The dashboard provides:
- System monitoring metrics
- Real-time alerts
- Knowledge graph visualization
- Security report generation

## Testing with Malware Samples

To test the application with malware samples:

```bash
python test_malwarebazaar_samples.py
```

This will:
1. Download safe malware samples from MalwareBazaar
2. Analyze the samples for malicious behavior
3. Generate knowledge graphs of the behavior
4. Create security reports with MITRE ATT&CK mappings

## Troubleshooting

### API Connection Issues

If you encounter issues connecting to MalwareBazaar:
- Verify your API key is correctly set as an environment variable
- Check your internet connection
- Ensure the API endpoint is accessible

### Dashboard Not Starting

If the dashboard fails to start:
- Check if the port (default: 8081) is already in use
- Verify all dependencies are installed
- Check the logs directory for error messages

## Advanced Configuration

You can modify the dashboard configuration in:
```
config/monitoring_dashboard_config.yaml
```

Key settings include:
- Host and port for the dashboard
- Monitoring intervals
- UI theme
- Knowledge graph generation settings
- Report generation settings
