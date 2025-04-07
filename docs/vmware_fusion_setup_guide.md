# VMware Fusion Setup Guide for Cyber Attack Tracer

This guide provides detailed instructions for setting up and testing the Cyber Attack Tracer project in a VMware Fusion virtual machine environment.

## 1. Environment Setup

### 1.1 Clone the Repository
```bash
# Clone the repository
git clone https://github.com/Littledogbear/Captone-Project.git
cd Captone-Project
```

### 1.2 Create and Activate Virtual Environment
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux
source venv/bin/activate
# On Windows
# venv\Scripts\activate
```

### 1.3 Install Dependencies
```bash
# Install required packages
pip install -r requirements.txt

# Install additional ML dependencies if needed
pip install transformers torch numpy
```

### 1.4 Configure Environment Variables
```bash
# Set your MalwareBazaar API key
export Malware_Bazzar_personal_key="your_api_key_here"
```

## 2. Testing the Application

### 2.1 Start the Monitoring Dashboard
```bash
# Run the monitoring dashboard
python run_monitoring_dashboard.py
```

The dashboard will be accessible at: http://127.0.0.1:8082

### 2.2 Dashboard Features
The dashboard includes several tabs:
- **System Monitoring**: Shows CPU, memory, disk, and network metrics
- **Alerts**: Displays security alerts with severity levels
- **Knowledge Graph**: Visualizes attack patterns and relationships
- **Reports**: Generates and displays security reports

## 3. Working with Malware Samples

### 3.1 Downloading Samples from MalwareBazaar
```bash
# Run the MalwareBazaar sample downloader
python test_malwarebazaar_samples.py
```

This script will:
1. Connect to MalwareBazaar API using your API key
2. Download sample malware files to the `samples` directory
3. Store metadata about the samples for analysis

### 3.2 Simulating Malware Detection
```bash
# Run the attribution test with samples
python run_attribution_test_with_sample_data.py
```

This will:
1. Process the downloaded malware samples
2. Generate attribution data
3. Create knowledge graphs
4. Produce security reports

### 3.3 Running Comprehensive Tests
```bash
# Run comprehensive system test with specific samples
python test_comprehensive_system_with_specific_samples.py
```

This test demonstrates the full system capabilities with predefined malware samples.

## 4. Demonstration Workflow

For a complete demonstration of the system's capabilities, follow these steps:

1. Start the monitoring dashboard:
   ```bash
   python run_monitoring_dashboard.py
   ```

2. In a separate terminal (with virtual environment activated), run:
   ```bash
   python run_attribution_dashboard_test.py
   ```

3. Navigate to http://127.0.0.1:8082 in your browser

4. Explore the dashboard tabs:
   - View system metrics on the System Monitoring tab
   - Check alerts on the Alerts tab
   - Generate and view knowledge graphs on the Knowledge Graph tab
   - Generate and view security reports on the Reports tab

5. Download and examine the generated reports and knowledge graphs

## 5. Troubleshooting

### 5.1 Port Conflicts
If you encounter port conflicts, modify the port in the dashboard script:
```python
# In run_monitoring_dashboard.py or similar files
uvicorn.run(app, host="127.0.0.1", port=8083)  # Change port number
```

### 5.2 API Key Issues
If MalwareBazaar API requests fail, verify your API key is correctly set:
```bash
echo $Malware_Bazzar_personal_key
```

### 5.3 Missing Dependencies
If you encounter missing module errors, install the specific dependency:
```bash
pip install <module_name>
```

## 6. Safety Considerations

When working with malware samples, even in a controlled environment:
- Ensure your virtual machine is isolated from your main network
- Do not execute malware samples directly
- Use the built-in analysis tools to examine samples safely
- Keep your VM software updated with security patches
