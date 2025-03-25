# Installation Instructions

## Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

## Installation Steps

1. **Create and activate a virtual environment (recommended)**:
   ```bash
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   
   # On Windows
   python -m venv venv
   venv\Scripts\activate
   ```

2. **Install the package**:
   ```bash
   pip install -e .
   ```
   This will install the package in development mode, along with all its dependencies.

3. **Run the tests**:
   ```bash
   python test_trace_collector.py
   python test_virustotal_integration.py
   python test_knowledge_graph.py
   python test_trend_analyzer.py
   python test_attribution.py
   python test_main_application.py
   ```

4. **Start the application**:
   ```bash
   uvicorn src.main:app --reload
   ```
   The API will be available at http://localhost:8000

5. **View the API documentation**:
   Open http://localhost:8000/docs in your web browser to view the Swagger UI documentation.

## Example Usage

Check the `examples` directory for example scripts demonstrating how to use the system.

For example, to run the visualization example:
```bash
python examples/visualization_example.py
```

## Configuration

The system configuration is stored in `config/config.yaml`. You can modify this file to change the system settings.

## Logs

Logs are stored in the `logs` directory. The logging configuration is stored in `config/logging_config.yaml`.
