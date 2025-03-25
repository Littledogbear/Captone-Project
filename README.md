# Cyber Attack Trace Collector and Analyzer

A comprehensive system for collecting, analyzing, and visualizing cyber attack traces. This software helps security professionals identify attack patterns, categorize malware, and prevent future attacks.

## Features

- **Automated Trace Collection**: Collect system traces including processes, network connections, and system resources
- **AI-Powered Analysis**: Analyze traces using advanced AI techniques to identify attack patterns
- **Knowledge Graph Construction**: Build knowledge graphs to visualize attack techniques and their relationships
- **VirusTotal Integration**: Leverage the VirusTotal API for malware analysis and categorization
- **Attack Technique Identification**: Map observed behaviors to MITRE ATT&CK techniques
- **Advanced Visualization**: Interactive and static visualization of knowledge graphs and attack patterns
- **Trend Analysis**: Identify emerging attack technique trends over time
- **Attribution Capabilities**: Identify potential origins of attacks through geolocation and tool fingerprinting
- **Real-time Monitoring**: Continuously monitor system for suspicious activities
- **Automated Alerting**: Generate alerts for detected threats with configurable severity levels
- **Alert Dashboard**: Web-based dashboard for viewing and managing alerts

## System Architecture

The system consists of the following main components:

1. **Trace Collector**: Collects system traces from various sources
2. **Analysis Engine**: Analyzes traces to identify attack patterns
3. **Knowledge Graph Builder**: Constructs knowledge graphs from analyzed traces
4. **VirusTotal Integration**: Integrates with the VirusTotal API for malware analysis
5. **Visualization Engine**: Provides static and interactive visualizations
6. **Attribution Engine**: Identifies potential attack origins
7. **Trend Analyzer**: Analyzes attack technique trends over time
8. **Real-time Monitor**: Continuously monitors system for suspicious activities
9. **Alert Manager**: Manages and sends alerts for detected threats
10. **Alert Dashboard**: Provides a web interface for viewing and managing alerts

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

## Usage

### API Endpoints

The system provides a RESTful API with the following main endpoints:

- `/traces/collect`: Collect system traces
- `/traces/analyze`: Analyze collected traces
- `/knowledge/build`: Build a knowledge graph from traces
- `/malware/analyze`: Analyze a malware sample using VirusTotal
- `/malware/categorize`: Categorize malware based on extracted features
- `/trends/analyze`: Analyze trends in attack techniques
- `/attribution/analyze`: Attribute an attack based on traces
- `/visualization/graph`: Create a visualization of a knowledge graph
- `/visualization/interactive`: Create an interactive visualization of a knowledge graph
- `/monitoring/status`: Get real-time monitoring status
- `/monitoring/start`: Start real-time monitoring
- `/monitoring/stop`: Stop real-time monitoring
- `/alerts`: Get recent alerts
- `/alerts/clear`: Clear all alerts
- `/dashboard`: Get the URL for the alert dashboard

### Example Usage

Check the `examples` directory for example scripts demonstrating how to use the system:

- `visualization_example.py`: Demonstrates how to create and visualize knowledge graphs
- `real_time_monitoring_example.py`: Demonstrates how to use the real-time monitoring and alerting system

## Configuration

The system configuration is stored in `config/config.yaml`. You can modify this file to change the system settings.

### Real-time Monitoring Configuration

```yaml
real_time_monitor:
  enabled: true
  monitoring_interval: 30  # seconds
  max_history: 100
  alert_dir: "data/alerts"

alerting:
  enabled: true
  alert_dir: "data/alerts"
  max_history: 1000
  enabled_handlers: ["console", "file"]
  suspicious_processes: ["mimikatz", "psexec", "netcat", "nc.exe"]
  suspicious_ports: [4444, 8080, 9001, 31337]
```

## Testing

The system includes several test scripts to verify its functionality:

- `test_trace_collector.py`: Test the trace collector component
- `test_virustotal_integration.py`: Test the VirusTotal integration
- `test_knowledge_graph.py`: Test the knowledge graph builder
- `test_trend_analyzer.py`: Test the trend analyzer
- `test_attribution.py`: Test the attribution engine
- `test_real_time_monitoring.py`: Test the real-time monitoring and alerting system
- `test_main_application.py`: Test the main application

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [EMBER Dataset](https://github.com/elastic/ember) for providing malware analysis data
- [MITRE ATT&CK](https://attack.mitre.org/) for the attack technique framework
- [NetworkX](https://networkx.org/) for graph operations
- [D3.js](https://d3js.org/) for interactive visualizations
