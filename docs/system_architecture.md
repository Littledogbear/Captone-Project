# Cyber Attack Tracer - System Architecture

## System Architecture Diagram

```
+-------------------------------------------------------------------------------------------------------------+
|                                     Cyber Attack Tracer System                                              |
+-------------------------------------------------------------------------------------------------------------+
|                                                                                                             |
|  +-------------------+    +-------------------+    +-------------------+    +-------------------+           |
|  |                   |    |                   |    |                   |    |                   |           |
|  |  Trace Collection |    |  Analysis Engine  |    | Knowledge Graph   |    |  Reporting System |           |
|  |  System           |    |                   |    | Generator         |    |                   |           |
|  |                   |    |                   |    |                   |    |                   |           |
|  +--------+----------+    +--------+----------+    +--------+----------+    +--------+----------+           |
|           |                        |                        |                        |                      |
|           v                        v                        v                        v                      |
|  +-------------------+    +-------------------+    +-------------------+    +-------------------+           |
|  |                   |    |                   |    |                   |    |                   |           |
|  | Platform-specific |    | Malware Analysis  |    | Graph Visualizer  |    | Report Generator  |           |
|  | Collectors        |    | Integration       |    |                   |    |                   |           |
|  |                   |    |                   |    |                   |    |                   |           |
|  +-------------------+    +-------------------+    +-------------------+    +-------------------+           |
|                                    |                                                                        |
|                                    v                                                                        |
|  +-------------------+    +-------------------+    +-------------------+    +-------------------+           |
|  |                   |    |                   |    |                   |    |                   |           |
|  | Real-time         |    | AI Analysis       |    | Attribution       |    | Trend Analysis    |           |
|  | Monitoring        |    | Integration       |    | Engine            |    |                   |           |
|  |                   |    |                   |    |                   |    |                   |           |
|  +--------+----------+    +-------------------+    +-------------------+    +-------------------+           |
|           |                                                                                                 |
|           v                                                                                                 |
|  +-------------------+    +-------------------+    +-------------------+                                    |
|  |                   |    |                   |    |                   |                                    |
|  | Alerting System   |    | Dashboard         |    | IOC Integration   |                                    |
|  |                   |    |                   |    |                   |                                    |
|  |                   |    |                   |    |                   |                                    |
|  +-------------------+    +-------------------+    +-------------------+                                    |
|                                                                                                             |
+-------------------------------------------------------------------------------------------------------------+
|                                                                                                             |
|                                        FastAPI Backend                                                      |
|                                                                                                             |
+-------------------------------------------------------------------------------------------------------------+
```

## Major Components

### 1. FastAPI Backend

**Purpose:** Serves as the core API layer that connects all components and provides endpoints for external interaction.

**Functionality:**
- RESTful API endpoints for trace collection, analysis, and reporting
- Authentication and authorization for secure access
- Request validation and error handling
- Cross-platform compatibility
- Asynchronous processing for improved performance

**Key Files:**
- `src/main.py`: Main application entry point
- `src/api/routes/`: API route definitions
- `src/api/models/`: Data models for API requests/responses

### 2. Trace Collection System

**Purpose:** Collects system traces from various sources to identify potential malware activity.

**Functionality:**
- Platform-specific collectors for Windows and macOS
- Process monitoring to track suspicious processes
- File system monitoring to detect file modifications
- Registry monitoring (Windows) to detect system changes
- Network connection monitoring to identify suspicious traffic
- Memory analysis for advanced threat detection

**Key Files:**
- `src/trace_collector/base_collector.py`: Abstract base class for collectors
- `src/trace_collector/windows_collector.py`: Windows-specific implementation
- `src/trace_collector/mac_collector.py`: macOS-specific implementation
- `src/trace_collector/collector.py`: Main orchestration class

### 3. Analysis Engine

**Purpose:** Analyzes collected traces to identify malware behavior and attack patterns.

**Functionality:**
- Trace analysis to identify suspicious patterns
- File analysis to detect malicious code
- Behavior analysis to identify attack techniques
- Integration with external analysis services
- AI-powered analysis for advanced threat detection
- Confidence scoring for detected threats

**Key Files:**
- `src/analysis_engine/analyzer.py`: Main analysis orchestration
- `src/analysis_engine/file_analyzer.py`: File analysis functionality
- `src/analysis_engine/ai_analysis_integrator.py`: AI analysis integration
- `src/ember_integration/behavior_analyzer.py`: Behavior analysis

### 4. AI Analyzer

**Purpose:** Provides advanced AI-powered analysis of malware behavior and attack patterns.

**Functionality:**
- Natural language processing for threat description
- Pattern recognition for attack technique identification
- Anomaly detection for unknown threats
- Confidence scoring for detected techniques
- Contextual analysis of attack patterns

**Key Files:**
- `src/analysis_engine/ai_analysis_integrator.py`: AI analysis integration
- `src/trace_collector/ai_trace_analyzer.py`: AI-powered trace analysis

### 5. MITRE Mapping Module

**Purpose:** Maps observed behavior to MITRE ATT&CK framework techniques.

**Functionality:**
- Technique identification based on observed behavior
- Confidence scoring for identified techniques
- Technique description retrieval
- Tactic categorization
- Attack pattern analysis

**Key Files:**
- `src/knowledge_graph/attack_kg_mapping.json`: Mapping definitions
- `src/knowledge_graph/knowledge_graph_builder.py`: Technique mapping logic

### 6. Knowledge Graph Generator

**Purpose:** Builds knowledge graphs representing attack techniques and their relationships.

**Functionality:**
- Graph construction from analyzed traces
- Node and edge creation for different entity types
- Relationship mapping between entities
- Attack pattern identification
- Enhanced visualization preparation

**Key Files:**
- `src/knowledge_graph/knowledge_graph_builder.py`: Basic graph builder
- `src/knowledge_graph/enhanced_graph_builder.py`: Enhanced graph builder
- `src/knowledge_graph/graph_visualizer.py`: Graph visualization

### 7. Dashboard

**Purpose:** Provides a real-time monitoring interface for system activity and alerts.

**Functionality:**
- Real-time system metrics display
- Alert visualization and management
- Knowledge graph integration
- Report generation interface
- Interactive data visualization
- Responsive web interface

**Key Files:**
- `src/alerting/monitoring_dashboard.py`: Dashboard implementation
- `src/alerting/templates/real_time_dashboard.html`: Dashboard template
- `src/alerting/static/dashboard.css`: Dashboard styling

### 8. Alerting System

**Purpose:** Manages and sends alerts for detected threats.

**Functionality:**
- Alert generation based on severity
- Alert categorization by type
- Notification delivery
- Alert history management
- Severity calculation

**Key Files:**
- `src/alerting/alert_types.py`: Alert type definitions
- `src/alerting/alert_manager.py`: Alert management
- `src/alerting/severity_manager.py`: Severity calculation
- `src/alerting/severity_notifier.py`: Notification delivery

### 9. Reporting System

**Purpose:** Generates comprehensive reports from analysis results.

**Functionality:**
- HTML report generation
- JSON report generation
- Visualization integration
- Threat level assessment
- Security improvement suggestions
- Malware details presentation

**Key Files:**
- `src/reporting/report_generator.py`: Report generation logic
- `src/reporting/templates/report_template.html`: HTML report template

### 10. External Integrations

**Purpose:** Integrates with external services for enhanced analysis.

**Functionality:**
- MalwareBazaar integration for sample analysis
- VirusTotal integration for malware detection
- Sandbox integration for safe execution
- IOC analysis for threat intelligence
- Geolocation services for attribution

**Key Files:**
- `src/virustotal_integration/virustotal_analyzer.py`: VirusTotal integration
- `src/sandbox/cuckoo_integration.py`: Sandbox integration
- `src/ioc_integration/ioc_analyzer.py`: IOC analysis

## Data Flow

1. **Trace Collection:** System traces are collected from the host system using platform-specific collectors.
2. **Analysis:** Collected traces are analyzed to identify suspicious behavior and potential malware.
3. **Technique Mapping:** Identified behavior is mapped to MITRE ATT&CK techniques.
4. **Knowledge Graph Construction:** A knowledge graph is built representing the attack techniques and their relationships.
5. **Alert Generation:** Alerts are generated based on the severity of detected threats.
6. **Visualization:** Knowledge graphs and system metrics are visualized in the dashboard.
7. **Reporting:** Comprehensive reports are generated from analysis results.

## Key Features

1. **Real-time Monitoring:** Continuous monitoring of system activity with immediate alerts.
2. **Knowledge Graph Visualization:** Interactive visualization of attack patterns.
3. **AI-powered Analysis:** Advanced threat detection using AI techniques.
4. **Comprehensive Reporting:** Detailed reports with security improvement suggestions.
5. **Cross-platform Support:** Works on both Windows and macOS.
6. **External Integrations:** Integration with external services for enhanced analysis.
7. **Attribution Analysis:** Identification of potential threat actors.
8. **Trend Analysis:** Analysis of attack technique trends over time.
