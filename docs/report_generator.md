# Report Generator Documentation

## Overview
The Report Generator in the Cyber Attack Tracer system incorporates AI analysis into comprehensive reports, processing AI analysis data into structured formats, extracting threat levels from AI confidence scores, presenting AI-identified techniques with descriptions, and generating security improvement suggestions based on AI analysis.

## Core Components

### 1. Report Generator
Located in `src/reporting/report_generator.py`, this component:
- Incorporates AI analysis into comprehensive reports
- Processes AI analysis data into structured formats
- Extracts threat levels from AI confidence scores
- Presents AI-identified techniques with descriptions
- Generates security improvement suggestions based on AI analysis

Key methods:
```python
def generate_report(self, analysis_data, output_file: str = "", report_type: str = "html") -> str:
    """
    Generate a report from analysis data.
    
    Args:
        analysis_data: Dictionary containing analysis data or string
        output_file: Optional path to save the report to
        report_type: Type of report to generate (html, json, or comprehensive)
        
    Returns:
        Path to the generated report
    """
    try:
        if isinstance(analysis_data, str):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if output_file:
                report_path = output_file
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
            else:
                report_path = os.path.join(self.output_dir, f"report_{timestamp}.html")
            
            with open(report_path, "w") as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Simple Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Report Generated at {timestamp}</h1>
    <p>{analysis_data}</p>
</body>
</html>""")
            
            return report_path
        
        # Generate timestamp for report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Process analysis data
        processed_data = self._process_analysis_data(analysis_data)
        
        # Generate visualizations
        visualizations = self._generate_visualizations(analysis_data)
        
        # Generate improvement suggestions
        suggestions = self._generate_improvement_suggestions(analysis_data)
        
        # Combine all data for the report
        report_data = {
            "timestamp": timestamp,
            "analysis_data": processed_data,
            "visualizations": visualizations,
            "suggestions": suggestions
        }
        
        # Generate report based on type
        if report_type == "html" or report_type == "comprehensive":
            return self._generate_html_report(report_data, timestamp, output_file)
        elif report_type == "json":
            return self._generate_json_report(report_data, timestamp, output_file)
        else:
            self.logger.error(f"Unsupported report type: {report_type}")
            return ""
    except Exception as e:
        self.logger.error(f"Error generating report: {str(e)}")
        return ""
```

### 2. AI Analysis Integration
The generator integrates AI analysis into reports:
- Processes AI analysis data into structured formats
- Extracts threat levels from AI confidence scores
- Presents AI-identified techniques with descriptions

Key methods:
```python
def _process_analysis_data(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """Process and structure analysis data for the report."""
    if isinstance(analysis_data, str):
        return {
            "summary": {
                "scan_time": datetime.now().isoformat(),
                "threat_level": "UNKNOWN",
                "total_processes": 0,
                "total_network_connections": 0,
                "total_file_events": 0,
                "total_registry_events": 0
            },
            "malware_analysis": [],
            "attack_techniques": [],
            "system_activity": {
                "processes": [],
                "network": [],
                "file_system": [],
                "registry": []
            }
        }
        
    processed_data = {
        "summary": {
            "scan_time": analysis_data.get("timestamp", datetime.now().isoformat()),
            "threat_level": self._determine_overall_threat_level(analysis_data),
            "total_processes": len(analysis_data.get("processes", [])),
            "total_network_connections": len(analysis_data.get("network_connections", [])),
            "total_file_events": len(analysis_data.get("file_system_events", [])),
            "total_registry_events": len(analysis_data.get("registry_events", []))
        },
        "malware_analysis": self._process_malware_analysis(analysis_data),
        "attack_techniques": self._process_attack_techniques(analysis_data),
        "system_activity": {
            "processes": self._process_processes(analysis_data.get("processes", [])),
            "network": self._process_network_connections(analysis_data.get("network_connections", [])),
            "file_system": analysis_data.get("file_system_events", []),
            "registry": analysis_data.get("registry_events", [])
        }
    }
    
    if "ai_analysis" in analysis_data:
        ai_analysis = analysis_data["ai_analysis"]
        if isinstance(ai_analysis, dict):
            processed_data["ai_analysis"] = ai_analysis
        else:
            processed_data["ai_analysis"] = {"summary": str(ai_analysis)}
    
    if "ioc_analysis" in analysis_data:
        ioc_analysis = analysis_data["ioc_analysis"]
        if isinstance(ioc_analysis, dict):
            processed_data["ioc_analysis"] = ioc_analysis
        else:
            processed_data["ioc_analysis"] = {"summary": str(ioc_analysis)}
    
    return processed_data
```

### 3. Security Improvement Suggestions
The generator generates security improvement suggestions based on AI analysis:
- Maps detected MITRE ATT&CK techniques to specific security improvements
- Uses detected technique IDs to determine relevant countermeasures
- Generates targeted recommendations based on specific malware behaviors
- Prioritizes recommendations based on severity and confidence of detected techniques

Key methods:
```python
def _generate_improvement_suggestions(self, analysis_data) -> List[Dict[str, Any]]:
    """Generate security improvement suggestions based on analysis data."""
    suggestions = []
    
    # Example suggestion
    suggestions.append({
        "title": "Implement defense-in-depth strategy",
        "description": "Deploy multiple layers of security controls to protect against coordinated attacks.",
        "priority": "critical"
    })
    
    # Additional suggestions based on analysis data
    # ...
    
    return suggestions
```

## Integration Points

1. **With AI Trace Analyzer**
   - Incorporates AI analysis into comprehensive reports
   - Processes AI analysis data into structured formats
   - Extracts threat levels from AI confidence scores
   - Presents AI-identified techniques with descriptions

2. **With Knowledge Graph Builder**
   - Integrates knowledge graph results into reports
   - Provides visualizations of attack patterns and trends

3. **With Visualization Engine**
   - Provides static and interactive visualizations of knowledge graphs
   - Visualizes the full scope of a malware attack

## Error Handling

The report generator implements robust error handling:
- Graceful degradation of functionality
- Detailed error logging for debugging
- Default report results when generation fails

## Performance Considerations

The system is optimized for CPU-only operation:
- Efficient text processing
- Minimal memory footprint
- Background thread initialization

## Security Features

The report generator implements several security measures:
- No external API dependencies
- Local-only model execution
- Sanitized input processing
- Secure output handling

## Testing

The report generator can be tested using:
```python
python test_comprehensive_system_with_specific_samples.py
```

This will:
- Test AI analysis with specific malware samples
- Verify integration with other components
- Generate test reports and visualizations
- Validate confidence score calculations
