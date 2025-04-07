"""
Test script to demonstrate all features of the Cyber Attack Trace Analyzer working together.
This includes:
- UI components
- Knowledge graph generation
- Report generation
- AI analysis
- Multi-malware attack detection
"""
import os
import sys
import json
import logging
import matplotlib.pyplot as plt
import networkx as nx
from datetime import datetime
import time
import random
import threading

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.ember_integration.behavior_analyzer import BehaviorAnalyzer
from src.ember_integration.malware_categorizer import MalwareCategorizer
from src.ioc_integration.ioc_analyzer import IOCAnalyzer
from src.knowledge_graph.enhanced_graph_builder import EnhancedGraphBuilder
from src.reporting.report_generator import ReportGenerator
from src.trace_collector.ai_trace_analyzer import AITraceAnalyzer
from src.analysis_engine.ai_analysis_integrator import AIAnalysisIntegrator
from src.attribution.attribution_engine import AttributionEngine
from src.analysis_engine.trend_analyzer import TrendAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_test_results():
    """Load test results from test_results.json."""
    results_file = os.path.join(os.path.dirname(__file__), "test_results.json")
    if not os.path.exists(results_file):
        logger.error(f"Test results file {results_file} does not exist")
        return []
    try:
        with open(results_file, "r") as f:
            results = json.load(f)
        logger.info(f"Loaded {len(results)} malware sample results")
        return results
    except Exception as e:
        logger.error(f"Error loading test results: {str(e)}")
        return []

def select_diverse_samples(results, count=3):
    """Select diverse malware samples from results."""
    if not results:
        return []
    
    filtered_samples = []
    seen_types = set()
    
    for result in results:
        category = result.get("category", {}).get("category", "unknown")
        if category not in seen_types and len(seen_types) < count:
            seen_types.add(category)
            filtered_samples.append(result)
    
    if len(filtered_samples) < count:
        remaining = count - len(filtered_samples)
        for result in results:
            if len(filtered_samples) >= count:
                break
            if result not in filtered_samples:
                filtered_samples.append(result)
                remaining -= 1
    
    logger.info(f"Selected {len(filtered_samples)} diverse malware samples")
    return filtered_samples

def generate_traces(samples):
    """Generate traces for multiple malware samples."""
    traces = []
    timestamp_base = datetime.now().strftime("%Y-%m-%dT%H:")
    
    for i, sample in enumerate(samples):
        sample_info = sample.get("sample_info", {})
        behavior = sample.get("behavior", {})
        
        main_pid = 1000 + i
        
        traces.append({
            "type": "process",
            "pid": main_pid,
            "name": sample_info.get("file_name", "malware.exe"),
            "command_line": f"{sample_info.get('file_name', 'malware.exe')} --hidden",
            "timestamp": f"{timestamp_base}00:{i}0Z"
        })
        
        for j, operation in enumerate(behavior.get("file_operations", ["write"])):
            traces.append({
                "type": "file",
                "process_id": main_pid,
                "path": f"C:\\Users\\victim\\Documents\\file_{i}_{j}.txt",
                "operation": operation,
                "timestamp": f"{timestamp_base}01:{i}{j}Z"
            })
        
        for j, operation in enumerate(behavior.get("network_operations", ["connect"])):
            traces.append({
                "type": "network",
                "process_id": main_pid,
                "destination": f"malware-{i}.net",
                "port": 443 + j,
                "protocol": "tcp",
                "operation": operation,
                "timestamp": f"{timestamp_base}02:{i}{j}Z"
            })
        
        for j, operation in enumerate(behavior.get("registry_operations", ["write"])):
            traces.append({
                "type": "registry",
                "process_id": main_pid,
                "key": f"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware_{i}",
                "value": sample_info.get("file_name", "malware.exe"),
                "operation": operation,
                "timestamp": f"{timestamp_base}03:{i}{j}Z"
            })
    
    if len(samples) > 1:
        for i in range(len(samples)):
            for j in range(len(samples)):
                if i != j:
                    traces.append({
                        "type": "file",
                        "process_id": 1000 + i,
                        "path": f"C:\\Users\\victim\\Documents\\file_{j}_0.txt",
                        "operation": "read",
                        "timestamp": f"{timestamp_base}04:{i}{j}Z"
                    })
                    
                    traces.append({
                        "type": "registry",
                        "process_id": 1000 + i,
                        "key": f"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware_{j}",
                        "value": "modified_value",
                        "operation": "write",
                        "timestamp": f"{timestamp_base}05:{i}{j}Z"
                    })
    
    logger.info(f"Generated {len(traces)} traces for multi-malware attack scenario")
    return traces

def build_knowledge_graph(traces):
    """Build knowledge graph from traces."""
    kg_builder = EnhancedGraphBuilder()
    graph = kg_builder.build_graph_from_traces(traces)
    techniques = kg_builder.identify_techniques()
    
    logger.info(f"Built knowledge graph with {len(techniques)} identified techniques")
    
    return graph, techniques

def visualize_graph(graph, output_path):
    """Visualize knowledge graph and save to file."""
    plt.figure(figsize=(12, 10))
    
    pos = nx.spring_layout(graph, seed=42)
    
    process_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'process']
    file_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'file']
    network_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'network']
    registry_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'registry']
    
    nx.draw_networkx_nodes(graph, pos, nodelist=process_nodes, node_color='red', node_size=500, alpha=0.8)
    nx.draw_networkx_nodes(graph, pos, nodelist=file_nodes, node_color='blue', node_size=400, alpha=0.8)
    nx.draw_networkx_nodes(graph, pos, nodelist=network_nodes, node_color='green', node_size=400, alpha=0.8)
    nx.draw_networkx_nodes(graph, pos, nodelist=registry_nodes, node_color='purple', node_size=400, alpha=0.8)
    
    nx.draw_networkx_edges(graph, pos, width=1.0, alpha=0.5, arrows=True)
    
    process_labels = {n: f"P:{graph.nodes[n].get('pid', '')}" for n in process_nodes}
    file_labels = {n: f"F:{os.path.basename(n)}" for n in file_nodes}
    network_labels = {n: f"N:{graph.nodes[n].get('destination', '')}" for n in network_nodes}
    registry_labels = {n: f"R:{os.path.basename(n)}" for n in registry_nodes}
    
    nx.draw_networkx_labels(graph, pos, labels=process_labels, font_size=8)
    nx.draw_networkx_labels(graph, pos, labels=file_labels, font_size=8)
    nx.draw_networkx_labels(graph, pos, labels=network_labels, font_size=8)
    nx.draw_networkx_labels(graph, pos, labels=registry_labels, font_size=8)
    
    plt.title("Multi-Malware Attack Knowledge Graph")
    plt.axis('off')
    plt.tight_layout()
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close()
    
    logger.info(f"Saved knowledge graph visualization to {output_path}")

def analyze_with_ai(samples, traces):
    """Analyze malware samples with AI components."""
    ai_trace_analyzer = AITraceAnalyzer()
    attribution_engine = AttributionEngine()
    trend_analyzer = TrendAnalyzer()
    
    ai_analysis_integrator = AIAnalysisIntegrator()
    
    analysis_results = []
    
    for sample in samples:
        sample_info = sample.get("sample_info", {})
        sha256 = sample_info.get("sha256_hash", "")
        
        logger.info(f"Performing AI analysis on sample {sha256}")
        
        result = ai_analysis_integrator.analyze_malware_sample(sample)
        analysis_results.append(result)
        
        logger.info(f"AI analysis completed for sample {sha256}")
    
    return analysis_results

def generate_report(samples, traces, techniques, ai_results):
    """Generate comprehensive attack report."""
    report_generator = ReportGenerator()
    
    techniques_list = []
    for technique_id, technique_data in techniques.items():
        techniques_list.append({
            "technique_id": technique_id,
            "technique_name": technique_data.get("name", "Unknown"),
            "confidence": technique_data.get("confidence", 0)
        })
    
    analysis_data = {
        "sample_info": {
            "file_name": "Multi-Malware Attack",
            "file_type": "Multiple",
            "file_size": sum(s.get("sample_info", {}).get("file_size", 0) for s in samples),
            "md5": "",
            "sha1": "",
            "sha256": "",
            "tags": []
        },
        "analysis_result": {
            "severity": "high" if len(techniques) > 3 else "medium" if len(techniques) > 1 else "low",
            "confidence": 0.9,
            "malware_type": "Multi-Malware Attack",
            "techniques": techniques_list
        },
        "system_activity": {
            "processes": [],
            "network_connections": [],
            "file_operations": [],
            "registry_operations": []
        },
        "malware_samples": samples,
        "ai_analysis": ai_results,
        "improvement_suggestions": [
            {
                "title": "Network segmentation",
                "description": "Implement strict network segmentation to contain the spread of multiple malware across the network.",
                "priority": "critical"
            },
            {
                "title": "Keep systems updated",
                "description": "Regularly update operating systems, applications, and security software to patch known vulnerabilities.",
                "priority": "high"
            },
            {
                "title": "Use strong endpoint protection",
                "description": "Deploy comprehensive endpoint protection solutions that include antivirus, anti-malware, and behavioral analysis capabilities.",
                "priority": "high"
            },
            {
                "title": "Implement application whitelisting",
                "description": "Use application whitelisting to prevent unauthorized executables from running on systems.",
                "priority": "high"
            },
            {
                "title": "Network traffic monitoring",
                "description": "Implement network traffic monitoring to detect and block command and control communications.",
                "priority": "high"
            },
            {
                "title": "Egress filtering",
                "description": "Implement egress filtering to block outbound connections to known malicious domains.",
                "priority": "high"
            },
            {
                "title": "Comprehensive security monitoring",
                "description": "Deploy comprehensive security monitoring to detect complex, multi-stage attacks involving multiple malware types.",
                "priority": "high"
            },
            {
                "title": "Incident response plan",
                "description": "Develop and regularly test an incident response plan specifically for complex, coordinated attacks.",
                "priority": "high"
            }
        ]
    }
    
    for trace in traces:
        trace_type = trace.get("type")
        if trace_type == "process":
            analysis_data["system_activity"]["processes"].append(trace)
        elif trace_type == "network":
            analysis_data["system_activity"]["network_connections"].append(trace)
        elif trace_type == "file":
            analysis_data["system_activity"]["file_operations"].append(trace)
        elif trace_type == "registry":
            analysis_data["system_activity"]["registry_operations"].append(trace)
    
    output_dir = os.path.join(os.path.dirname(__file__), "output", "multi_malware_reports")
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, f"multi_malware_report_{timestamp}.html")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Multi-Malware Attack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .section {{ margin-bottom: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #34495e; color: white; }}
    </style>
</head>
<body>
    <h1>Multi-Malware Attack Analysis Report</h1>
    <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    
    <div class="section">
        <h2>Attack Summary</h2>
        <p>This is a complex attack involving {len(samples)} different malware samples. 
        The attack utilizes {len(techniques)} distinct techniques. 
        The malware samples appear to be working in concert, with evidence of interaction between them.</p>
    </div>
    
    <div class="section">
        <h2>Attack Techniques</h2>
        <table>
            <tr>
                <th>Technique ID</th>
                <th>Name</th>
                <th>Confidence</th>
            </tr>
"""
    
    for t_id, t_data in techniques.items():
        html_content += f"""<tr>
            <td>{t_id}</td>
            <td>{t_data.get('name', 'Unknown')}</td>
            <td>{t_data.get('confidence', 0) * 100:.1f}%</td>
        </tr>
"""
    
    html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Malware Samples</h2>
        <table>
            <tr>
                <th>File Name</th>
                <th>Type</th>
                <th>SHA256</th>
            </tr>
"""
    
    for s in samples:
        sample_info = s.get('sample_info', {})
        category = s.get('category', {})
        html_content += f"""<tr>
            <td>{sample_info.get('file_name', 'Unknown')}</td>
            <td>{category.get('category', 'Unknown')}</td>
            <td>{sample_info.get('sha256_hash', 'Unknown')[:16]}...</td>
        </tr>
"""
    
    html_content += """
        </table>
    </div>
    
    <div class="section">
        <h2>Security Improvement Suggestions</h2>
        <ul>
"""
    
    for s in analysis_data.get('improvement_suggestions', []):
        html_content += f"""<li><strong>{s.get('title', '')}</strong>: {s.get('description', '')}</li>
"""
    
    html_content += """
        </ul>
    </div>
</body>
</html>
"""
    
    with open(report_file, "w") as f:
        f.write(html_content)
    
    logger.info(f"Multi-malware attack report saved to {report_file}")
    
    return report_file, analysis_data["analysis_result"]["severity"].upper()

def main():
    """Main function to test all features together."""
    results = load_test_results()
    if not results:
        logger.error("No test results found")
        return
    
    samples = select_diverse_samples(results, 3)
    if not samples:
        logger.error("No diverse samples found")
        return
    
    traces = generate_traces(samples)
    
    graph, techniques = build_knowledge_graph(traces)
    
    output_dir = os.path.join(os.path.dirname(__file__), "output", "holistic_test")
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    graph_path = os.path.join(output_dir, f"multi_malware_graph_{timestamp}.png")
    
    visualize_graph(graph, graph_path)
    
    ai_results = analyze_with_ai(samples, traces)
    
    report_file, severity = generate_report(samples, traces, techniques, ai_results)
    
    print("\n=== Multi-Malware Attack Analysis Summary ===\n")
    print(f"Analyzed {len(samples)} malware samples in a coordinated attack")
    print(f"Identified {len(techniques)} attack techniques")
    print(f"Overall severity: {severity}")
    print(f"Report saved to: {report_file}")
    print(f"Knowledge graph saved to: {graph_path}")
    print("\nAttack summary:")
    
    malware_types = [s.get("category", {}).get("category", "unknown") if s.get("category") else "unknown" for s in samples]
    print(f"This is a complex attack involving {len(samples)} different malware samples ({', '.join(filter(None, malware_types))}). "
          f"The attack utilizes {len(techniques)} distinct techniques including "
          f"{next(iter(techniques.values())).get('name', 'unknown')}. "
          f"The malware samples appear to be working in concert, with evidence of interaction between them. "
          f"This suggests a coordinated attack rather than isolated incidents.")

if __name__ == "__main__":
    main()
