"""
Run a focused attribution test with sample data designed to demonstrate attribution functionality.
This script shows attribution results without requiring a dashboard server.
"""

import os
import sys
import json
import logging
from datetime import datetime
from pathlib import Path
import networkx as nx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attribution_test")

output_dir = Path("output/attribution_test")
output_dir.mkdir(parents=True, exist_ok=True)

def create_actor_profiles():
    """Create actor profiles for attribution matching."""
    return {
        "APT28": {
            "name": "APT28",
            "aliases": ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
            "attribution": {
                "country": "RU",
                "type": "state-sponsored"
            },
            "tools": ["X-Agent", "X-Tunnel", "Mimikatz"],
            "techniques": ["T1055", "T1059.003", "T1071.001", "T1547.001"],
            "description": "Russian state-sponsored threat actor known for targeting government and military organizations."
        },
        "Lazarus": {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "Guardians of Peace"],
            "attribution": {
                "country": "KP",
                "type": "state-sponsored"
            },
            "tools": ["HOPLIGHT", "BLINDINGCAN", "ELECTRICFISH"],
            "techniques": ["T1486", "T1490", "T1083", "T1222.001"],
            "description": "North Korean state-sponsored threat actor known for financially motivated attacks."
        }
    }

def create_sample_data():
    """Create sample data with attribution indicators."""
    return {
        "TrojanSample": {
            "sha256": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "name": "TrojanSample.exe",
            "type": "trojan",
            "tags": ["trojan", "stealer", "backdoor"],
            "description": "This trojan establishes persistence through registry modifications and communicates with command and control servers.",
            "network": [
                {
                    "ip": "45.77.65.211",
                    "country": "Russia",
                    "country_code": "RU",
                    "city": "Moscow"
                }
            ],
            "tools": [
                {
                    "name": "X-Agent",
                    "confidence": 0.92
                },
                {
                    "name": "X-Tunnel",
                    "confidence": 0.85
                }
            ],
            "techniques": [
                "T1055",  # Process Injection
                "T1059.003",  # Windows Command Shell
                "T1071.001",  # Web Protocols
                "T1547.001"  # Registry Run Keys / Startup Folder
            ]
        },
        "RansomwareSample": {
            "sha256": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
            "name": "RansomwareSample.exe",
            "type": "ransomware",
            "tags": ["ransomware", "encryptor"],
            "description": "This ransomware encrypts user files and demands payment for decryption.",
            "network": [
                {
                    "ip": "175.45.176.3",
                    "country": "North Korea",
                    "country_code": "KP",
                    "city": "Pyongyang"
                }
            ],
            "tools": [
                {
                    "name": "HOPLIGHT",
                    "confidence": 0.88
                }
            ],
            "techniques": [
                "T1486",  # Data Encrypted for Impact
                "T1490",  # Inhibit System Recovery
                "T1083",  # File and Directory Discovery
                "T1222.001"  # File and Directory Permissions Modification
            ]
        }
    }

def run_attribution_analysis():
    """Run attribution analysis on sample data."""
    sample_data = create_sample_data()
    actor_profiles = create_actor_profiles()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    results = {}
    
    for sample_name, sample in sample_data.items():
        print(f"\n{'='*80}")
        print(f"ATTRIBUTION ANALYSIS FOR {sample_name}")
        print(f"{'='*80}")
        
        attribution_result = attribute_sample(sample, actor_profiles)
        
        attribution_file = output_dir / f"attribution_{sample_name}_{timestamp}.json"
        with open(attribution_file, "w") as f:
            json.dump(attribution_result, f, indent=2)
        
        print(f"\nAttribution Result:")
        if attribution_result["potential_actors"]:
            for actor in attribution_result["potential_actors"]:
                print(f"  - {actor['name']} (Match Score: {actor['match_score']:.2f})")
                print(f"    Aliases: {', '.join(actor['aliases'])}")
                print(f"    Matches: {', '.join(actor['matches'])}")
                print(f"    Description: {actor['description']}")
        else:
            print("  No potential actors identified")
        
        graph = build_knowledge_graph(sample, attribution_result)
        
        graph_data = {
            "nodes": [{"id": n, **graph.nodes[n]} for n in graph.nodes()],
            "edges": [{"source": u, "target": v, **graph.edges[u, v]} for u, v in graph.edges()]
        }
        
        graph_file = output_dir / f"graph_{sample_name}_{timestamp}.json"
        with open(graph_file, "w") as f:
            json.dump(graph_data, f, indent=2)
        
        print(f"\nKnowledge Graph:")
        print(f"  - Nodes: {len(graph_data['nodes'])}")
        print(f"  - Edges: {len(graph_data['edges'])}")
        print(f"  - Graph saved to: {graph_file}")
        
        report_data = {
            "malware_info": {
                "name": sample["name"],
                "sha256": sample["sha256"],
                "type": sample["type"],
                "description": sample["description"]
            },
            "attribution": attribution_result,
            "graph_path": str(graph_file)
        }
        
        report_file = output_dir / f"report_{sample_name}_{timestamp}.html"
        generate_report(report_data, str(report_file))
        
        print(f"\nReport:")
        print(f"  - Report saved to: {report_file}")
        
        results[sample_name] = {
            "attribution": attribution_result,
            "graph_file": str(graph_file),
            "report_file": str(report_file)
        }
    
    print(f"\n{'='*80}")
    print("ATTRIBUTION TEST SUMMARY")
    print(f"{'='*80}")
    
    print("\nTest Results:")
    for sample_name, result in results.items():
        print(f"\n{sample_name}:")
        if result["attribution"]["potential_actors"]:
            for actor in result["attribution"]["potential_actors"]:
                print(f"  - {actor['name']} (Match Score: {actor['match_score']:.2f})")
                print(f"    Matches: {', '.join(actor['matches'])}")
        else:
            print("  No potential actors identified")
    
    return results

def attribute_sample(sample, actor_profiles):
    """Attribute sample to potential threat actors."""
    potential_actors = []
    
    sample_country_code = None
    sample_tools = []
    sample_techniques = sample.get("techniques", [])
    
    for network in sample.get("network", []):
        if "country_code" in network:
            sample_country_code = network["country_code"]
            break
    
    for tool in sample.get("tools", []):
        if "name" in tool:
            sample_tools.append(tool["name"])
    
    for actor_id, profile in actor_profiles.items():
        match_score = 0.0
        matches = []
        
        actor_country = profile.get("attribution", {}).get("country")
        if actor_country and actor_country == sample_country_code:
            match_score += 0.3
            matches.append(f"country:{actor_country}")
        
        actor_tools = profile.get("tools", [])
        tool_matches = [tool for tool in sample_tools if tool in actor_tools]
        if tool_matches:
            tool_match_score = 0.3 * (len(tool_matches) / len(actor_tools))
            match_score += tool_match_score
            for tool in tool_matches:
                matches.append(f"tool:{tool}")
        
        actor_techniques = profile.get("techniques", [])
        technique_matches = [tech for tech in sample_techniques if tech in actor_techniques]
        if technique_matches:
            technique_match_score = 0.4 * (len(technique_matches) / len(actor_techniques))
            match_score += technique_match_score
            for technique in technique_matches:
                matches.append(f"technique:{technique}")
        
        if match_score > 0.2:
            potential_actors.append({
                "actor_id": actor_id,
                "name": profile.get("name", "Unknown"),
                "aliases": profile.get("aliases", []),
                "match_score": match_score,
                "matches": matches,
                "description": profile.get("description", "")
            })
    
    potential_actors.sort(key=lambda x: x["match_score"], reverse=True)
    
    attribution_result = {
        "timestamp": datetime.now().isoformat(),
        "attribution_id": f"attr_{int(datetime.now().timestamp())}",
        "confidence_score": potential_actors[0]["match_score"] if potential_actors else 0.0,
        "potential_actors": potential_actors,
        "overall_assessment": generate_assessment(potential_actors)
    }
    
    return attribution_result

def generate_assessment(potential_actors):
    """Generate overall assessment based on potential actors."""
    if not potential_actors:
        return "LOW CONFIDENCE ATTRIBUTION: No known threat actors could be confidently matched to this attack."
    
    top_actor = potential_actors[0]
    match_score = top_actor["match_score"]
    
    if match_score > 0.7:
        confidence = "HIGH"
    elif match_score > 0.4:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    
    return f"{confidence} CONFIDENCE ATTRIBUTION: This attack is attributed to {top_actor['name']} with {confidence.lower()} confidence. The attack techniques, tools, and infrastructure are consistent with known {top_actor['name']} operations."

def build_knowledge_graph(sample, attribution_result):
    """Build knowledge graph from sample data and attribution result."""
    graph = nx.DiGraph()
    
    malware_id = f"malware_{sample['name'].lower().replace(' ', '_').replace('.', '_')}"
    graph.add_node(malware_id, 
                  label=sample["name"],
                  type="malware",
                  malware_type=sample["type"],
                  description=sample["description"])
    
    for technique in sample.get("techniques", []):
        technique_id = f"technique_{technique}"
        graph.add_node(technique_id,
                      label=technique,
                      type="technique",
                      description=f"MITRE ATT&CK Technique: {technique}")
        
        graph.add_edge(malware_id, technique_id,
                      label="uses",
                      type="technique_use")
    
    for tool in sample.get("tools", []):
        tool_id = f"tool_{tool['name'].lower().replace(' ', '_')}"
        graph.add_node(tool_id,
                      label=tool["name"],
                      type="tool",
                      confidence=tool.get("confidence", 0.0))
        
        graph.add_edge(malware_id, tool_id,
                      label="uses",
                      type="tool_use")
    
    for network in sample.get("network", []):
        if "ip" in network:
            network_id = f"network_{network['ip'].replace('.', '_')}"
            graph.add_node(network_id,
                          label=network["ip"],
                          type="network",
                          country=network.get("country", "Unknown"),
                          country_code=network.get("country_code", ""))
            
            graph.add_edge(malware_id, network_id,
                          label="connects to",
                          type="network_connection")
    
    if attribution_result.get("potential_actors"):
        for actor in attribution_result["potential_actors"]:
            actor_id = f"actor_{actor['name'].lower().replace(' ', '_')}"
            graph.add_node(actor_id,
                          label=actor["name"],
                          type="actor",
                          confidence=actor["match_score"],
                          description=actor["description"])
            
            graph.add_edge(actor_id, malware_id,
                          label="attributed to",
                          type="attribution",
                          confidence=actor["match_score"])
            
            for match in actor.get("matches", []):
                if match.startswith("technique:"):
                    technique = match.split(":")[1]
                    technique_id = f"technique_{technique}"
                    if technique_id in graph:
                        graph.add_edge(actor_id, technique_id,
                                      label="uses",
                                      type="attribution")
                elif match.startswith("tool:"):
                    tool = match.split(":")[1]
                    tool_id = f"tool_{tool.lower().replace(' ', '_')}"
                    if tool_id in graph:
                        graph.add_edge(actor_id, tool_id,
                                      label="uses",
                                      type="attribution")
    
    return graph

def generate_report(data, output_file):
    """Generate a simple HTML report."""
    malware_info = data.get("malware_info", {})
    attribution = data.get("attribution", {})
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Attribution Report - {malware_info.get('name', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .section {{ margin-bottom: 20px; }}
        .actor {{ background-color: #f0f0f0; padding: 10px; margin-bottom: 10px; border-radius: 5px; }}
        .confidence {{ font-weight: bold; }}
        .matches {{ margin-left: 20px; }}
        .assessment {{ background-color: #e6f7ff; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Attribution Report</h1>
    <div class="section">
        <h2>Malware Information</h2>
        <p><strong>Name:</strong> {malware_info.get('name', 'Unknown')}</p>
        <p><strong>SHA256:</strong> {malware_info.get('sha256', 'Unknown')}</p>
        <p><strong>Type:</strong> {malware_info.get('type', 'Unknown')}</p>
        <p><strong>Description:</strong> {malware_info.get('description', 'No description available.')}</p>
    </div>
    
    <div class="section">
        <h2>Attribution Analysis</h2>
        <p><strong>Confidence Score:</strong> {attribution.get('confidence_score', 0) * 100:.0f}%</p>
        
        <h3>Potential Threat Actors</h3>
        {''.join([f'''
        <div class="actor">
            <h4>{actor.get('name', 'Unknown Actor')}</h4>
            <p><strong>Aliases:</strong> {', '.join(actor.get('aliases', []))}</p>
            <p class="confidence"><strong>Match Score:</strong> {actor.get('match_score', 0) * 100:.0f}%</p>
            <p><strong>Matches:</strong></p>
            <ul class="matches">
                {''.join([f'<li>{match}</li>' for match in actor.get('matches', [])])}
            </ul>
            <p><strong>Description:</strong> {actor.get('description', 'No description available.')}</p>
        </div>
        ''' for actor in attribution.get('potential_actors', [])])}
    </div>
    
    <div class="section assessment">
        <h2>Overall Assessment</h2>
        <p>{attribution.get('overall_assessment', 'No assessment available.')}</p>
    </div>
    
    <div class="section">
        <h2>Knowledge Graph</h2>
        <p>Knowledge graph data is available at: {data.get('graph_path', 'Unknown')}</p>
    </div>
</body>
</html>
"""
    
    with open(output_file, "w") as f:
        f.write(html)
    
    return output_file

if __name__ == "__main__":
    run_attribution_analysis()
