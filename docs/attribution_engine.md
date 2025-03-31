# Attribution Engine Documentation

## Overview
The Attribution Engine in the Cyber Attack Tracer system uses AI analysis results to identify potential threat actors, match detected techniques to known threat actor profiles, calculate confidence scores for attribution, and provide historical context for similar attacks.

## Core Components

### 1. Attribution Engine
Located in `src/attribution/attribution_engine.py`, this component:
- Uses AI analysis results to identify potential threat actors
- Matches detected techniques to known threat actor profiles
- Calculates confidence scores for attribution
- Provides historical context for similar attacks

Key methods:
```python
def attribute_attack(self, traces: Dict[str, Any], knowledge_graph: Optional[nx.DiGraph] = None) -> Dict[str, Any]:
    """Attribute an attack based on traces and knowledge graph."""
    attribution_result = {
        "timestamp": datetime.now().isoformat(),
        "attribution_id": f"attr_{int(datetime.now().timestamp())}",
        "confidence_score": 0.0,
        "potential_actors": [],
        "geolocation_data": [],
        "identified_tools": [],
        "techniques": [],
        "overall_assessment": ""
    }
    
    # Extract network connections
    network_connections = traces.get("network_connections", [])
    
    # Extract processes
    processes = traces.get("processes", [])
    
    # Get geolocation data for remote IPs
    for connection in network_connections:
        remote_ip = connection.get("remote_address", {}).get("ip")
        if remote_ip:
            geo_data = self.geolocation.get_geolocation(remote_ip)
            if not geo_data.get("is_private", False):
                attribution_result["geolocation_data"].append(geo_data)
                
    # Identify tools from processes and network connections
    process_tools = self.tool_fingerprinting.identify_tools_from_processes(processes)
    network_tools = self.tool_fingerprinting.identify_tools_from_network(network_connections)
    
    attribution_result["identified_tools"] = process_tools + network_tools
    
    # Extract techniques from knowledge graph if available
    if knowledge_graph:
        # This would be implemented to extract techniques from the knowledge graph
        # For now, we'll use techniques from the traces if available
        attribution_result["techniques"] = traces.get("techniques", [])
        
    # Match against actor profiles
    potential_actors = self._match_actor_profiles(
        attribution_result["geolocation_data"],
        attribution_result["identified_tools"],
        attribution_result["techniques"]
    )
    
    attribution_result["potential_actors"] = potential_actors
    
    # Calculate overall confidence score
    attribution_result["confidence_score"] = self._calculate_confidence_score(
        attribution_result["geolocation_data"],
        attribution_result["identified_tools"],
        attribution_result["techniques"],
        potential_actors
    )
    
    # Generate overall assessment
    attribution_result["overall_assessment"] = self._generate_assessment(attribution_result)
    
    # Save attribution result to database
    self.attribution_db[attribution_result["attribution_id"]] = attribution_result
    self._save_attribution_db()
    
    return attribution_result
```

### 2. Actor Profile Matching
The engine matches attack data against known actor profiles:
- Extracts countries from geolocation data
- Identifies tools from processes and network connections
- Matches techniques to actor profiles
- Calculates match scores for potential actors

Key methods:
```python
def _match_actor_profiles(self, 
                         geolocation_data: List[Dict[str, Any]], 
                         identified_tools: List[Dict[str, Any]], 
                         techniques: List[str]) -> List[Dict[str, Any]]:
    """Match attack data against known actor profiles."""
    potential_actors = []
    
    # Extract countries from geolocation data
    countries = set()
    for geo in geolocation_data:
        if "country_code" in geo and geo["country_code"] != "XX" and not geo.get("is_private", False):
            countries.add(geo["country_code"])
            
    # Extract tools
    tools = set()
    for tool in identified_tools:
        tools.add(tool.get("name"))
        
    # Match against actor profiles
    for actor_id, profile in self.actor_profiles.items():
        match_score = 0.0
        matches = []
        
        # Check country attribution
        actor_country = profile.get("attribution", {}).get("country")
        if actor_country and actor_country in countries:
            match_score += 0.3
            matches.append(f"Country match: {actor_country}")
            
        # Check tools
        actor_tools = set(profile.get("tools", []))
        tool_matches = tools.intersection(actor_tools)
        if tool_matches:
            match_score += 0.3 * (len(tool_matches) / len(actor_tools))
            matches.append(f"Tool matches: {', '.join(tool_matches)}")
            
        # Check techniques
        actor_techniques = set(profile.get("techniques", []))
        technique_matches = set(techniques).intersection(actor_techniques)
        if technique_matches:
            match_score += 0.4 * (len(technique_matches) / len(actor_techniques))
            matches.append(f"Technique matches: {', '.join(technique_matches)}")
            
        # Add to potential actors if score is above threshold
        if match_score > 0.2:
            potential_actors.append({
                "actor_id": actor_id,
                "name": profile.get("name"),
                "aliases": profile.get("aliases", []),
                "attribution": profile.get("attribution", {}),
                "match_score": match_score,
                "matches": matches
            })
            
    # Sort by match score
    potential_actors.sort(key=lambda x: x["match_score"], reverse=True)
    
    return potential_actors
```

### 3. Confidence Score Calculation
The engine calculates overall confidence scores for attribution:
- Base confidence
- Geolocation confidence
- Tool confidence
- Technique confidence
- Actor match confidence

Key methods:
```python
def _calculate_confidence_score(self, 
                               geolocation_data: List[Dict[str, Any]], 
                               identified_tools: List[Dict[str, Any]], 
                               techniques: List[str],
                               potential_actors: List[Dict[str, Any]]) -> float:
    """Calculate overall confidence score for attribution."""
    # Base confidence
    confidence = 0.0
    
    # Geolocation confidence (max 0.3)
    if geolocation_data:
        # More unique non-private IPs from same country increases confidence
        countries = {}
        for geo in geolocation_data:
            if not geo.get("is_private", False) and geo.get("country_code") != "XX":
                country = geo.get("country_code")
                countries[country] = countries.get(country, 0) + 1
                
        if countries:
            # Get the most common country
            most_common_country = max(countries.items(), key=lambda x: x[1])
            country_ratio = most_common_country[1] / len(geolocation_data)
            confidence += 0.3 * country_ratio
            
    # Tool confidence (max 0.3)
    if identified_tools:
        # More identified tools increases confidence
        tool_confidence = min(len(identified_tools) * 0.1, 0.3)
        confidence += tool_confidence
        
    # Technique confidence (max 0.2)
    if techniques:
        # More identified techniques increases confidence
        technique_confidence = min(len(techniques) * 0.05, 0.2)
        confidence += technique_confidence
        
    # Actor match confidence (max 0.2)
    if potential_actors:
        # Higher match score for top actor increases confidence
        top_actor_score = potential_actors[0]["match_score"]
        confidence += 0.2 * top_actor_score
        
    return min(confidence, 1.0)
```

### 4. Historical Context
The engine provides historical context for similar attacks:
- Stores attribution results in a database
- Retrieves recent attribution history
- Retrieves attribution results by ID

Key methods:
```python
def get_attribution_history(self, limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent attribution history."""
    try:
        # Sort by timestamp (descending)
        sorted_attributions = sorted(
            self.attribution_db.values(),
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
        
        # Return limited number of results
        return sorted_attributions[:limit]
    except Exception as e:
        self.logger.error(f"Error getting attribution history: {str(e)}")
        return []
        
def get_attribution_by_id(self, attribution_id: str) -> Optional[Dict[str, Any]]:
    """Get attribution result by ID."""
    return self.attribution_db.get(attribution_id)
```

## Integration Points

1. **With AI Trace Analyzer**
   - Uses AI analysis results for threat actor attribution
   - Matches detected techniques to known threat actor profiles
   - Calculates confidence scores for attribution

2. **With Knowledge Graph**
   - Extracts techniques from knowledge graph if available
   - Provides historical context for similar attacks

3. **With Reporting System**
   - Integrates attribution results into reports
   - Generates overall assessment of attribution
   - Provides historical context for similar attacks

## Error Handling

The attribution engine implements robust error handling:
- Graceful degradation of functionality
- Detailed error logging for debugging
- Default attribution results when matching fails

## Performance Considerations

The system is optimized for CPU-only operation:
- Efficient text processing
- Minimal memory footprint
- Background thread initialization

## Security Features

The attribution engine implements several security measures:
- No external API dependencies
- Local-only model execution
- Sanitized input processing
- Secure output handling

## Testing

The attribution engine can be tested using:
```python
python test_comprehensive_system_with_specific_samples.py
```

This will:
- Test AI analysis with specific malware samples
- Verify integration with other components
- Generate test reports and visualizations
- Validate confidence score calculations
