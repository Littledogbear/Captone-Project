import logging
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from datetime import datetime
import networkx as nx

from .geolocation import IPGeolocation
from .tool_fingerprinting import ToolFingerprinting

class AttributionEngine:
    """Engine for attributing cyber attacks to their origins."""
    
    def __init__(self, 
                 attribution_db_path: str = "data/attribution/attribution_db.json",
                 actor_profiles_path: str = "data/attribution/actor_profiles.json"):
        self.logger = logging.getLogger(__name__)
        self.attribution_db_path = attribution_db_path
        self.actor_profiles_path = actor_profiles_path
        self.attribution_db = {}
        self.actor_profiles = {}
        
        # Initialize components
        self.geolocation = IPGeolocation()
        self.tool_fingerprinting = ToolFingerprinting()
        
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(self.attribution_db_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.actor_profiles_path), exist_ok=True)
        
        # Load databases
        self._load_attribution_db()
        self._load_actor_profiles()
        
    def _load_attribution_db(self):
        """Load attribution database."""
        try:
            if os.path.exists(self.attribution_db_path):
                with open(self.attribution_db_path, "r") as f:
                    self.attribution_db = json.load(f)
                self.logger.info(f"Loaded attribution database with {len(self.attribution_db)} entries")
            else:
                self.logger.info("Attribution database not found, creating empty database")
                self.attribution_db = {}
                self._save_attribution_db()
        except Exception as e:
            self.logger.error(f"Error loading attribution database: {str(e)}")
            self.attribution_db = {}
            
    def _save_attribution_db(self):
        """Save attribution database."""
        try:
            with open(self.attribution_db_path, "w") as f:
                json.dump(self.attribution_db, f, indent=2)
            self.logger.info(f"Saved attribution database with {len(self.attribution_db)} entries")
        except Exception as e:
            self.logger.error(f"Error saving attribution database: {str(e)}")
            
    def _load_actor_profiles(self):
        """Load threat actor profiles."""
        try:
            if os.path.exists(self.actor_profiles_path):
                with open(self.actor_profiles_path, "r") as f:
                    self.actor_profiles = json.load(f)
                self.logger.info(f"Loaded {len(self.actor_profiles)} actor profiles")
            else:
                self.logger.info("Actor profiles not found, creating default profiles")
                self._create_default_actor_profiles()
        except Exception as e:
            self.logger.error(f"Error loading actor profiles: {str(e)}")
            self._create_default_actor_profiles()
            
    def _save_actor_profiles(self):
        """Save threat actor profiles."""
        try:
            with open(self.actor_profiles_path, "w") as f:
                json.dump(self.actor_profiles, f, indent=2)
            self.logger.info(f"Saved {len(self.actor_profiles)} actor profiles")
        except Exception as e:
            self.logger.error(f"Error saving actor profiles: {str(e)}")
            
    def _create_default_actor_profiles(self):
        """Create default threat actor profiles."""
        self.actor_profiles = {
            "APT28": {
                "name": "APT28",
                "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm"],
                "description": "Russian state-sponsored threat actor",
                "motivation": ["espionage", "information theft"],
                "attribution": {
                    "country": "RU",
                    "type": "state-sponsored",
                    "confidence": "high"
                },
                "tools": ["X-Tunnel", "X-Agent", "Lojack", "Zebrocy"],
                "techniques": ["T1566", "T1190", "T1133", "T1078"],
                "targets": ["government", "military", "political organizations"],
                "first_seen": "2004",
                "active": True
            },
            "APT29": {
                "name": "APT29",
                "aliases": ["Cozy Bear", "The Dukes", "CozyDuke"],
                "description": "Russian state-sponsored threat actor",
                "motivation": ["espionage", "information theft"],
                "attribution": {
                    "country": "RU",
                    "type": "state-sponsored",
                    "confidence": "high"
                },
                "tools": ["MiniDuke", "CosmicDuke", "OnionDuke", "SUNBURST"],
                "techniques": ["T1566", "T1195", "T1078", "T1105"],
                "targets": ["government", "think tanks", "healthcare"],
                "first_seen": "2008",
                "active": True
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "aliases": ["Hidden Cobra", "Guardians of Peace", "APT38"],
                "description": "North Korean state-sponsored threat actor",
                "motivation": ["financial gain", "espionage", "sabotage"],
                "attribution": {
                    "country": "KP",
                    "type": "state-sponsored",
                    "confidence": "high"
                },
                "tools": ["HOPLIGHT", "ELECTRICFISH", "BADCALL", "FALLCHILL"],
                "techniques": ["T1566", "T1133", "T1486", "T1570"],
                "targets": ["financial institutions", "cryptocurrency exchanges", "entertainment"],
                "first_seen": "2009",
                "active": True
            },
            "APT41": {
                "name": "APT41",
                "aliases": ["Double Dragon", "Wicked Panda", "Barium"],
                "description": "Chinese state-sponsored threat actor with financial motives",
                "motivation": ["espionage", "financial gain"],
                "attribution": {
                    "country": "CN",
                    "type": "state-sponsored",
                    "confidence": "high"
                },
                "tools": ["Poison Ivy", "PlugX", "Winnti", "ShadowPad"],
                "techniques": ["T1190", "T1133", "T1059", "T1105"],
                "targets": ["healthcare", "telecommunications", "video games"],
                "first_seen": "2012",
                "active": True
            }
        }
        self._save_actor_profiles()
        
    def add_actor_profile(self, actor_id: str, profile: Dict[str, Any]) -> bool:
        """Add a new threat actor profile."""
        try:
            self.actor_profiles[actor_id] = profile
            self._save_actor_profiles()
            self.logger.info(f"Added profile for actor {actor_id}")
            return True
        except Exception as e:
            self.logger.error(f"Error adding profile for actor {actor_id}: {str(e)}")
            return False
            
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
        
    def _generate_assessment(self, attribution_result: Dict[str, Any]) -> str:
        """Generate an overall assessment of the attribution."""
        assessment = []
        
        # Add confidence level description
        confidence_score = attribution_result.get("confidence_score", 0.0)
        if confidence_score >= 0.8:
            assessment.append("HIGH CONFIDENCE ATTRIBUTION: ")
        elif confidence_score >= 0.5:
            assessment.append("MEDIUM CONFIDENCE ATTRIBUTION: ")
        else:
            assessment.append("LOW CONFIDENCE ATTRIBUTION: ")
            
        # Add potential actor information
        potential_actors = attribution_result.get("potential_actors", [])
        if potential_actors:
            top_actor = potential_actors[0]
            actor_name = top_actor.get("name")
            actor_country = top_actor.get("attribution", {}).get("country", "Unknown")
            
            assessment.append(f"This attack is likely attributed to {actor_name} ")
            assessment.append(f"(country: {actor_country}) ")
            assessment.append(f"with a match score of {top_actor.get('match_score', 0):.2f}. ")
            
            # Add match details
            matches = top_actor.get("matches", [])
            if matches:
                assessment.append("Evidence includes: ")
                assessment.append(", ".join(matches))
                assessment.append(". ")
        else:
            assessment.append("No known threat actors could be confidently matched to this attack. ")
            
        # Add geolocation information
        geo_data = attribution_result.get("geolocation_data", [])
        if geo_data:
            countries = {}
            for geo in geo_data:
                country = geo.get("country")
                if country != "Unknown" and country != "Private":
                    countries[country] = countries.get(country, 0) + 1
                    
            if countries:
                most_common_country = max(countries.items(), key=lambda x: x[1])
                assessment.append(f"The majority of connections ({most_common_country[1]}) ")
                assessment.append(f"originated from {most_common_country[0]}. ")
                
        # Add tool information
        tools = attribution_result.get("identified_tools", [])
        if tools:
            tool_names = set(tool.get("name") for tool in tools)
            assessment.append(f"Identified tools include: {', '.join(tool_names)}. ")
            
            # Add skill level assessment
            skill_levels = []
            for tool in tools:
                skill_level = tool.get("attribution", {}).get("skill_level")
                if skill_level:
                    skill_levels.append(skill_level)
                    
            if skill_levels:
                # Determine the highest skill level
                if "high" in "".join(skill_levels).lower():
                    assessment.append("The attack demonstrates a HIGH level of sophistication. ")
                elif "medium" in "".join(skill_levels).lower():
                    assessment.append("The attack demonstrates a MEDIUM level of sophistication. ")
                else:
                    assessment.append("The attack demonstrates a BASIC level of sophistication. ")
                    
        # Add technique information
        techniques = attribution_result.get("techniques", [])
        if techniques:
            assessment.append(f"The attack utilized {len(techniques)} distinct techniques. ")
            
        # Add recommendations
        assessment.append("RECOMMENDATIONS: ")
        if confidence_score >= 0.5 and potential_actors:
            assessment.append("Review threat intelligence reports for the identified actor. ")
            assessment.append("Implement specific countermeasures for their known TTPs. ")
        else:
            assessment.append("Implement general security controls based on the identified techniques. ")
            assessment.append("Continue monitoring for additional evidence to improve attribution confidence.")
            
        return "".join(assessment)
        
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
