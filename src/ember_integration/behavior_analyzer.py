import logging
from typing import Dict, Any, List, Set, Tuple, Optional
import numpy as np
from datetime import datetime
import json
import os

class BehaviorAnalyzer:
    """Analyzes malware behavior patterns and identifies similarities between samples."""
    
    def __init__(self, db_path: str = ""):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or os.path.join(os.path.expanduser("~"), "cyber_attack_tracer", "data", "behavior_db")
        self.behavior_db = {}
        
        os.makedirs(self.db_path, exist_ok=True)
        
        self._load_database()
        
    def _load_database(self):
        """Load behavior database from disk."""
        db_file = os.path.join(self.db_path, "behavior_db.json")
        if os.path.exists(db_file):
            try:
                with open(db_file, "r") as f:
                    self.behavior_db = json.load(f)
                self.logger.info(f"Loaded behavior database with {len(self.behavior_db)} entries")
            except Exception as e:
                self.logger.error(f"Error loading behavior database: {str(e)}")
                self.behavior_db = {}
                
    def _save_database(self):
        """Save behavior database to disk."""
        db_file = os.path.join(self.db_path, "behavior_db.json")
        try:
            with open(db_file, "w") as f:
                json.dump(self.behavior_db, f, indent=2)
            self.logger.info(f"Saved behavior database with {len(self.behavior_db)} entries")
        except Exception as e:
            self.logger.error(f"Error saving behavior database: {str(e)}")
            
    def add_behavior(self, sample_id: str, behavior_data: Dict[str, Any]):
        """Add behavior data for a malware sample."""
        self.behavior_db[sample_id] = {
            "behavior": behavior_data,
            "added_timestamp": datetime.now().isoformat()
        }
        self._save_database()
        
    def find_similar_behaviors(self, behavior_data: Dict[str, Any], threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Find samples with similar behavior patterns."""
        if not self.behavior_db:
            return []
            
        similarities = []
        for sample_id, sample_data in self.behavior_db.items():
            similarity = self.calculate_behavior_similarity(behavior_data, sample_data["behavior"])
            if similarity >= threshold:
                similarities.append({
                    "sample_id": sample_id,
                    "similarity": similarity,
                    "timestamp": sample_data["added_timestamp"]
                })
                
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        return similarities
        
    def calculate_behavior_similarity(self, behavior1: Dict[str, Any], behavior2: Dict[str, Any]) -> float:
        """Calculate similarity between two behavior patterns."""
        if not behavior1 or not behavior2:
            return 0.0
            
        aspects = [
            "file_operations",
            "registry_operations",
            "network_operations",
            "process_operations",
            "common_processes",
            "common_files",
            "common_registry",
            "common_domains",
            "common_ports"
        ]
        
        aspect_scores = []
        for aspect in aspects:
            if aspect in behavior1 and aspect in behavior2:
                score = self._calculate_list_similarity(behavior1[aspect], behavior2[aspect])
                aspect_scores.append(score)
                
        bool_props = ["high_cpu_usage", "keylogging", "screenshot"]
        for prop in bool_props:
            if prop in behavior1 and prop in behavior2:
                score = 1.0 if behavior1[prop] == behavior2[prop] else 0.0
                aspect_scores.append(score)
                
        if aspect_scores:
            return sum(aspect_scores) / len(aspect_scores)
        return 0.0
        
    def _calculate_list_similarity(self, list1: List[Any], list2: List[Any]) -> float:
        """Calculate Jaccard similarity between two lists."""
        if not list1 or not list2:
            return 0.0
            
        set1 = set(list1)
        set2 = set(list2)
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        if union == 0:
            return 0.0
            
        return intersection / union
        
    def match_behavior_pattern(self, behavior_data: Dict[str, Any], patterns: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Match behavior data against known behavior patterns."""
        if not behavior_data or not patterns:
            return None
            
        matches = []
        for pattern_name, pattern in patterns.items():
            similarity = self.calculate_behavior_similarity(behavior_data, pattern)
            if similarity > 0.5:  # Threshold for pattern matching
                matches.append({
                    "pattern": pattern_name,
                    "similarity": similarity
                })
                
        if not matches:
            return None
            
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        
        return {
            "best_match": matches[0]["pattern"],
            "similarity": matches[0]["similarity"],
            "all_matches": matches
        }
        
    def analyze_behavior_trends(self, time_window_days: int = 30) -> Dict[str, Any]:
        """Analyze trends in behavior patterns over time."""
        if not self.behavior_db:
            return {"trends": [], "total_samples": 0}
            
        now = datetime.now()
        
        recent_samples = {}
        for sample_id, sample_data in self.behavior_db.items():
            try:
                sample_time = datetime.fromisoformat(sample_data["added_timestamp"])
                days_diff = (now - sample_time).days
                if days_diff <= time_window_days:
                    recent_samples[sample_id] = sample_data
            except (ValueError, TypeError):
                self.logger.warning(f"Invalid timestamp for sample {sample_id}")
                
        pattern_counts = {}
        for sample_id, sample_data in recent_samples.items():
            behavior = sample_data["behavior"]
            
            for op in behavior.get("file_operations", []):
                key = f"file_operation:{op}"
                pattern_counts[key] = pattern_counts.get(key, 0) + 1
                
            for op in behavior.get("network_operations", []):
                key = f"network_operation:{op}"
                pattern_counts[key] = pattern_counts.get(key, 0) + 1
                
            for op in behavior.get("process_operations", []):
                key = f"process_operation:{op}"
                pattern_counts[key] = pattern_counts.get(key, 0) + 1
                
            for op in behavior.get("registry_operations", []):
                key = f"registry_operation:{op}"
                pattern_counts[key] = pattern_counts.get(key, 0) + 1
                
        total_samples = len(recent_samples)
        trends = []
        
        for pattern, count in pattern_counts.items():
            percentage = (count / total_samples) * 100 if total_samples > 0 else 0
            trends.append({
                "pattern": pattern,
                "count": count,
                "percentage": percentage
            })
            
        trends.sort(key=lambda x: x["count"], reverse=True)
        
        return {
            "trends": trends,
            "total_samples": total_samples,
            "time_window_days": time_window_days
        }
