from typing import Dict, Any, List
import logging
import numpy as np
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

class TrendAnalyzer:
    """Analyzes trends in attack techniques over time."""
    
    def __init__(self, history_file: str = None):
        self.logger = logging.getLogger(__name__)
        self.history_file = history_file or os.path.join(
            os.path.expanduser("~"), "cyber_attack_tracer", "data", "technique_history.json"
        )
        self.technique_history = self._load_history()
        
    def _load_history(self) -> Dict[str, List[str]]:
        """Load technique history from file."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading technique history: {str(e)}")
                
        return {}
        
    def _save_history(self):
        """Save technique history to file."""
        try:
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, "w") as f:
                json.dump(self.technique_history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving technique history: {str(e)}")
        
    def add_technique_observation(self, technique_id: str, timestamp: str = None):
        """Add a technique observation to the history."""
        if not timestamp:
            timestamp = datetime.now().isoformat()
            
        if technique_id not in self.technique_history:
            self.technique_history[technique_id] = []
            
        self.technique_history[technique_id].append(timestamp)
        self._save_history()
        
    def analyze_trends(self, time_window: int = 30) -> Dict[str, Any]:
        """Analyze trends in attack techniques over the specified time window (days)."""
        try:
            current_time = datetime.now()
            window_start = current_time - timedelta(days=time_window)
            
            trends = {}
            
            for technique_id, timestamps in self.technique_history.items():
                # Filter observations within the time window
                recent_observations = [ts for ts in timestamps 
                                      if datetime.fromisoformat(ts) >= window_start]
                
                # Calculate trend metrics
                total_observations = len(recent_observations)
                
                if total_observations > 0:
                    # Group by week
                    weekly_counts = self._group_by_week(recent_observations, window_start, current_time)
                    
                    # Calculate trend direction
                    trend_direction = self._calculate_trend_direction(weekly_counts)
                    
                    trends[technique_id] = {
                        "total_observations": total_observations,
                        "weekly_counts": weekly_counts,
                        "trend_direction": trend_direction
                    }
                    
            return {
                "time_window": time_window,
                "window_start": window_start.isoformat(),
                "window_end": current_time.isoformat(),
                "technique_trends": trends
            }
        except Exception as e:
            self.logger.error("Error analyzing trends: %s", str(e))
            return {"error": str(e)}
            
    def _group_by_week(self, timestamps: List[str], 
                      window_start: datetime, 
                      window_end: datetime) -> List[int]:
        """Group observations by week."""
        # Calculate number of weeks in the window
        weeks = (window_end - window_start).days // 7 + 1
        
        # Initialize counts
        weekly_counts = [0] * weeks
        
        for ts in timestamps:
            dt = datetime.fromisoformat(ts)
            week_index = (dt - window_start).days // 7
            
            if 0 <= week_index < weeks:
                weekly_counts[week_index] += 1
                
        return weekly_counts
        
    def _calculate_trend_direction(self, weekly_counts: List[int]) -> str:
        """Calculate the trend direction based on weekly counts."""
        if len(weekly_counts) < 2:
            return "stable"
            
        # Calculate slope using simple linear regression
        x = np.arange(len(weekly_counts))
        slope, _ = np.polyfit(x, weekly_counts, 1)
        
        if slope > 0.1:
            return "increasing"
        elif slope < -0.1:
            return "decreasing"
        else:
            return "stable"
            
    def get_top_techniques(self, time_window: int = 30, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the top techniques by frequency in the specified time window."""
        try:
            current_time = datetime.now()
            window_start = current_time - timedelta(days=time_window)
            
            technique_counts = {}
            
            for technique_id, timestamps in self.technique_history.items():
                # Filter observations within the time window
                recent_observations = [ts for ts in timestamps 
                                      if datetime.fromisoformat(ts) >= window_start]
                
                technique_counts[technique_id] = len(recent_observations)
                
            # Sort techniques by count
            sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Get top techniques
            top_techniques = []
            for technique_id, count in sorted_techniques[:limit]:
                top_techniques.append({
                    "technique_id": technique_id,
                    "count": count
                })
                
            return top_techniques
        except Exception as e:
            self.logger.error("Error getting top techniques: %s", str(e))
            return []
            
    def generate_trend_report(self, time_window: int = 30) -> Dict[str, Any]:
        """Generate a comprehensive trend report."""
        try:
            trends = self.analyze_trends(time_window)
            top_techniques = self.get_top_techniques(time_window)
            
            # Calculate overall trend direction
            overall_direction = "stable"
            increasing_count = 0
            decreasing_count = 0
            
            for technique_data in trends.get("technique_trends", {}).values():
                if technique_data.get("trend_direction") == "increasing":
                    increasing_count += 1
                elif technique_data.get("trend_direction") == "decreasing":
                    decreasing_count += 1
                    
            if increasing_count > decreasing_count:
                overall_direction = "increasing"
            elif decreasing_count > increasing_count:
                overall_direction = "decreasing"
                
            return {
                "time_window": time_window,
                "window_start": trends.get("window_start"),
                "window_end": trends.get("window_end"),
                "top_techniques": top_techniques,
                "overall_direction": overall_direction,
                "technique_trends": trends.get("technique_trends", {}),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error("Error generating trend report: %s", str(e))
            return {"error": str(e)}
