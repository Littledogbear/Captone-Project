import numpy as np
from typing import List, Dict, Any
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import logging

class PatternDetector:
    """Real-time pattern detection system using sliding windows and clustering."""
    
    def __init__(self, window_size: int = 300, pattern_threshold: float = 0.7):
        self.window_size = window_size
        self.pattern_threshold = pattern_threshold
        self.logger = logging.getLogger(__name__)
        self.scaler = StandardScaler()
        self.clusterer = DBSCAN(eps=0.3, min_samples=3)
        
    def detect_patterns(self, trace_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect patterns in the trace history using sliding window analysis."""
        if not trace_history:
            return {"patterns": [], "anomalies": []}
            
        try:
            # Extract features from traces
            features = self._extract_features(trace_history)
            
            # Normalize features
            if features.size > 0:
                features_scaled = self.scaler.fit_transform(features)
                
                # Detect clusters (patterns)
                clusters = self.clusterer.fit_predict(features_scaled)
                
                # Analyze patterns
                patterns = self._analyze_patterns(trace_history, clusters)
                
                # Detect temporal anomalies
                anomalies = self._detect_temporal_anomalies(trace_history)
                
                return {
                    "patterns": patterns,
                    "anomalies": anomalies,
                    "timestamp": datetime.now().isoformat()
                }
            
        except Exception as e:
            self.logger.error(f"Error in pattern detection: {str(e)}")
            
        return {"patterns": [], "anomalies": []}
        
    def _extract_features(self, trace_history: List[Dict[str, Any]]) -> np.ndarray:
        """Extract numerical features from trace history."""
        features = []
        
        for trace in trace_history:
            trace_features = [
                len(trace['processes']),
                len(trace['network_connections']),
                trace['system_resources']['cpu_percent'],
                trace['system_resources']['memory']['percent']
            ]
            features.append(trace_features)
            
        return np.array(features)
        
    def _analyze_patterns(self, trace_history: List[Dict[str, Any]], 
                        clusters: np.ndarray) -> List[Dict[str, Any]]:
        """Analyze detected clusters to identify significant patterns."""
        patterns = []
        unique_clusters = np.unique(clusters)
        
        for cluster_id in unique_clusters:
            if cluster_id != -1:  # Skip noise points
                cluster_traces = [trace_history[i] for i in range(len(clusters)) 
                                if clusters[i] == cluster_id]
                
                pattern = {
                    "cluster_id": int(cluster_id),
                    "size": len(cluster_traces),
                    "start_time": cluster_traces[0]['timestamp'],
                    "end_time": cluster_traces[-1]['timestamp'],
                    "avg_cpu": np.mean([t['system_resources']['cpu_percent'] 
                                      for t in cluster_traces]),
                    "avg_memory": np.mean([t['system_resources']['memory']['percent'] 
                                         for t in cluster_traces])
                }
                patterns.append(pattern)
                
        return patterns
        
    def _detect_temporal_anomalies(self, trace_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect temporal anomalies in system behavior."""
        anomalies = []
        
        if len(trace_history) < 2:
            return anomalies
            
        # Calculate first-order differences
        cpu_values = [t['system_resources']['cpu_percent'] for t in trace_history]
        memory_values = [t['system_resources']['memory']['percent'] for t in trace_history]
        
        cpu_diff = np.diff(cpu_values)
        memory_diff = np.diff(memory_values)
        
        # Detect sudden changes
        cpu_threshold = np.std(cpu_diff) * 2
        memory_threshold = np.std(memory_diff) * 2
        
        for i in range(len(cpu_diff)):
            if abs(cpu_diff[i]) > cpu_threshold or abs(memory_diff[i]) > memory_threshold:
                anomaly = {
                    "timestamp": trace_history[i+1]['timestamp'],
                    "type": "sudden_change",
                    "metrics": {
                        "cpu_change": float(cpu_diff[i]),
                        "memory_change": float(memory_diff[i])
                    }
                }
                anomalies.append(anomaly)
                
        return anomalies
