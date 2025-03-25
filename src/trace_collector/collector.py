import logging
import psutil
import json
import socket
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from .ai_trace_analyzer import AITraceAnalyzer
from src.analysis_engine.pattern_detector import PatternDetector
from src.utils.platform_detector import PlatformDetector
from .windows_collector import WindowsTraceCollector
from .mac_collector import MacTraceCollector

class TraceCollector:
    """Collects system traces and analyzes them for potential cyber attacks."""
    
    def __init__(self, log_dir: str = "logs", model_path: str = "distilbert-base-uncased",
                 window_size: int = 300, pattern_threshold: float = 0.7):
        self.logger = logging.getLogger(__name__)
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Real-time monitoring parameters
        self.window_size = window_size  # Time window in seconds
        self.pattern_threshold = pattern_threshold
        self.trace_history = []
        self.pattern_cache = {}
        self.last_analysis_time = datetime.now()
        
        # Initialize platform detector and platform-specific collector
        self.platform_detector = PlatformDetector()
        if self.platform_detector.is_windows():
            self.platform_collector = WindowsTraceCollector()
        elif self.platform_detector.is_mac():
            self.platform_collector = MacTraceCollector()
        else:
            self.logger.warning("Unsupported platform, some features may not work properly")
            self.platform_collector = None

        try:
            self.ai_analyzer = AITraceAnalyzer(model_path=model_path)
            self.pattern_detector = PatternDetector(
                window_size=window_size,
                pattern_threshold=pattern_threshold
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize analyzers: {str(e)}")
            self.ai_analyzer = None
            self.pattern_detector = None

    def collect_system_traces(self) -> Dict[str, Any]:
        """Collect and analyze system traces using AI-based real-time pattern detection."""
        current_time = datetime.now()

        # Collect raw traces using platform-specific collector if available
        if self.platform_collector:
            processes = self.platform_collector.collect_processes()
            network_connections = self.platform_collector.collect_network_connections()
            file_system_events = self.platform_collector.collect_file_system_events()
            registry_events = self.platform_collector.collect_registry_events()
            system_resources = self.platform_collector.collect_system_resources()
            
            traces = {
                'timestamp': current_time.isoformat(),
                'processes': processes.get('processes', []),
                'network_connections': network_connections.get('network_connections', []),
                'file_system_events': file_system_events.get('file_system_events', []),
                'registry_events': registry_events.get('registry_events', []),
                'system_resources': system_resources.get('system_resources', {})
            }
        else:
            # Fallback to generic collection methods
            traces = {
                'timestamp': current_time.isoformat(),
                'processes': self._get_process_info(),
                'network_connections': self._get_network_connections(),
                'system_resources': self._get_system_resources(),
                'file_system_events': [],
                'registry_events': []
            }

        # Generate CPU usage graph
        self._generate_cpu_usage_graph(traces['processes'])

        # Add to trace history and maintain window
        self.trace_history.append(traces)
        self._maintain_trace_window(current_time)

        # Detect patterns in real-time
        if self.pattern_detector:
            try:
                patterns = self.pattern_detector.detect_patterns(self.trace_history)
                traces['patterns'] = patterns
            except Exception as e:
                self.logger.error(f"Pattern detection failed: {str(e)}")
                traces['patterns'] = {"patterns": [], "anomalies": []}

        # Analyze traces using AI if available
        if self.ai_analyzer:
            try:
                analysis_results = self.ai_analyzer.analyze_system_traces(traces)
                traces['ai_analysis'] = analysis_results

                # Save traces if they indicate potential threats
                if analysis_results.get('threat_assessment', {}).get('threat_level') in ['MEDIUM', 'HIGH', 'CRITICAL']:
                    self._save_trace_data(traces)
            except Exception as e:
                traces['ai_analysis'] = self._handle_ai_error(e)
                self.logger.warning("AI analysis failed, continuing with basic trace collection")
        else:
            traces['ai_analysis'] = {
                'status': 'unavailable',
                'message': 'AI analysis not available',
                'timestamp': datetime.now().isoformat()
            }

        return traces

    def _get_process_info(self) -> List[Dict[str, Any]]:
        """Collect information about running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
            try:
                processes.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "username": proc.info["username"],
                    "cpu_usage": proc.info["cpu_percent"],
                    "memory_usage": proc.info["memory_info"].rss / (1024 * 1024)  # Convert to MB
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Collect information about network connections."""
        connections = []
        try:
            for conn in psutil.net_connections():
                connections.append({
                    'local_address': conn.laddr._asdict() if conn.laddr else None,
                    'remote_address': conn.raddr._asdict() if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        except (psutil.AccessDenied, psutil.Error):
            self.logger.warning("Unable to collect network connections")
        return connections

    def _get_system_resources(self) -> Dict[str, Any]:
        """Collect system resource usage information."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory()._asdict(),
            'disk': {str(part.mountpoint): psutil.disk_usage(part.mountpoint)._asdict()
                    for part in psutil.disk_partitions()},
            'network_io': psutil.net_io_counters()._asdict()
        }

    def _generate_cpu_usage_graph(self, process_info: List[Dict[str, Any]], output_file='cpu_usage.png'):
        """Generate a graph of CPU usage over time for monitored processes."""
        if not process_info:
            return

        timestamps = [datetime.now() for _ in range(len(process_info))]
        cpu_usages = [process['cpu_usage'] for process in process_info]
        process_names = [process['name'] for process in process_info]

        plt.figure(figsize=(10, 6))
        for i, process_name in enumerate(process_names):
            plt.plot(timestamps, [cpu_usages[i]] * len(timestamps), label=process_name)

        plt.xlabel('Time')
        plt.ylabel('CPU Usage (%)')
        plt.title('CPU Usage Over Time')
        plt.legend()
        plt.savefig(output_file)
        plt.close()

    def _save_trace_data(self, traces: Dict[str, Any]) -> None:
        """Save trace data to a file when threats are detected."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = self.log_dir / f"threat_trace_{timestamp}.json"

            with open(filename, 'w') as f:
                json.dump(traces, f, indent=2, default=str)

            self.logger.info(f"Saved threat trace data to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving trace data: {str(e)}")

    def _handle_ai_error(self, error: Exception) -> Dict[str, Any]:
        """Handle AI-related errors gracefully."""
        error_info = {
            'timestamp': datetime.now().isoformat(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            'status': 'error'
        }
        self.logger.error(f"AI analysis error: {error_info}")
        return error_info

    def _maintain_trace_window(self, current_time: datetime) -> None:
        """Maintain the sliding window of trace history."""
        window_start = current_time - timedelta(seconds=self.window_size)

        # Remove traces outside the window
        self.trace_history = [
            trace for trace in self.trace_history
            if datetime.fromisoformat(trace['timestamp']) >= window_start
        ]

        # Update pattern cache
        self._update_pattern_cache()

    def _update_pattern_cache(self) -> None:
        """Update the pattern cache based on recent traces."""
        if not self.trace_history or not self.pattern_detector:
            return

        try:
            # Detect patterns in current window
            current_patterns = self.pattern_detector.detect_patterns(self.trace_history)

            # Update cache with timestamp
            self.pattern_cache[datetime.now().isoformat()] = current_patterns

            # Remove old patterns from cache
            current_time = datetime.now()
            old_patterns = [
                timestamp for timestamp in self.pattern_cache
                if (current_time - datetime.fromisoformat(timestamp)).total_seconds() > self.window_size
            ]

            for timestamp in old_patterns:
                del self.pattern_cache[timestamp]

        except Exception as e:
            self.logger.error(f"Error updating pattern cache: {str(e)}")
