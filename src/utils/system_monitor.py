import psutil
import logging
from typing import Dict, Any
from datetime import datetime

class SystemMonitor:
    """Monitor system resources and activities."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_usage': self._get_cpu_usage(),
            'memory_usage': self._get_memory_usage(),
            'disk_usage': self._get_disk_usage(),
            'network_usage': self._get_network_usage()
        }
    
    def _get_cpu_usage(self) -> Dict[str, Any]:
        """Get CPU usage statistics."""
        return {
            'percent': psutil.cpu_percent(interval=1),
            'count': psutil.cpu_count(),
            'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        }
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        return psutil.virtual_memory()._asdict()
    
    def _get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage statistics."""
        return {
            str(part.mountpoint): psutil.disk_usage(part.mountpoint)._asdict()
            for part in psutil.disk_partitions()
        }
    
    def _get_network_usage(self) -> Dict[str, Any]:
        """Get network usage statistics."""
        return psutil.net_io_counters()._asdict()
