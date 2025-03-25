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
        try:
            cpu_info = self._get_cpu_usage()
            memory_info = self._get_memory_usage()
            
            # Add the specific fields expected by the test
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_info.get('percent', 0),
                'memory_percent': memory_info.get('percent', 0),
                'cpu_usage': cpu_info,
                'memory_usage': memory_info,
                'disk_usage': self._get_disk_usage(),
                'network_usage': self._get_network_usage()
            }
        except Exception as e:
            self.logger.error(f"Error getting system status: {str(e)}")
            # Return default values if there's an error
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': 0,
                'memory_percent': 0,
                'cpu_usage': {'percent': 0},
                'memory_usage': {'percent': 0},
                'disk_usage': {},
                'network_usage': {}
            }
    
    def _get_cpu_usage(self) -> Dict[str, Any]:
        """Get CPU usage statistics."""
        try:
            cpu_freq = psutil.cpu_freq()
            freq_dict = cpu_freq._asdict() if cpu_freq else {'current': 0, 'min': 0, 'max': 0}
            
            return {
                'percent': psutil.cpu_percent(interval=0.1),
                'count': psutil.cpu_count(),
                'frequency': freq_dict
            }
        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {str(e)}")
            return {
                'percent': 0,
                'count': 1,
                'frequency': {'current': 0, 'min': 0, 'max': 0}
            }
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        try:
            return psutil.virtual_memory()._asdict()
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {str(e)}")
            return {'percent': 0, 'total': 0, 'available': 0, 'used': 0, 'free': 0}
    
    def _get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage statistics."""
        try:
            return {
                str(part.mountpoint): psutil.disk_usage(part.mountpoint)._asdict()
                for part in psutil.disk_partitions()
            }
        except Exception as e:
            self.logger.error(f"Error getting disk usage: {str(e)}")
            return {}
    
    def _get_network_usage(self) -> Dict[str, Any]:
        """Get network usage statistics."""
        try:
            return psutil.net_io_counters()._asdict()
        except Exception as e:
            self.logger.error(f"Error getting network usage: {str(e)}")
            return {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0}
