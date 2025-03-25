import psutil
import logging
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseTraceCollector

class MacTraceCollector(BaseTraceCollector):
    """Mac-specific trace collector."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def collect_processes(self) -> Dict[str, Any]:
        """Collect running processes on Mac."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return {"processes": processes}
        
    def collect_network_connections(self) -> Dict[str, Any]:
        """Collect network connections on Mac."""
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.raddr:
                connections.append({
                    "local_ip": conn.laddr.ip,
                    "local_port": conn.laddr.port,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "status": conn.status,
                    "pid": conn.pid
                })
        return {"network_connections": connections}
        
    def collect_file_system_events(self) -> Dict[str, Any]:
        """Collect file system events on Mac."""
        # Mac-specific file system events collection
        # This is a placeholder implementation
        return {"file_system_events": []}
        
    def collect_registry_events(self) -> Dict[str, Any]:
        """Collect registry events on Mac."""
        # Mac doesn't have a registry, alternative is preferences
        # This is a placeholder implementation
        return {"registry_events": []}
        
    def collect_system_resources(self) -> Dict[str, Any]:
        """Collect system resource usage on Mac."""
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "system_resources": {
                "cpu_percent": cpu,
                "memory_percent": memory.percent,
                "disk_percent": disk.percent
            }
        }
