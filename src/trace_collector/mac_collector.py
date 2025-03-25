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
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            return {"processes": processes}
        except Exception as e:
            self.logger.error(f"Error collecting processes: {str(e)}")
            return {"processes": []}
        
    def collect_network_connections(self) -> Dict[str, Any]:
        """Collect network connections on Mac."""
        try:
            connections = []
            for conn in psutil.net_connections(kind='all'):
                connection_info = {
                    "status": conn.status,
                    "pid": conn.pid
                }
                
                # Safely handle local address
                if conn.laddr:
                    try:
                        connection_info["local_ip"] = conn.laddr.ip
                        connection_info["local_port"] = conn.laddr.port
                    except AttributeError:
                        # Handle case where laddr is not a named tuple
                        if isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
                            connection_info["local_ip"] = conn.laddr[0]
                            connection_info["local_port"] = conn.laddr[1]
                
                # Safely handle remote address
                if conn.raddr:
                    try:
                        connection_info["remote_ip"] = conn.raddr.ip
                        connection_info["remote_port"] = conn.raddr.port
                    except AttributeError:
                        # Handle case where raddr is not a named tuple
                        if isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
                            connection_info["remote_ip"] = conn.raddr[0]
                            connection_info["remote_port"] = conn.raddr[1]
                
                connections.append(connection_info)
                
            return {"network_connections": connections}
        except Exception as e:
            self.logger.error(f"Error collecting network connections: {str(e)}")
            return {"network_connections": []}
        
    def collect_file_system_events(self) -> Dict[str, Any]:
        """Collect file system events on Mac."""
        try:
            # Mac-specific file system events collection
            # This is a placeholder implementation
            return {"file_system_events": []}
        except Exception as e:
            self.logger.error(f"Error collecting file system events: {str(e)}")
            return {"file_system_events": []}
        
    def collect_registry_events(self) -> Dict[str, Any]:
        """Collect registry events on Mac."""
        try:
            # Mac doesn't have a registry, alternative is preferences
            # This is a placeholder implementation
            return {"registry_events": []}
        except Exception as e:
            self.logger.error(f"Error collecting registry events: {str(e)}")
            return {"registry_events": []}
        
    def collect_system_resources(self) -> Dict[str, Any]:
        """Collect system resource usage on Mac."""
        try:
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
        except Exception as e:
            self.logger.error(f"Error collecting system resources: {str(e)}")
            return {"system_resources": {}}
