from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseTraceCollector(ABC):
    """Abstract base class for platform-specific trace collectors."""
    
    @abstractmethod
    def collect_processes(self) -> Dict[str, Any]:
        """Collect running processes."""
        pass
        
    @abstractmethod
    def collect_network_connections(self) -> Dict[str, Any]:
        """Collect network connections."""
        pass
        
    @abstractmethod
    def collect_file_system_events(self) -> Dict[str, Any]:
        """Collect file system events."""
        pass
        
    @abstractmethod
    def collect_registry_events(self) -> Dict[str, Any]:
        """Collect registry events."""
        pass
        
    @abstractmethod
    def collect_system_resources(self) -> Dict[str, Any]:
        """Collect system resource usage."""
        pass
