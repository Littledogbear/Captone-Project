import platform
import logging
from typing import Literal

class PlatformDetector:
    """Detect and provide platform-specific information."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.platform = self._detect_platform()
        
    def _detect_platform(self) -> Literal["windows", "mac", "linux", "unknown"]:
        """Detect the current platform."""
        system = platform.system().lower()
        
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "mac"
        elif system == "linux":
            return "linux"
        else:
            self.logger.warning(f"Unknown platform: {system}")
            return "unknown"
            
    def get_platform(self) -> str:
        """Get the current platform."""
        return self.platform
        
    def is_windows(self) -> bool:
        """Check if the current platform is Windows."""
        return self.platform == "windows"
        
    def is_mac(self) -> bool:
        """Check if the current platform is Mac."""
        return self.platform == "mac"
