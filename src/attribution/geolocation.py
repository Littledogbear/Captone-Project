import logging
import requests
import json
from typing import Dict, Any, Optional
import os
from pathlib import Path
import time

class IPGeolocation:
    """Provides geolocation services for IP addresses."""
    
    def __init__(self, cache_dir: str = "data/geolocation_cache"):
        self.logger = logging.getLogger(__name__)
        self.cache_dir = cache_dir
        self.cache = {}
        self.last_request_time = 0
        self.request_interval = 1.0  # Minimum time between API requests in seconds
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Load cache from disk
        self._load_cache()
        
    def _load_cache(self):
        """Load geolocation cache from disk."""
        try:
            cache_file = Path(self.cache_dir) / "ip_cache.json"
            if cache_file.exists():
                with open(cache_file, "r") as f:
                    self.cache = json.load(f)
                self.logger.info(f"Loaded {len(self.cache)} IP addresses from cache")
        except Exception as e:
            self.logger.error(f"Error loading geolocation cache: {str(e)}")
            self.cache = {}
            
    def _save_cache(self):
        """Save geolocation cache to disk."""
        try:
            cache_file = Path(self.cache_dir) / "ip_cache.json"
            with open(cache_file, "w") as f:
                json.dump(self.cache, f)
            self.logger.info(f"Saved {len(self.cache)} IP addresses to cache")
        except Exception as e:
            self.logger.error(f"Error saving geolocation cache: {str(e)}")
            
    def get_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address."""
        # Check cache first
        if ip_address in self.cache:
            self.logger.debug(f"IP {ip_address} found in cache")
            return self.cache[ip_address]
            
        # Handle private IP addresses
        if self._is_private_ip(ip_address):
            result = {
                "ip": ip_address,
                "country": "Private",
                "region": "Private",
                "city": "Private",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Private Network",
                "organization": "Private Network",
                "is_private": True
            }
            self.cache[ip_address] = result
            self._save_cache()
            return result
            
        # Rate limiting
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.request_interval:
            time.sleep(self.request_interval - time_since_last_request)
            
        # Query IP geolocation API
        try:
            # Using ip-api.com (free, no API key required)
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("status") == "success":
                    result = {
                        "ip": ip_address,
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "latitude": data.get("lat", 0.0),
                        "longitude": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown"),
                        "organization": data.get("org", "Unknown"),
                        "is_private": False
                    }
                    
                    # Cache the result
                    self.cache[ip_address] = result
                    self._save_cache()
                    
                    return result
                else:
                    self.logger.warning(f"Failed to get geolocation for IP {ip_address}: {data.get('message', 'Unknown error')}")
            else:
                self.logger.warning(f"Failed to get geolocation for IP {ip_address}: HTTP {response.status_code}")
                
            # Return a default result on failure
            return self._get_default_result(ip_address)
        except Exception as e:
            self.logger.error(f"Error getting geolocation for IP {ip_address}: {str(e)}")
            return self._get_default_result(ip_address)
            
    def _get_default_result(self, ip_address: str) -> Dict[str, Any]:
        """Get a default geolocation result."""
        return {
            "ip": ip_address,
            "country": "Unknown",
            "country_code": "XX",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
            "organization": "Unknown",
            "is_private": False,
            "error": True
        }
        
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if an IP address is private."""
        # Simple check for private IP ranges
        octets = ip_address.split('.')
        if len(octets) != 4:
            return False
            
        try:
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
                
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
                
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
                
            # 127.0.0.0/8 (localhost)
            if first_octet == 127:
                return True
                
            return False
        except:
            return False
            
    def get_country_risk_score(self, country_code: str) -> float:
        """Get a risk score for a country based on cyber threat activity."""
        # This is a simplified implementation
        # In a real system, this would be based on threat intelligence data
        high_risk_countries = ["CN", "RU", "IR", "KP", "SY"]
        medium_risk_countries = ["RO", "BG", "UA", "BY", "PK", "VN"]
        
        if country_code in high_risk_countries:
            return 0.8
        elif country_code in medium_risk_countries:
            return 0.5
        else:
            return 0.2
