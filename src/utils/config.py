import yaml
import os
import logging
from typing import Dict, Any
from pathlib import Path

class ConfigLoader:
    """Loads configuration from YAML files."""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        self.config = {}
        
        self._load_config()
        
    def _load_config(self):
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r") as f:
                    self.config = yaml.safe_load(f)
                    self.logger.info(f"Loaded configuration from {self.config_path}")
            else:
                self.logger.warning(f"Configuration file {self.config_path} not found, using defaults")
                self.config = self._get_default_config()
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            self.config = self._get_default_config()
            
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "app": {
                "name": "Cyber Attack Tracer",
                "version": "0.1.0",
                "log_level": "INFO",
                "log_dir": "logs"
            },
            "trace_collector": {
                "window_size": 300,  # 5 minutes
                "pattern_threshold": 0.7,
                "log_dir": "logs/traces"
            },
            "ai_analyzer": {
                "model_path": "distilbert-base-uncased",
                "zero_shot_model": "cross-encoder/nli-distilroberta-base",
                "confidence_threshold": 0.6
            },
            "ember_integration": {
                "model_path": None,
                "ember_data_path": None
            },
            "knowledge_graph": {
                "output_dir": "data/graphs"
            },
            "malware_categorizer": {
                "db_path": "data/malware_db"
            },
            "trend_analyzer": {
                "history_file": "data/technique_history.json",
                "default_window": 30  # 30 days
            }
        }
        
    def get_config(self) -> Dict[str, Any]:
        """Get the loaded configuration."""
        return self.config
        
    def get_app_config(self) -> Dict[str, Any]:
        """Get application configuration."""
        return self.config.get("app", {})
        
    def get_component_config(self, component_name: str) -> Dict[str, Any]:
        """Get configuration for a specific component."""
        return self.config.get(component_name, {})
        
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False)
                
            self.config = config
            self.logger.info(f"Saved configuration to {self.config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False
            
    def update_config(self, updates: Dict[str, Any]) -> bool:
        """Update configuration with new values."""
        try:
            # Deep update of configuration
            self._deep_update(self.config, updates)
            
            # Save updated configuration
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error updating configuration: {str(e)}")
            return False
            
    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Deep update a nested dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value

def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """Convenience function to load configuration."""
    loader = ConfigLoader(config_path)
    return loader.get_config()
