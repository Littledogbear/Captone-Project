"""
EMBER Integration Module (Legacy Compatibility).

This module provides backward compatibility by redirecting imports to VirusTotal.
"""

from src.virustotal_integration.ember_compatibility import EmberAnalyzer
from .feature_extractor_no_lief import PEFeatureExtractor
# Add other forwarded imports as needed
