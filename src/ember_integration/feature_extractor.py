import numpy as np
import hashlib
from typing import Dict, Any, List, Tuple
import logging
import json
import os
from datetime import datetime

class PEFeatureExtractor:
    """Extracts features from PE files for malware analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def extract_features(self, file_path: str) -> Dict[str, Any]:
        """Extract features from a PE file."""
        try:
            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()
                
            # Check if it's a PE file (MZ header)
            if not file_data.startswith(b'MZ'):
                return {"error": "Not a valid PE file"}
                
            # Extract features
            features = {
                "file_path": file_path,
                "file_size": len(file_data),
                "md5": hashlib.md5(file_data).hexdigest(),
                "sha256": hashlib.sha256(file_data).hexdigest(),
                "header_info": self._extract_header_info(file_data),
                "section_info": self._extract_section_info(file_data),
                "import_info": self._extract_import_info(file_data),
                "export_info": self._extract_export_info(file_data),
                "entropy_analysis": self._calculate_entropy(file_data),
                "byte_histogram": self._calculate_byte_histogram(file_data),
                "strings": self._extract_strings(file_data)
            }
            
            return features
        except Exception as e:
            self.logger.error(f"Error extracting features from {file_path}: {str(e)}")
            return {"error": str(e)}
            
    def _extract_header_info(self, file_data: bytes) -> Dict[str, Any]:
        """Extract information from PE header."""
        # Simplified implementation without LIEF
        header_info = {
            "machine": "UNKNOWN",
            "timestamp": int(datetime.now().timestamp()),
            "characteristics": [],
            "subsystem": "UNKNOWN",
            "dll_characteristics": []
        }
        return header_info
        
    def _extract_section_info(self, file_data: bytes) -> List[Dict[str, Any]]:
        """Extract information about PE sections."""
        # Simplified implementation without LIEF
        return []
        
    def _extract_import_info(self, file_data: bytes) -> Dict[str, List[str]]:
        """Extract information about imported functions."""
        # Simplified implementation without LIEF
        return {}
        
    def _extract_export_info(self, file_data: bytes) -> List[str]:
        """Extract information about exported functions."""
        # Simplified implementation without LIEF
        return []
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
            
        byte_counts = np.zeros(256, dtype=np.int64)
        for byte in data:
            byte_counts[byte] += 1
            
        probs = byte_counts / len(data)
        probs = probs[probs > 0]  # Remove zero probabilities
        
        return -np.sum(probs * np.log2(probs))
        
    def _calculate_byte_histogram(self, data: bytes) -> List[int]:
        """Calculate histogram of byte values."""
        histogram = np.zeros(256, dtype=np.int64)
        for byte in data:
            histogram[byte] += 1
        return histogram.tolist()
        
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings from binary data."""
        strings = []
        
        # ASCII strings
        ascii_pattern = b'[\\x20-\\x7e]{%d,}' % min_length
        import re
        ascii_strings = re.findall(ascii_pattern, data)
        for s in ascii_strings:
            try:
                strings.append(s.decode('ascii'))
            except:
                pass
                
        # Unicode strings (simple approach)
        for i in range(0, len(data) - min_length * 2, 2):
            if all(data[j] >= 0x20 and data[j] <= 0x7e and data[j+1] == 0 for j in range(i, i + min_length * 2, 2)):
                try:
                    unicode_str = data[i:i + min_length * 2].decode('utf-16-le')
                    strings.append(unicode_str)
                except:
                    pass
                    
        return strings
