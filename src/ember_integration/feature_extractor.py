import lief
import numpy as np
import hashlib
from typing import Dict, Any, List, Tuple
import logging
import json
import os

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
                
            # Parse PE file with LIEF
            lief_binary = lief.parse(list(file_data))
            
            if lief_binary is None:
                return {"error": "Not a valid PE file"}
                
            # Extract features
            features = {
                "file_path": file_path,
                "file_size": len(file_data),
                "md5": hashlib.md5(file_data).hexdigest(),
                "sha256": hashlib.sha256(file_data).hexdigest(),
                "header_info": self._extract_header_info(lief_binary),
                "section_info": self._extract_section_info(lief_binary),
                "import_info": self._extract_import_info(lief_binary),
                "export_info": self._extract_export_info(lief_binary),
                "entropy_analysis": self._calculate_entropy(file_data),
                "byte_histogram": self._calculate_byte_histogram(file_data),
                "strings": self._extract_strings(file_data)
            }
            
            return features
        except Exception as e:
            self.logger.error(f"Error extracting features from {file_path}: {str(e)}")
            return {"error": str(e)}
            
    def _extract_header_info(self, binary: lief.PE.Binary) -> Dict[str, Any]:
        """Extract information from PE header."""
        header_info = {
            "machine": binary.header.machine.name if hasattr(binary.header, "machine") else "",
            "timestamp": binary.header.time_date_stamps,
            "characteristics": [str(c) for c in binary.header.characteristics_list],
            "subsystem": binary.optional_header.subsystem.name if hasattr(binary.optional_header, "subsystem") else "",
            "dll_characteristics": [str(c) for c in binary.optional_header.dll_characteristics_lists]
        }
        return header_info
        
    def _extract_section_info(self, binary: lief.PE.Binary) -> List[Dict[str, Any]]:
        """Extract information about PE sections."""
        sections = []
        for section in binary.sections:
            section_info = {
                "name": section.name,
                "size": section.size,
                "virtual_size": section.virtual_size,
                "entropy": section.entropy,
                "characteristics": [str(c) for c in section.characteristics_lists]
            }
            sections.append(section_info)
        return sections
        
    def _extract_import_info(self, binary: lief.PE.Binary) -> Dict[str, List[str]]:
        """Extract information about imported functions."""
        imports = {}
        for imp in binary.imports:
            library_name = imp.name
            imports[library_name] = [entry.name for entry in imp.entries if entry.name]
        return imports
        
    def _extract_export_info(self, binary: lief.PE.Binary) -> List[str]:
        """Extract information about exported functions."""
        exports = []
        if binary.has_exports:
            for exp in binary.exported_functions:
                exports.append(exp.name if exp.name else f"ORDINAL_{exp.ordinal}")
        return exports
        
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
