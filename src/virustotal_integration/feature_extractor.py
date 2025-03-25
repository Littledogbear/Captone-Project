import os
import hashlib
import logging
from typing import Dict, Any, List
import lief
import json

class VirusTotalFeatureExtractor:
    """Extracts features from files for VirusTotal analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def extract_features(self, file_path: str) -> Dict[str, Any]:
        """Extract features from a file for VirusTotal analysis."""
        try:
            # Read file
            with open(file_path, "rb") as f:
                file_data = f.read()
                
            # Calculate hashes
            features = {
                "file_path": file_path,
                "file_size": len(file_data),
                "md5": hashlib.md5(file_data).hexdigest(),
                "sha256": hashlib.sha256(file_data).hexdigest(),
                "sha1": hashlib.sha1(file_data).hexdigest()
            }
            
            # Try to extract PE-specific features if it's a PE file
            try:
                lief_binary = lief.parse(list(file_data))
                if lief_binary:
                    features["is_pe"] = True
                    features["header_info"] = self._extract_header_info(lief_binary)
                    features["section_info"] = self._extract_section_info(lief_binary)
                    features["import_info"] = self._extract_import_info(lief_binary)
                    features["export_info"] = self._extract_export_info(lief_binary)
                else:
                    features["is_pe"] = False
            except Exception as e:
                self.logger.debug(f"Not a PE file or error parsing PE: {str(e)}")
                features["is_pe"] = False
            
            return features
        except Exception as e:
            self.logger.error(f"Error extracting features from {file_path}: {str(e)}")
            return {"error": str(e)}

    # Keep the same helper methods from the original PEFeatureExtractor
    def _extract_header_info(self, binary) -> Dict[str, Any]:
        """Extract information from PE header."""
        # Implementation copied from PEFeatureExtractor
        header_info = {
            "machine": binary.header.machine.name if hasattr(binary.header, "machine") else "",
            "timestamp": binary.header.time_date_stamps,
            "characteristics": [str(c) for c in binary.header.characteristics_list],
            "subsystem": binary.optional_header.subsystem.name if hasattr(binary.optional_header, "subsystem") else "",
            "dll_characteristics": [str(c) for c in binary.optional_header.dll_characteristics_lists]
        }
        return header_info
        
    def _extract_section_info(self, binary) -> List[Dict[str, Any]]:
        """Extract information about PE sections."""
        # Implementation copied from PEFeatureExtractor
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
        
    def _extract_import_info(self, binary) -> Dict[str, List[str]]:
        """Extract information about imported functions."""
        # Implementation copied from PEFeatureExtractor
        imports = {}
        for imp in binary.imports:
            library_name = imp.name
            imports[library_name] = [entry.name for entry in imp.entries if entry.name]
        return imports
        
    def _extract_export_info(self, binary) -> List[str]:
        """Extract information about exported functions."""
        # Implementation copied from PEFeatureExtractor
        exports = []
        if binary.has_exports:
            for exp in binary.exported_functions:
                exports.append(exp.name if exp.name else f"ORDINAL_{exp.ordinal}")
        return exports
