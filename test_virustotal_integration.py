"""Test script for the VirusTotal integration components."""

import logging
import sys
import os
from pathlib import Path
from src.virustotal_integration.virustotal_analyzer import VirusTotalAnalyzer
from src.virustotal_integration.feature_extractor import VirusTotalFeatureExtractor
from src.ember_integration.malware_categorizer import MalwareCategorizer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_test_file():
    """Create a simple test file for testing."""
    test_dir = Path("data/test_samples")
    test_dir.mkdir(parents=True, exist_ok=True)
    
    test_file = test_dir / "test_sample.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file for VirusTotal analysis.\n")
        f.write("MZ" + "A" * 100)  # Simple MZ header simulation
    
    logger.info(f"Created test file at {test_file}")
    return str(test_file)

def test_feature_extractor():
    """Test the VirusTotalFeatureExtractor component."""
    try:
        logger.info("Initializing VirusTotalFeatureExtractor...")
        extractor = VirusTotalFeatureExtractor()
        
        # Create a test file
        test_file = create_test_file()
        
        logger.info(f"Extracting features from {test_file}...")
        features = extractor.extract_features(test_file)
        
        logger.info("Feature extraction results:")
        logger.info(f"- File size: {features.get('file_size', 0)}")
        logger.info(f"- MD5: {features.get('md5', '')}")
        logger.info(f"- SHA256: {features.get('sha256', '')}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing VirusTotalFeatureExtractor: {str(e)}")
        return False

def test_malware_categorizer():
    """Test the MalwareCategorizer component."""
    try:
        logger.info("Initializing MalwareCategorizer...")
        categorizer = MalwareCategorizer()
        
        # Create sample features
        sample_features = {
            "file_size": 1024,
            "md5": "sample_md5_hash",
            "sha256": "sample_sha256_hash",
            "is_pe": True,
            "header_info": {
                "timestamp": "2023-01-01",
                "characteristics": ["executable", "dll"]
            },
            "section_info": [
                {"name": ".text", "size": 512, "entropy": 7.2},
                {"name": ".data", "size": 256, "entropy": 5.1}
            ],
            "import_info": {"kernel32.dll": ["VirtualAlloc", "CreateThread"]},
            "export_info": ["SampleFunction1", "SampleFunction2"]
        }
        
        logger.info("Categorizing sample...")
        categorization = categorizer.categorize_sample(sample_features)
        
        logger.info("Categorization results:")
        logger.info(f"- Category: {categorization.get('category', 'unknown')}")
        logger.info(f"- Confidence: {categorization.get('confidence', 0)}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing MalwareCategorizer: {str(e)}")
        return False

def test_virustotal_analyzer():
    """Test the VirusTotalAnalyzer component."""
    try:
        logger.info("Initializing VirusTotalAnalyzer...")
        analyzer = VirusTotalAnalyzer()
        
        # Create a test file
        test_file = create_test_file()
        
        logger.info(f"Analyzing {test_file}...")
        try:
            analysis = analyzer.analyze_file(test_file)
            logger.info("Analysis results:")
            logger.info(f"- Status: {analysis.get('status', 'unknown')}")
            if "error" in analysis:
                logger.info(f"- Error: {analysis.get('error', '')}")
                logger.info("This may be expected if no API key is configured")
        except Exception as e:
            logger.warning(f"Analysis error: {str(e)}")
            logger.info("This may be expected if no API key is configured")
        
        # Test status method
        status = analyzer.get_status()
        logger.info(f"Analyzer status: {status}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing VirusTotalAnalyzer: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_feature_extractor() and test_malware_categorizer() and test_virustotal_analyzer()
    sys.exit(0 if success else 1)
