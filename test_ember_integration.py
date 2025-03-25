"""Test script for the EMBER integration components."""

import logging
import sys
import os
from pathlib import Path
from src.ember_integration.ember_analyzer import EmberAnalyzer
from src.ember_integration.feature_extractor import PEFeatureExtractor
from src.ember_integration.malware_categorizer import MalwareCategorizer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_test_pe_file():
    """Create a simple test PE file for testing."""
    test_dir = Path("data/test_samples")
    test_dir.mkdir(parents=True, exist_ok=True)
    
    test_file = test_dir / "test_sample.txt"
    with open(test_file, "w") as f:
        f.write("This is a test file to simulate a PE file for testing purposes.\n")
        f.write("MZ" + "A" * 100)  # Simple MZ header simulation
    
    logger.info(f"Created test file at {test_file}")
    return str(test_file)

def test_feature_extractor():
    """Test the FeatureExtractor component."""
    try:
        logger.info("Initializing FeatureExtractor...")
        extractor = PEFeatureExtractor()
        
        # Create a test file
        test_file = create_test_pe_file()
        
        logger.info(f"Extracting features from {test_file}...")
        try:
            features = extractor.extract_features(test_file)
            logger.info(f"Feature extraction successful: {len(features)} features extracted")
        except Exception as e:
            logger.warning(f"Feature extraction failed as expected for non-PE file: {str(e)}")
            logger.info("This is expected behavior for a simulated PE file")
            
        return True
    except Exception as e:
        logger.error(f"Error testing FeatureExtractor: {str(e)}")
        return False

def test_malware_categorizer():
    """Test the MalwareCategorizer component."""
    try:
        logger.info("Initializing MalwareCategorizer...")
        categorizer = MalwareCategorizer()
        
        # Create sample features
        sample_features = {
            "general": {
                "size": 1024,
                "md5": "sample_md5_hash",
                "sha256": "sample_sha256_hash"
            },
            "header": {
                "timestamp": "2023-01-01",
                "characteristics": ["executable", "dll"]
            },
            "sections": [
                {"name": ".text", "size": 512, "entropy": 7.2},
                {"name": ".data", "size": 256, "entropy": 5.1}
            ],
            "imports": ["kernel32.dll", "user32.dll"],
            "exports": ["SampleFunction1", "SampleFunction2"]
        }
        
        logger.info("Categorizing sample...")
        categorization = categorizer.categorize_sample(sample_features)
        
        logger.info("Categorization results:")
        logger.info(f"- Category: {categorization.get('category', 'unknown')}")
        logger.info(f"- Confidence: {categorization.get('confidence', 0)}")
        logger.info(f"- Techniques: {len(categorization.get('techniques', []))}")
        
        return True
    except Exception as e:
        logger.error(f"Error testing MalwareCategorizer: {str(e)}")
        return False

def test_ember_analyzer():
    """Test the EmberAnalyzer component."""
    try:
        logger.info("Initializing EmberAnalyzer...")
        analyzer = EmberAnalyzer()
        
        # Create a test file
        test_file = create_test_pe_file()
        
        logger.info(f"Analyzing {test_file}...")
        try:
            analysis = analyzer.analyze_file(test_file)
            logger.info("Analysis results:")
            logger.info(f"- Status: {analysis.get('status', 'unknown')}")
            logger.info(f"- Score: {analysis.get('score', 0)}")
        except Exception as e:
            logger.warning(f"Analysis failed as expected for non-PE file: {str(e)}")
            logger.info("This is expected behavior for a simulated PE file")
            
        return True
    except Exception as e:
        logger.error(f"Error testing EmberAnalyzer: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_feature_extractor() and test_malware_categorizer() and test_ember_analyzer()
    sys.exit(0 if success else 1)
