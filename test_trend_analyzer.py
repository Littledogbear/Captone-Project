"""Test script for the TrendAnalyzer component."""

import logging
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from src.analysis_engine.trend_analyzer import TrendAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_trend_analyzer():
    """Test the TrendAnalyzer component."""
    try:
        # Create a temporary history file for testing
        test_dir = Path("data/test")
        test_dir.mkdir(parents=True, exist_ok=True)
        test_history_file = str(test_dir / "test_technique_history.json")
        
        logger.info(f"Initializing TrendAnalyzer with test history file: {test_history_file}")
        trend_analyzer = TrendAnalyzer(history_file=test_history_file)
        
        # Add technique observations with different timestamps
        current_time = datetime.now()
        
        # Add observations for T1071 (Command and Control)
        logger.info("Adding technique observations for T1071...")
        for i in range(10):
            timestamp = (current_time - timedelta(days=i*3)).isoformat()
            trend_analyzer.add_technique_observation("T1071", timestamp)
            
        # Add observations for T1048 (Exfiltration)
        logger.info("Adding technique observations for T1048...")
        for i in range(5):
            timestamp = (current_time - timedelta(days=i*5)).isoformat()
            trend_analyzer.add_technique_observation("T1048", timestamp)
            
        # Add observations for T1059 (Command and Scripting Interpreter)
        logger.info("Adding technique observations for T1059...")
        for i in range(15):
            timestamp = (current_time - timedelta(days=i*2)).isoformat()
            trend_analyzer.add_technique_observation("T1059", timestamp)
            
        # Analyze trends
        logger.info("Analyzing trends...")
        trends = trend_analyzer.analyze_trends(time_window=30)
        
        logger.info("Trend analysis results:")
        logger.info(f"- Time window: {trends.get('time_window', 0)} days")
        logger.info(f"- Window start: {trends.get('window_start', '')}")
        logger.info(f"- Window end: {trends.get('window_end', '')}")
        
        for technique_id, technique_data in trends.get("technique_trends", {}).items():
            logger.info(f"- {technique_id}:")
            logger.info(f"  - Total observations: {technique_data.get('total_observations', 0)}")
            logger.info(f"  - Weekly counts: {technique_data.get('weekly_counts', [])}")
            logger.info(f"  - Trend direction: {technique_data.get('trend_direction', '')}")
            
        # Get top techniques
        logger.info("Getting top techniques...")
        top_techniques = trend_analyzer.get_top_techniques(time_window=30, limit=3)
        
        logger.info("Top techniques:")
        for i, technique in enumerate(top_techniques):
            logger.info(f"{i+1}. {technique.get('technique_id', '')}: {technique.get('count', 0)} observations")
            
        # Generate trend report
        logger.info("Generating trend report...")
        report = trend_analyzer.generate_trend_report(time_window=30)
        
        logger.info("Trend report:")
        logger.info(f"- Overall direction: {report.get('overall_direction', '')}")
        logger.info(f"- Top techniques: {len(report.get('top_techniques', []))}")
        
        # Clean up test file
        try:
            os.remove(test_history_file)
            logger.info(f"Removed test history file: {test_history_file}")
        except:
            pass
            
        return True
    except Exception as e:
        logger.error(f"Error testing TrendAnalyzer: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_trend_analyzer()
    sys.exit(0 if success else 1)
