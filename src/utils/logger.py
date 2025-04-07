
import logging
import os
from datetime import datetime

def setup_logger(log_level=logging.INFO):
    """Set up logging configuration."""
    os.makedirs("logs", exist_ok=True)
    
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f"logs/app_{datetime.now().strftime('%Y%m%d')}.log")
        ]
    )
    
    return logging.getLogger()
