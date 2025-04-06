"""
Run Monitoring Dashboard Script.

This script provides a convenient way to start the monitoring dashboard.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.alerting.dashboard_main import main

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    os.makedirs("output/dashboard_graphs", exist_ok=True)
    os.makedirs("output/dashboard_reports", exist_ok=True)
    
    main()
