from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
import logging.config
import yaml
import asyncio
from pathlib import Path

from src.trace_collector.collector import TraceCollector
from src.analysis_engine.analyzer import TraceAnalyzer
from src.analysis_engine.trend_analyzer import TrendAnalyzer
from src.utils.system_monitor import SystemMonitor
from src.utils.config import load_config
from src.ember_integration.ember_analyzer import EmberAnalyzer
from src.knowledge_graph.knowledge_graph_builder import KnowledgeGraphBuilder
from src.knowledge_graph.technique_identifier import TechniqueIdentifier
from src.knowledge_graph.graph_visualizer import GraphVisualizer
from src.knowledge_graph.interactive_visualizer import InteractiveVisualizer
from src.ember_integration.malware_categorizer import MalwareCategorizer
from src.attribution.geolocation import IPGeolocation
from src.attribution.tool_fingerprinting import ToolFingerprinting
from src.attribution.attribution_engine import AttributionEngine
from src.alerting.real_time_monitor import RealTimeMonitor
from src.alerting.alert_manager import AlertManager
from src.alerting.notification_service import NotificationService
from src.alerting.alert_dashboard import AlertDashboard
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="Cyber Attack Tracer",
    description="AI-powered cyber attack trace collection and analysis system",
    version="0.1.0"
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Initialize components
system_monitor = SystemMonitor()
trace_collector = None
trace_analyzer = None
ember_analyzer = None
knowledge_graph_builder = None
technique_identifier = None
graph_visualizer = None
malware_categorizer = None
trend_analyzer = None
attribution_engine = None
real_time_monitor = None
alert_manager = None
notification_service = None
alert_dashboard = None

def init_components():
    """Initialize components in background."""
    global trace_collector, trace_analyzer, ember_analyzer, knowledge_graph_builder
    global technique_identifier, graph_visualizer, malware_categorizer, trend_analyzer
    global attribution_engine, real_time_monitor, alert_manager, notification_service
    global alert_dashboard
    try:
        trace_collector = TraceCollector()
        trace_analyzer = TraceAnalyzer()
        ember_analyzer = EmberAnalyzer()
        knowledge_graph_builder = KnowledgeGraphBuilder()
        technique_identifier = TechniqueIdentifier()
        graph_visualizer = GraphVisualizer()
        malware_categorizer = MalwareCategorizer()
        trend_analyzer = TrendAnalyzer()
        attribution_engine = AttributionEngine()
        alert_manager = AlertManager()
        notification_service = NotificationService()
        real_time_monitor = RealTimeMonitor()
        alert_dashboard = AlertDashboard()
        logger.info("Components initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing components: {str(e)}")

@app.on_event("startup")
async def startup_event():
    """Initialize components on startup."""
    global system_monitor
    try:
        # Initialize system monitor first as it doesn't require async init
        system_monitor = SystemMonitor()
        
        # Start component initialization in background
        import threading
        threading.Thread(target=init_components, daemon=True).start()
        
        # Start real-time monitoring if enabled
        config = load_config()
        if config.get("real_time_monitor", {}).get("enabled", False):
            # We'll start monitoring after components are initialized
            threading.Thread(target=lambda: _start_monitoring_when_ready(), daemon=True).start()
            logger.info("Real-time monitoring will start when components are ready")
        
        # Start alert dashboard if enabled
        if config.get("alert_dashboard", {}).get("enabled", False):
            # We'll start dashboard after components are initialized
            threading.Thread(target=lambda: _start_dashboard_when_ready(), daemon=True).start()
            logger.info("Alert dashboard will start when components are ready")
        
    except Exception as e:
        logger.error(f"Error in startup: {str(e)}")
        raise

def _start_monitoring_when_ready():
    """Start real-time monitoring when components are ready."""
    import time
    # Wait for real-time monitor to be initialized
    while real_time_monitor is None:
        time.sleep(1)
    # Start monitoring
    real_time_monitor.start_monitoring()
    logger.info("Real-time monitoring started")

def _start_dashboard_when_ready():
    """Start alert dashboard when components are ready."""
    import time
    # Wait for alert dashboard to be initialized
    while alert_dashboard is None:
        time.sleep(1)
    # Start dashboard
    alert_dashboard.start()
    logger.info("Alert dashboard started")

# Load logging configuration
config_path = Path("config/logging_config.yaml")
if config_path.exists():
    with open(config_path, "r") as f:
        logging_config = yaml.safe_load(f)
        logging.config.dictConfig(logging_config)

logger = logging.getLogger(__name__)

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Cyber Attack Tracer API"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/system/status")
async def get_system_status() -> Dict[str, Any]:
    """Get current system status."""
    try:
        status = system_monitor.get_system_status()
        if trace_collector and trace_collector.ai_analyzer:
            status["ai_status"] = {
                "initialized": trace_collector.ai_analyzer.is_initialized,
                "error": trace_collector.ai_analyzer.initialization_error
            }
        return status
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting system status")

@app.post("/traces/collect")
async def collect_traces() -> Dict[str, Any]:
    """Collect system traces."""
    if not trace_collector:
        raise HTTPException(
            status_code=503,
            detail="System initializing - trace collector not ready"
        )
    try:
        traces = trace_collector.collect_system_traces()
        return traces
    except Exception as e:
        logger.error(f"Error collecting traces: {str(e)}")
        raise HTTPException(status_code=500, detail="Error collecting traces")

@app.post("/traces/analyze")
async def analyze_traces(traces: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze collected traces."""
    if not trace_analyzer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - trace analyzer not ready"
        )
    try:
        analysis = trace_analyzer.analyze_traces(traces)
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing traces: {str(e)}")
        raise HTTPException(status_code=500, detail="Error analyzing traces")

@app.post("/malware/analyze")
async def analyze_malware(file_path: str) -> Dict[str, Any]:
    """Analyze a malware sample using EMBER."""
    if not ember_analyzer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - EMBER analyzer not ready"
        )
    try:
        analysis = ember_analyzer.analyze_file(file_path)
        return analysis
    except Exception as e:
        logger.error(f"Error analyzing malware: {str(e)}")
        raise HTTPException(status_code=500, detail="Error analyzing malware")

@app.post("/knowledge/build")
async def build_knowledge_graph(traces: Dict[str, Any]) -> Dict[str, Any]:
    """Build a knowledge graph from traces."""
    if not knowledge_graph_builder or not technique_identifier or not trend_analyzer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - knowledge graph components not ready"
        )
    try:
        graph = knowledge_graph_builder.build_graph_from_traces(traces)
        techniques = technique_identifier.identify_techniques(graph)
        
        # Update trend analyzer
        for technique in techniques:
            trend_analyzer.add_technique_observation(technique["technique_id"])
            
        return {
            "graph": {
                "nodes": len(graph.nodes()),
                "edges": len(graph.edges())
            },
            "techniques": techniques
        }
    except Exception as e:
        logger.error(f"Error building knowledge graph: {str(e)}")
        raise HTTPException(status_code=500, detail="Error building knowledge graph")

@app.post("/malware/categorize")
async def categorize_malware(features: Dict[str, Any]) -> Dict[str, Any]:
    """Categorize malware based on extracted features."""
    if not malware_categorizer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - malware categorizer not ready"
        )
    try:
        categorization = malware_categorizer.categorize_sample(features)
        return categorization
    except Exception as e:
        logger.error(f"Error categorizing malware: {str(e)}")
        raise HTTPException(status_code=500, detail="Error categorizing malware")

@app.get("/trends/analyze")
async def analyze_trends(time_window: int = 30) -> Dict[str, Any]:
    """Analyze trends in attack techniques."""
    if not trend_analyzer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - trend analyzer not ready"
        )
    try:
        trends = trend_analyzer.analyze_trends(time_window)
        return trends
    except Exception as e:
        logger.error(f"Error analyzing trends: {str(e)}")
        raise HTTPException(status_code=500, detail="Error analyzing trends")

@app.get("/trends/report")
async def generate_trend_report(time_window: int = 30) -> Dict[str, Any]:
    """Generate a comprehensive trend report."""
    if not trend_analyzer:
        raise HTTPException(
            status_code=503,
            detail="System initializing - trend analyzer not ready"
        )
    try:
        report = trend_analyzer.generate_trend_report(time_window)
        return report
    except Exception as e:
        logger.error(f"Error generating trend report: {str(e)}")
        raise HTTPException(status_code=500, detail="Error generating trend report")

@app.post("/attribution/analyze")
async def attribute_attack(traces: Dict[str, Any]) -> Dict[str, Any]:
    """Attribute an attack based on traces."""
    if not attribution_engine:
        raise HTTPException(
            status_code=503,
            detail="System initializing - attribution engine not ready"
        )
    try:
        # Build knowledge graph if available
        graph = None
        if knowledge_graph_builder:
            graph = knowledge_graph_builder.build_graph_from_traces(traces)
            
        # Attribute attack
        attribution = attribution_engine.attribute_attack(traces, graph)
        return attribution
    except Exception as e:
        logger.error(f"Error attributing attack: {str(e)}")
        raise HTTPException(status_code=500, detail="Error attributing attack")

@app.get("/attribution/history")
async def get_attribution_history(limit: int = 10) -> List[Dict[str, Any]]:
    """Get attribution history."""
    if not attribution_engine:
        raise HTTPException(
            status_code=503,
            detail="System initializing - attribution engine not ready"
        )
    try:
        history = attribution_engine.get_attribution_history(limit)
        return history
    except Exception as e:
        logger.error(f"Error getting attribution history: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting attribution history")

@app.get("/attribution/{attribution_id}")
async def get_attribution_by_id(attribution_id: str) -> Dict[str, Any]:
    """Get attribution by ID."""
    if not attribution_engine:
        raise HTTPException(
            status_code=503,
            detail="System initializing - attribution engine not ready"
        )
    try:
        attribution = attribution_engine.get_attribution_by_id(attribution_id)
        if not attribution:
            raise HTTPException(status_code=404, detail="Attribution not found")
        return attribution
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting attribution: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting attribution")

@app.post("/geolocation/lookup")
async def lookup_ip_geolocation(ip_data: Dict[str, Any]) -> Dict[str, Any]:
    """Look up geolocation for an IP address."""
    if not attribution_engine:
        raise HTTPException(
            status_code=503,
            detail="System initializing - attribution engine not ready"
        )
    try:
        ip_address = ip_data.get("ip_address")
        if not ip_address:
            raise HTTPException(status_code=400, detail="IP address is required")
            
        geolocation = attribution_engine.geolocation.get_geolocation(ip_address)
        return geolocation
    except Exception as e:
        logger.error(f"Error looking up IP geolocation: {str(e)}")
        raise HTTPException(status_code=500, detail="Error looking up IP geolocation")

@app.get("/monitoring/status")
async def get_monitoring_status() -> Dict[str, Any]:
    """Get real-time monitoring status."""
    if not real_time_monitor:
        raise HTTPException(
            status_code=503,
            detail="System initializing - real-time monitor not ready"
        )
    try:
        status = real_time_monitor.get_monitoring_status()
        return status
    except Exception as e:
        logger.error(f"Error getting monitoring status: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting monitoring status")

@app.post("/monitoring/start")
async def start_monitoring() -> Dict[str, Any]:
    """Start real-time monitoring."""
    if not real_time_monitor:
        raise HTTPException(
            status_code=503,
            detail="System initializing - real-time monitor not ready"
        )
    try:
        real_time_monitor.start_monitoring()
        return {"status": "monitoring_started"}
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail="Error starting monitoring")

@app.post("/monitoring/stop")
async def stop_monitoring() -> Dict[str, Any]:
    """Stop real-time monitoring."""
    if not real_time_monitor:
        raise HTTPException(
            status_code=503,
            detail="System initializing - real-time monitor not ready"
        )
    try:
        real_time_monitor.stop_monitoring()
        return {"status": "monitoring_stopped"}
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail="Error stopping monitoring")

@app.get("/alerts")
async def get_alerts(limit: int = 100, severity: str = None, alert_type: str = None) -> List[Dict[str, Any]]:
    """Get recent alerts."""
    if not real_time_monitor or not real_time_monitor.alert_manager:
        raise HTTPException(
            status_code=503,
            detail="System initializing - alert manager not ready"
        )
    try:
        alerts = real_time_monitor.get_recent_alerts(limit, severity, alert_type)
        return alerts
    except Exception as e:
        logger.error(f"Error getting alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting alerts")

@app.post("/alerts/clear")
async def clear_alerts() -> Dict[str, Any]:
    """Clear all alerts."""
    if not real_time_monitor or not real_time_monitor.alert_manager:
        raise HTTPException(
            status_code=503,
            detail="System initializing - alert manager not ready"
        )
    try:
        real_time_monitor.alert_manager.clear_alerts()
        return {"status": "alerts_cleared"}
    except Exception as e:
        logger.error(f"Error clearing alerts: {str(e)}")
        raise HTTPException(status_code=500, detail="Error clearing alerts")

@app.get("/dashboard")
async def get_dashboard_url() -> Dict[str, Any]:
    """Get the URL for the alert dashboard."""
    if not alert_dashboard:
        raise HTTPException(
            status_code=503,
            detail="System initializing - alert dashboard not ready"
        )
    try:
        config = load_config().get("alert_dashboard", {})
        host = config.get("host", "127.0.0.1")
        port = config.get("port", 8080)
        return {
            "dashboard_url": f"http://{host}:{port}",
            "status": "running" if alert_dashboard.running else "stopped"
        }
    except Exception as e:
        logger.error(f"Error getting dashboard URL: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting dashboard URL")
