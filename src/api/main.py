"""FastAPI main application for TR4C3R Web Dashboard.

Provides REST API endpoints for OSINT searches, result visualization,
and real-time updates via WebSockets.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from src.core.config import get_config
from src.core.correlation import CorrelationEngine
from src.core.data_models import Result
from src.core.logging_setup import (
    configure_comprehensive_logging,
    AuditLogger,
    PerformanceLogger,
    log_performance,
)
from src.search.email import EmailSearch
from src.search.name import NameSearch
from src.search.phone import PhoneSearch
from src.search.social import SocialMediaSearch
from src.search.username import UsernameSearch
from src.storage.database import Database
from src.visualization.graph_exporter import GraphExporter
from src.api.mobile import (
    MobileSearchRequest,
    MobileSearchResponse,
    MobileResult,
    ThreatFeedRequest,
    ThreatFeedResponse,
    ThreatIndicator,
    ThreatIntelligenceFeed,
    PushNotification,
    PushSubscription,
    PushPreferences,
    PushNotificationManager,
    OfflineSyncRequest,
    OfflineSyncResponse,
    OfflineCache,
    OfflineManager,
    ThreatLevel,
    ThreatCategory,
    NotificationType,
)

logger = logging.getLogger(__name__)

# Global logging instances
audit_logger: Optional[AuditLogger] = None
performance_logger: Optional[PerformanceLogger] = None

# Get config for lifespan
config = get_config()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown events."""
    global audit_logger, performance_logger

    # === STARTUP ===
    log_dir = Path(config.get("logging.directory", "logs"))
    log_level_str = config.get("logging.level", "INFO")
    log_level = getattr(logging, log_level_str, logging.INFO)
    use_json = config.get("logging.json_format", False)

    audit_logger, performance_logger = configure_comprehensive_logging(
        log_dir=log_dir,
        level=log_level,
        use_json=use_json,
        console_output=True,
    )

    logger.info("TR4C3R API starting up...")
    logger.info(f"Database: {config.get('database.path', './tr4c3r.db')}")
    logger.info(f"Logging directory: {log_dir}")
    logger.info("Mobile API endpoints enabled")
    logger.info("API ready!")

    yield  # Application runs here

    # === SHUTDOWN ===
    logger.info("TR4C3R API shutting down...")


# FastAPI app with lifespan
app = FastAPI(
    title="TR4C3R OSINT API",
    description="Open Source Intelligence gathering and correlation API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global instances (config already initialized above for lifespan)
db = Database(config.get("database.path", "./tr4c3r.db"))
correlation_engine = CorrelationEngine(
    min_confidence=config.get("correlation.min_confidence", 0.5),
    max_depth=config.get("correlation.max_depth", 3),
)
graph_exporter = GraphExporter()

# Mobile-specific managers
threat_feed = ThreatIntelligenceFeed()
push_manager = PushNotificationManager()
offline_manager = OfflineManager()


# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to websocket: {e}")


manager = ConnectionManager()


# Pydantic models
class SearchRequest(BaseModel):
    """Search request model."""

    identifier: str = Field(..., description="Identifier to search for")
    search_type: str = Field(
        ..., description="Type of search: email, phone, name, username, social"
    )
    max_variants: Optional[int] = Field(10, description="Maximum variants for fuzzy search")


class SearchResponse(BaseModel):
    """Search response model."""

    search_id: int
    identifier: str
    search_type: str
    result_count: int
    timestamp: datetime
    results: List[Dict[str, Any]]


class CorrelationRequest(BaseModel):
    """Correlation analysis request."""

    search_ids: List[int] = Field(..., description="Search IDs to correlate")
    min_confidence: Optional[float] = Field(0.5, ge=0.0, le=1.0)
    max_depth: Optional[int] = Field(3, ge=1, le=5)


class ExportRequest(BaseModel):
    """Export request model."""

    search_id: int
    format: str = Field(..., description="Export format: json, csv, xml")


class GraphExportRequest(BaseModel):
    """Graph export request."""

    search_ids: List[int]
    format: str = Field(..., description="Graph format: gexf, pyvis, graphml, json")
    output_filename: Optional[str] = None


# Authentication dependency
async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Verify API token.

    In production, implement proper JWT verification or API key validation.
    """
    token = credentials.credentials

    # Simple token check (replace with proper auth in production)
    api_key = config.get("api.auth_token", "demo_token")
    if token != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    return token


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }


# Search endpoints
@app.post("/api/v1/search", response_model=SearchResponse)
async def search(
    request: SearchRequest,
    token: str = Depends(verify_token),
):
    """Perform OSINT search."""
    try:
        logger.info(f"Search request: {request.search_type} for '{request.identifier}'")

        # Extract user_id from token (simplified - real implementation would decode JWT)
        user_id = token[:8] if token else "unknown"

        # Log audit event
        if audit_logger:
            audit_logger.log_search(
                user_id=user_id,
                search_type=request.search_type,
                identifier=request.identifier,
                purpose=request.purpose if hasattr(request, "purpose") else None,
            )

        results = []

        # Perform search based on type with performance logging
        with log_performance(f"search_{request.search_type}"):
            if request.search_type == "email":
                search = EmailSearch()
                results = await search.search(request.identifier)
            elif request.search_type == "phone":
                search = PhoneSearch()
                results = await search.search(request.identifier)
            elif request.search_type == "name":
                search = NameSearch()
                results = await search.search(request.identifier)
            elif request.search_type == "username":
                search = UsernameSearch()
                results = await search.search(request.identifier)
            elif request.search_type == "social":
                search = SocialMediaSearch()
                results = await search.search(request.identifier)
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported search type: {request.search_type}",
                )

        # Save to database
        search_id = db.save_search(
            query=request.identifier,
            search_type=request.search_type,
            results=results,
        )

        # Log results count
        if audit_logger:
            audit_logger.log_search(
                user_id=user_id,
                search_type=request.search_type,
                identifier=request.identifier,
                results_count=len(results),
            )

        # Broadcast to WebSocket clients
        await manager.broadcast(
            {
                "type": "search_complete",
                "search_id": search_id,
                "identifier": request.identifier,
                "result_count": len(results),
            }
        )

        # Convert results to dict
        results_dict = [
            {
                "source": r.source,
                "identifier": r.identifier,
                "url": r.url,
                "confidence": r.confidence,
                "timestamp": r.timestamp.isoformat(),
                "metadata": r.metadata,
            }
            for r in results
        ]

        return SearchResponse(
            search_id=search_id,
            identifier=request.identifier,
            search_type=request.search_type,
            result_count=len(results),
            timestamp=datetime.now(timezone.utc),
            results=results_dict,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Search error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/search/{search_id}")
async def get_search(
    search_id: int,
    token: str = Depends(verify_token),
):
    """Get search by ID."""
    try:
        history = db.get_search_history(limit=100)
        search_info = next((s for s in history if s["id"] == search_id), None)
        if not search_info:
            raise HTTPException(status_code=404, detail="Search not found")

        results = db.get_search_results(search_id)

        return {
            "search": search_info,
            "results": [
                {
                    "source": r.source,
                    "identifier": r.identifier,
                    "url": r.url,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp.isoformat(),
                    "metadata": r.metadata,
                }
                for r in results
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching search: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/searches")
async def list_searches(
    search_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    token: str = Depends(verify_token),
):
    """List recent searches."""
    try:
        history = db.get_search_history(search_type=search_type, limit=limit)
        return {"searches": history, "count": len(history)}

    except Exception as e:
        logger.error(f"Error listing searches: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Correlation endpoints
@app.post("/api/v1/correlate")
async def correlate(
    request: CorrelationRequest,
    token: str = Depends(verify_token),
):
    """Perform correlation analysis on search results."""
    try:
        logger.info(f"Correlation request for searches: {request.search_ids}")

        # Clear existing graph
        correlation_engine.clear()

        # Build graph from all search results
        all_results = []
        for search_id in request.search_ids:
            results = db.get_search_results(search_id)
            all_results.extend(results)

        if not all_results:
            raise HTTPException(status_code=404, detail="No results found")

        correlation_engine.build_graph_from_results(all_results)

        # Get analysis
        stats = correlation_engine.get_statistics()
        clusters = correlation_engine.get_clusters(min_size=2)
        patterns = correlation_engine.find_patterns()

        # Export graph data
        graph_data = correlation_engine.export_graph()

        return {
            "statistics": stats,
            "clusters": [{"nodes": list(c), "size": len(c)} for c in clusters],
            "patterns": {
                "hubs": patterns["hubs"][:10],  # Top 10 hubs
                "bridges": patterns["bridges"][:10],
                "triangles": len(patterns["triangles"]),
                "isolated": len(patterns["isolated"]),
            },
            "graph": graph_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Correlation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/connections")
async def find_connections(
    identifier: str,
    max_depth: int = Query(3, ge=1, le=5),
    token: str = Depends(verify_token),
):
    """Find connections for an identifier."""
    try:
        connections = correlation_engine.find_connections(identifier, max_depth=max_depth)

        return {
            "identifier": identifier,
            "connections": connections,
            "count": len(connections),
        }

    except Exception as e:
        logger.error(f"Error finding connections: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Export endpoints
@app.post("/api/v1/export/search")
async def export_search(
    request: ExportRequest,
    token: str = Depends(verify_token),
):
    """Export search results."""
    try:
        # Extract user_id from token
        user_id = token[:8] if token else "unknown"

        export_format = request.format
        export_content = db.export_search(request.search_id, export_format)

        # Get search results for audit log
        results = db.get_search_results(request.search_id)

        # Log export operation
        if audit_logger:
            audit_logger.log_export(
                user_id=user_id,
                export_format=export_format,
                data_types=["search_results"],
                record_count=len(results),
            )

        # Write to temp file for download
        output_path = f"/tmp/search_{request.search_id}.{export_format}"
        with open(output_path, "w") as f:
            f.write(export_content)

        return FileResponse(
            output_path,
            media_type="application/octet-stream",
            filename=f"search_{request.search_id}.{request.format}",
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/export/graph")
async def export_graph(
    request: GraphExportRequest,
    token: str = Depends(verify_token),
):
    """Export correlation graph."""
    try:
        # Build graph from searches
        all_results = []
        for search_id in request.search_ids:
            results = db.get_search_results(search_id)
            all_results.extend(results)

        correlation_engine.clear()
        correlation_engine.build_graph_from_results(all_results)
        graph_data = correlation_engine.export_graph()

        # Determine output path
        filename = request.output_filename or f"graph.{request.format}"
        output_path = f"/tmp/{filename}"

        # Export based on format
        success = False
        if request.format == "gexf":
            success = graph_exporter.export_to_gephi(graph_data, output_path)
        elif request.format == "pyvis":
            success = graph_exporter.export_to_pyvis(graph_data, output_path)
        elif request.format == "graphml":
            success = graph_exporter.export_to_graphml(graph_data, output_path)
        elif request.format == "json":
            success = graph_exporter.export_to_json(graph_data, output_path)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")

        if not success:
            raise HTTPException(status_code=500, detail="Graph export failed")

        return FileResponse(
            output_path,
            media_type="application/octet-stream",
            filename=filename,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Graph export error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Statistics endpoint
@app.get("/api/v1/stats")
async def get_statistics(token: str = Depends(verify_token)):
    """Get database statistics."""
    try:
        stats = db.get_statistics()
        return stats

    except Exception as e:
        logger.error(f"Error fetching statistics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time search updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back for heartbeat
            await websocket.send_json(
                {"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()}
            )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        manager.disconnect(websocket)


# ============================================================================
# Mobile API Endpoints
# ============================================================================


@app.post("/api/v1/mobile/search", response_model=MobileSearchResponse)
async def mobile_search(
    request: MobileSearchRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Mobile-optimized search endpoint (lightweight responses).

    Provides paginated, reduced-payload results optimized for mobile devices.
    """
    start_time = datetime.now()

    try:
        # Perform search based on type
        results = []

        if request.search_type == "email":
            email_search = EmailSearch()
            search_results = await email_search.search(request.query)
            results = search_results
        elif request.search_type == "phone":
            phone_search = PhoneSearch()
            search_results = await phone_search.search(request.query)
            results = search_results
        elif request.search_type == "username":
            username_search = UsernameSearch()
            search_results = await username_search.search(request.query)
            results = search_results
        elif request.search_type == "name":
            name_search = NameSearch()
            search_results = await name_search.search(request.query)
            results = search_results
        else:
            raise HTTPException(
                status_code=400, detail=f"Invalid search type: {request.search_type}"
            )

        # Convert to mobile results (lightweight)
        mobile_results = []
        for idx, result in enumerate(results[: request.max_results]):
            mobile_result = MobileResult(
                id=f"{request.search_type}_{idx}",
                source=result.source,
                identifier=result.identifier,
                url=result.url,
                confidence=result.confidence,
                snippet=(
                    result.metadata.get("title", result.identifier)[:100]
                    if request.include_metadata
                    else None
                ),
                timestamp=result.timestamp,
            )
            mobile_results.append(mobile_result)

        execution_time = (datetime.now() - start_time).total_seconds()

        # Store in database
        search_id = f"mobile_{datetime.now().timestamp()}"
        db.add_search(
            search_type=request.search_type,
            query=request.query,
            results_count=len(mobile_results),
            metadata={"mobile": True, "max_results": request.max_results},
        )

        return MobileSearchResponse(
            search_id=search_id,
            query=request.query,
            total_results=len(results),
            results=mobile_results,
            has_more=len(results) > request.max_results,
            execution_time=execution_time,
        )

    except Exception as e:
        logger.error(f"Mobile search error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/threat-feed", response_model=ThreatFeedResponse)
async def get_threat_feed(
    request: ThreatFeedRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get threat intelligence feed.

    Provides real-time threat intelligence for OSINT targets.
    """
    try:
        threats = threat_feed.get_threats(
            indicator=request.indicator,
            indicator_types=request.indicator_types,
            threat_levels=request.threat_levels,
            categories=request.categories,
            since=request.since,
            limit=request.limit,
        )

        # Calculate next update time (every 15 minutes)
        next_update = datetime.now() + timedelta(minutes=15)

        return ThreatFeedResponse(
            total_threats=len(threats),
            threats=threats,
            last_updated=threat_feed.last_update,
            next_update=next_update,
        )

    except Exception as e:
        logger.error(f"Threat feed error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/threat-feed/add")
async def add_threat_indicator(
    threat: ThreatIndicator,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Add threat indicator to feed (admin only)."""
    try:
        threat_feed.add_threat(threat)
        return {"status": "success", "message": "Threat indicator added"}

    except Exception as e:
        logger.error(f"Add threat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/threat-feed/check/{indicator_type}/{value}")
async def check_threat_indicator(
    indicator_type: str,
    value: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Check if indicator is in threat feed."""
    try:
        threat = threat_feed.check_indicator(indicator_type, value)

        if threat:
            return {
                "found": True,
                "threat": threat,
            }
        else:
            return {"found": False, "message": "No threat intelligence found for this indicator"}

    except Exception as e:
        logger.error(f"Check threat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/threat-feed/stats")
async def get_threat_stats(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get threat feed statistics."""
    try:
        stats = threat_feed.get_statistics()
        return stats

    except Exception as e:
        logger.error(f"Threat stats error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/push/subscribe")
async def subscribe_push(
    subscription: PushSubscription,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Subscribe device for push notifications."""
    try:
        success = push_manager.subscribe(subscription)
        return {
            "status": "success" if success else "failed",
            "message": "Device subscribed for push notifications",
        }

    except Exception as e:
        logger.error(f"Push subscribe error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/mobile/push/unsubscribe/{user_id}/{device_token}")
async def unsubscribe_push(
    user_id: str,
    device_token: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Unsubscribe device from push notifications."""
    try:
        success = push_manager.unsubscribe(user_id, device_token)
        return {
            "status": "success" if success else "not_found",
            "message": "Device unsubscribed" if success else "Subscription not found",
        }

    except Exception as e:
        logger.error(f"Push unsubscribe error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/push/preferences/{user_id}")
async def set_push_preferences(
    user_id: str,
    preferences: PushPreferences,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Set user push notification preferences."""
    try:
        push_manager.set_preferences(user_id, preferences)
        return {"status": "success", "message": "Push preferences updated"}

    except Exception as e:
        logger.error(f"Push preferences error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/push/preferences/{user_id}")
async def get_push_preferences(
    user_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get user push notification preferences."""
    try:
        preferences = push_manager.get_preferences(user_id)
        return preferences

    except Exception as e:
        logger.error(f"Get push preferences error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/push/send")
async def send_push_notification(
    user_id: str,
    notification: PushNotification,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Send push notification to user (admin/system only)."""
    try:
        count = push_manager.send_notification(user_id, notification)
        return {
            "status": "success",
            "devices_notified": count,
            "message": f"Notification sent to {count} devices",
        }

    except Exception as e:
        logger.error(f"Send push error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/push/notifications/{user_id}")
async def get_push_notifications(
    user_id: str,
    since: Optional[datetime] = None,
    limit: int = Query(default=50, ge=1, le=200),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get push notifications for user."""
    try:
        notifications = push_manager.get_notifications(user_id, since, limit)
        return {
            "total": len(notifications),
            "notifications": notifications,
        }

    except Exception as e:
        logger.error(f"Get push notifications error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/mobile/offline/sync", response_model=OfflineSyncResponse)
async def sync_offline_data(
    request: OfflineSyncRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Sync data for offline use."""
    try:
        cache_entries = offline_manager.sync_data(
            last_sync=request.last_sync,
            cache_keys=request.cache_keys,
            max_size_mb=request.max_size_mb,
        )

        total_size = sum(entry.size_bytes for entry in cache_entries)

        return OfflineSyncResponse(
            sync_id=f"sync_{datetime.now().timestamp()}",
            synced_items=len(cache_entries),
            cache_entries=cache_entries,
            total_size_mb=total_size / 1024 / 1024,
            sync_time=datetime.now(),
            next_sync=datetime.now() + timedelta(hours=24),
        )

    except Exception as e:
        logger.error(f"Offline sync error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/offline/cache/{cache_key}")
async def get_offline_cache(
    cache_key: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get cached data by key."""
    try:
        cache = offline_manager.get_cache(cache_key)

        if not cache:
            raise HTTPException(status_code=404, detail="Cache not found or expired")

        return cache

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get cache error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/mobile/offline/stats")
async def get_offline_stats(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Get offline cache statistics."""
    try:
        stats = offline_manager.get_cache_size()
        return stats

    except Exception as e:
        logger.error(f"Offline stats error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/mobile/offline/cleanup")
async def cleanup_offline_cache(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Cleanup expired cache entries."""
    try:
        removed = offline_manager.cleanup_expired()
        return {
            "status": "success",
            "removed_entries": removed,
            "message": f"Cleaned up {removed} expired cache entries",
        }

    except Exception as e:
        logger.error(f"Cleanup cache error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Note: Startup/Shutdown events are now handled by the lifespan context manager above
