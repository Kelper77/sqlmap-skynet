#!/usr/bin/env python3
"""
SQLMAP SKYNET v1.0.0 - Automation with RAG Memory, Web Search, and Local File Browser
"""

import os
import sys
import json
import asyncio
import argparse
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.debug_logger import logger
from core.rag_memory import rag_memory
from core.state_manager import state
from scanners.runner import SQLMapRunner
from search.web_search import web_search
from utils.file_browser import file_browser
from core.scan_profiles import list_profiles, get_profile, apply_profile
from core.recon import target_recon
from core.notifications import notifications, NotifyEvent
from core.multi_ai import multi_ai
from core.scan_history import scan_history
from core.xss_scanner import xss_scanner, XSS_PAYLOADS, PayloadVariantGenerator
from core.anonymity import anonymity




# ============================================================================
# CONFIGURATION
# ============================================================================

APP_NAME = "sqlmap-skynet-v2.0.0"
APP_VERSION = "5-04-2026"

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="SQLMap AI Automation with RAG Memory and Web Search"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# CONNECTION MANAGER
# ============================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WS", f"Client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WS", f"Client disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send msg to spec client also error handling"""
        try:
            await websocket.send_json(message)
            return True
        except WebSocketDisconnect:
            logger.debug("WS", "Client disconnected during personal send")
            self.disconnect(websocket)
            return False
        except RuntimeError as e:
            if "disconnected" in str(e).lower():
                logger.debug("WS", "Client disconnected (RuntimeError)")
                self.disconnect(websocket)
                return False
            raise
        except Exception as e:
            logger.error("WS", f"Personal send error: {e}")
            self.disconnect(websocket)
            return False
    
    async def broadcast(self, message: dict):
        """Broadcast to all connected clients, removing disconnected ones in real time"""
        disconnected = []
        
        for connection in self.active_connections[:]:  # Copy list
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except RuntimeError as e:
                if "disconnected" in str(e).lower():
                    disconnected.append(connection)
                else:
                    logger.error("WS", f"Broadcast RuntimeError: {e}")
                    disconnected.append(connection)
            except Exception as e:
                logger.error("WS", f"Broadcast error: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
        
        if disconnected:
            logger.debug("WS", f"Removed {len(disconnected)} disconnected clients")

manager = ConnectionManager()

# ============================================================================
# STATE MANAGEMENT
# ============================================================================

async def broadcast_state(msg_type, payload=None):
    """Helper to broadcast state updates - handles both calling conventions"""
    # Handle both:
    #   broadcast_state("type", {"key": "value"})  <- separate args
    #   broadcast_state({"type": "...", "payload": {...}})  <- single dict
    if payload is None and isinstance(msg_type, dict):
        # Single dict argument style
        await manager.broadcast(msg_type)
    else:
        # Separate arguments style
        await manager.broadcast({"type": msg_type, "payload": payload})
    # await state.broadcast(msg_type, payload)

    
    # await manager.broadcast({"type": msg_type, "payload": payload})

# Override state broadcast to use our manager
state.broadcast = broadcast_state

# ============================================================================
# SCANNER TASK
# ============================================================================

current_runner: Optional[SQLMapRunner] = None
CURRENT_BACKEND: str = "sqlmap.py"


async def start_scan(params: dict):
    """Start Executing SQLMap Scan with profiles, recon, notifications, and history."""
    global current_runner, CURRENT_BACKEND
    
    try:
        state.running = True
        await broadcast_state("stats", {"running": True})

        urls = params.get('targets', [params.get('target', '')])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.splitlines() if u.strip()]
        urls = [u for u in urls if u]

        method = params.get('method', 'GET')
        max_cycles = params.get('max_cycles', 30)
        cookies = params.get('cookies', '')
        data = params.get('data', '')
        headers = params.get('headers', '')
        
        # Add tor, rag, and web_search parameters
        tor = params.get('tor', False)
        rag = params.get('rag', True)
        web_search_enabled = params.get('web_search', False)

        # ── Scan Profile support ──
        profile_name = params.get('profile', '')
        if profile_name:
            profile_opts = apply_profile(profile_name)
            if profile_opts:
                max_cycles = profile_opts.get('max_cycles', max_cycles)
                tor = profile_opts.get('tor', tor)
                await broadcast_state("terminal", {
                    "level": "info",
                    "line": f"[PROFILE] Applied '{profile_name}' — level={profile_opts.get('level')}, "
                            f"risk={profile_opts.get('risk')}, threads={profile_opts.get('threads')}, "
                            f"delay={profile_opts.get('delay')}, tamper={profile_opts.get('tamper')}"
                })
        
        backend = params.get('backend') or CURRENT_BACKEND
        if backend not in ('sqlmap.py'):
            backend = 'sqlmap.py'
        CURRENT_BACKEND = backend

        # Debug Fail and Info Configuration
        logger.info("MAIN", f"Scan config - Tor: {tor}, RAG: {rag}, Web Search: {web_search_enabled}, Profile: {profile_name or 'none'}")
        await broadcast_state("terminal", {
            "level": "info",
            "line": f"[*] Configuration: Tor={tor}, RAG={rag}, Web Search={web_search_enabled}"
        })

        # ── Pre-scan Recon ──
        recon_data = None
        run_recon = params.get('recon', False)
        if run_recon and urls:
            await broadcast_state("terminal", {
                "level": "info",
                "line": f"[RECON] Running target reconnaissance on {urls[0]}..."
            })
            try:
                recon_data = await target_recon.full_recon(urls[0])
                await broadcast_state("recon", recon_data)
                await broadcast_state("terminal", {
                    "level": "success",
                    "line": f"[RECON] Complete — Tech: {recon_data.get('tech_stack', [])}, "
                            f"WAF: {recon_data.get('waf_indicators', [])}, "
                            f"Risk: {recon_data.get('risk_score', 0)}/100"
                })
                if recon_data.get('recommendations'):
                    for rec in recon_data['recommendations']:
                        await broadcast_state("terminal", {
                            "level": "learning",
                            "line": f"[RECON TIP] {rec}"
                        })
            except Exception as e:
                logger.error("MAIN", f"Recon failed: {e}")

        # ── Notifications: scan start ──
        await notifications.notify(NotifyEvent.SCAN_START, {
            "target": urls[0] if urls else "unknown",
            "method": method,
            "profile": profile_name or "custom",
        })

        # Create runner with all parameters
        current_runner = SQLMapRunner(
            backend_type=backend,
            use_tor=tor,
            use_rag=rag,
            use_web_search=web_search_enabled
        )
        
        # Help UI show accurate progress
        try:
            current_runner.results['max_cycles'] = int(max_cycles)
        except Exception:
            pass
        
        # RUN Scanning with all options
        logger.debug("MAIN", f"About to call run_multiple with urls={urls}")
        logger.debug("MAIN", f"runner.running={getattr(current_runner, 'running', None)} state.running={state.running}")

        await current_runner.run_multiple(
            urls=urls,
            method=method,
            cookies=cookies,
            max_cycles=max_cycles,
            data=data,
            headers=headers,
            tor=tor,
            rag=rag,
            web_search=web_search_enabled
        )

        # ── Post-scan: Record history & notify ──
        if current_runner:
            import time
            duration = 'N/A'
            if current_runner.session_start_time:
                elapsed = time.time() - current_runner.session_start_time
                duration = f"{elapsed:.1f}s"

            scan_history.record_scan(
                session_id=current_runner.session_id or 'unknown',
                target=urls[0] if urls else 'unknown',
                results=current_runner.results,
                profile=profile_name or 'custom',
                duration=duration,
                recon_data=recon_data,
            )

            await notifications.notify(NotifyEvent.SCAN_COMPLETE, {
                "target": urls[0] if urls else "unknown",
                "injection_found": current_runner.results.get('injection_found', False),
                "databases": len(current_runner.results.get('databases', [])),
                "tables": sum(len(t) for t in current_runner.results.get('tables', {}).values()),
                "cycles": current_runner.results.get('cycles', 0),
                "duration": duration,
            })

            if current_runner.results.get('injection_found'):
                await notifications.notify(NotifyEvent.VULN_FOUND, {
                    "target": urls[0] if urls else "unknown",
                    "technique": ', '.join(current_runner.results.get('techniques', [])),
                    "dbms": current_runner.results.get('dbms_detected', 'Unknown'),
                })
                
    except Exception as e:
        logger.error("MAIN", f"Scan error: {e}")
        await broadcast_state("terminal", {
            "level": "error",
            "line": f"[!] Scan failed: {str(e)}"
        })
        await notifications.notify(NotifyEvent.ERROR, {
            "target": urls[0] if urls else "unknown",
            "error": str(e),
        })
    finally:
        current_runner = None
        state.running = False
        await broadcast_state("stats", {"running": False})

# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    global CURRENT_BACKEND

    try:
        while True:
            # Receive message from client with real time 
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                action = message.get('action')
                
                logger.debug("WS", f"Received action: {action}")
                
                # Handle different actions
                if action == 'start':
                    if not state.running:
                        # Ensure selected backend is used even if UI sends backend separately
                        message['backend'] = message.get('backend') or CURRENT_BACKEND
                        asyncio.create_task(start_scan(message))
                        await manager.send_personal_message({
                            "type": "terminal",
                            "payload": {"level": "info", "line": f"[*] Starting scan... (backend={message.get('backend')})"}
                        }, websocket)
                    else:
                        await manager.send_personal_message({
                            "type": "error",
                            "payload": {"line": "Scan already running"}
                        }, websocket)
                
                elif action == 'stop':
                    if current_runner:
                        await current_runner.stop()
                        await manager.send_personal_message({
                            "type": "terminal",
                            "payload": {"level": "info", "line": "[*] Stop requested"}
                        }, websocket)
                    else:
                        await manager.send_personal_message({
                            "type": "terminal",
                            "payload": {"level": "warning", "line": "[!] No scan running"}
                        }, websocket)
                
                elif action == 'tor':
                    enabled = message.get('enabled', False)
                    logger.info("WS", f"Tor toggled: {enabled}")
                    # Store tor preference in state for next scan
                    state.tor_enabled = enabled
                    await manager.send_personal_message({
                        "type": "terminal",
                        "payload": {"level": "info", "line": f"[*] Tor {'enabled' if enabled else 'disabled'}"}
                    }, websocket)
                
                elif action == 'rag':
                    enabled = message.get('enabled', True)
                    logger.info("WS", f"RAG toggled: {enabled}")
                    state.rag_enabled = enabled
                    await manager.send_personal_message({
                        "type": "terminal",
                        "payload": {"level": "info", "line": f"[*] RAG {'enabled' if enabled else 'disabled'}"}
                    }, websocket)
                
                elif action == 'web_search_toggle':
                    enabled = message.get('enabled', False)
                    logger.info("WS", f"Web search toggled: {enabled}")
                    state.web_search_enabled = enabled
                    await manager.send_personal_message({
                        "type": "terminal",
                        "payload": {"level": "info", "line": f"[*] Web Search {'enabled' if enabled else 'disabled'}"}
                    }, websocket)
                
                elif action == 'backend':
                    backend_type = message.get('type', 'sqlmap.py')
                    if backend_type not in ('sqlmap.py'):
                        backend_type = 'sqlmap.py'
                    CURRENT_BACKEND = backend_type
                    logger.info("WS", f"Backend switched: {backend_type}")
                    await manager.send_personal_message({
                        "type": "terminal",
                        "payload": {"level": "info", "line": f"[*] Backend: {backend_type}"}
                    }, websocket)
                
                elif action == 'web_search':
                    api = message.get('api', '')
                    enabled = message.get('enabled', False)
                    api_key = message.get('api_key', '')
                    web_search.configure(api, enabled, api_key)
                    logger.info("WS", f"Web search {api}: {enabled}")
                
                elif action == 'browse_files':
                    path = message.get('path', '.')
                    result = file_browser.browse_directory(path)
                    await manager.send_personal_message({
                        "type": "file_browser",
                        "payload": result
                    }, websocket)
                
                elif action == 'get_quick_access':
                    locations = file_browser.get_quick_access()
                    await manager.send_personal_message({
                        "type": "quick_access",
                        "payload": {"locations": locations}
                    }, websocket)
                
                elif action == 'load_target_file':
                    filepath = message.get('filepath', '')
                    result = file_browser.load_target_file(filepath)
                    await manager.send_personal_message({
                        "type": "target_file_loaded",
                        "payload": result
                    }, websocket)
                
                elif action == 'get_memory_stats':
                    # sessions = len(rag_memory.sessions)
                    sessions = len(rag_memory.memory.get('sessions', []))
                    await manager.send_personal_message({
                        "type": "memory_stats",
                        "payload": {"sessions": sessions}
                    }, websocket)
                
                elif action == 'get_search_stats':
                    stats = {
                        'total_searches': getattr(web_search, 'total_searches', 0),
                        'learned_patterns': len(getattr(web_search, 'learned_patterns', [])),
                        'apis_enabled': [k for k, v in getattr(web_search, 'apis', {}).items() if v.get('enabled')],
                        'recent_queries': getattr(web_search, 'recent_queries', [])[-5:]
                    }
                    await manager.send_personal_message({
                        "type": "search_stats",
                        "payload": stats
                    }, websocket)
                
                elif action == 'load_memory':
                    # Send recent sessions (support both .sessions and memory['sessions'])
                    sessions = getattr(rag_memory, 'sessions', None)
                    if sessions is None:
                        sessions = rag_memory.memory.get('sessions', []) if hasattr(rag_memory, 'memory') else []
                    recent = sessions[-10:] if sessions else []
                    for sess in recent:
                        await manager.send_personal_message({
                            "type": "memory",
                            "payload": {
                                "category": f"Session {sess.get('id', 'unknown')[:8]}",
                                "content": f"{sess.get('target', 'unknown')} | {sess.get('status', 'unknown')} | DBs: {sess.get('dbs', 0)}"
                            }
                        }, websocket)
                
                else:
                    logger.warning("WS", f"Unknown action: {action}")
                    
            except json.JSONDecodeError:
                logger.error("WS", "Invalid JSON received")
                await manager.send_personal_message({
                    "type": "error",
                    "payload": {"line": "Invalid JSON"}
                }, websocket)
                
            except WebSocketDisconnect:
                # Client disconnected - break to clean up
                logger.info("WS", "Client disconnected (WebSocketDisconnect)")
                break
                
            except Exception as e:
                logger.error("WS", f"Error handling message: {e}")
                # Continue processing other messages, don't break on minor errors
                continue
                
    except WebSocketDisconnect:
        logger.info("WS", "WebSocket disconnected (outer)")
    except Exception as e:
        logger.error("WS", f"WebSocket error: {e}")
    finally:
        # Always clean up
        manager.disconnect(websocket)

# ============================================================================
# HTTP ENDPOINTS
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    #Serve main dashboard 

    dashboard_path = Path(__file__).parent / "templates" / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(dashboard_path)
    else:
        return HTMLResponse("<h1>Dashboard not found</h1><p>Place dashboard.html in templates/</p>")

@app.get("/api/stats")
async def get_stats():
    #Get current scan statistics
    if current_runner:
        return {
            "running": state.running,
            "target": current_runner.target_url,
            "cycles": current_runner.results.get('cycles', 0),
            "databases": len(current_runner.results.get('databases', [])),
            "tables": sum(len(t) for t in current_runner.results.get('tables', {}).values()),
            "columns": sum(len(c) for c in current_runner.results.get('columns', {}).values()),
            "dumps": len(current_runner.results.get('dumps', [])),
            "waf_detected": current_runner.results.get('waf_detected'),
            "progress": (
                min(100, (current_runner.results.get('cycles', 0) / max(1, current_runner.results.get('max_cycles', 30))) * 100)
            ) if current_runner else 0,
            "tor_enabled": getattr(state, 'tor_enabled', False),
            "rag_enabled": getattr(state, 'rag_enabled', True),
            "web_search_enabled": getattr(state, 'web_search_enabled', False)
        }
    else:
        return {
            "running": False,
            "target": None,
            "cycles": 0,
            "databases": 0,
            "tables": 0,
            "columns": 0,
            "dumps": 0,
            "waf_detected": None,
            "progress": 0,
            "tor_enabled": getattr(state, 'tor_enabled', False),
            "rag_enabled": getattr(state, 'rag_enabled', True),
            "web_search_enabled": getattr(state, 'web_search_enabled', False)
        }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": APP_VERSION,
        "running": state.running,
        "connections": len(manager.active_connections)
    }

# ============================================================================
# SCAN PROFILES API
# ============================================================================

@app.get("/api/profiles")
async def get_profiles():
    """List all available scan profiles."""
    return {"profiles": list_profiles()}

@app.get("/api/profiles/{profile_id}")
async def get_profile_detail(profile_id: str):
    """Get detailed info for a specific scan profile."""
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return {
        "id": profile_id,
        "name": profile.name,
        "description": profile.description,
        "level": profile.level,
        "risk": profile.risk,
        "threads": profile.threads,
        "delay": profile.delay,
        "timeout": profile.timeout,
        "technique": profile.technique,
        "tamper": profile.tamper,
        "max_cycles": profile.max_cycles,
        "tor_recommended": profile.tor_recommended,
        "options": profile.options,
    }

# ============================================================================
# RECON API
# ============================================================================

@app.get("/api/recon")
async def run_recon(url: str = Query(..., description="Target URL to recon")):
    """Run full target reconnaissance."""
    result = await target_recon.full_recon(url)
    return result

@app.get("/api/recon/last")
async def get_last_recon():
    """Get the last recon result."""
    return target_recon.results or {"message": "No recon data yet"}

# ============================================================================
# NOTIFICATIONS API
# ============================================================================

@app.get("/api/notifications/channels")
async def get_notification_channels():
    """List configured notification channels."""
    return {"channels": notifications.list_channels()}

@app.post("/api/notifications/test")
async def test_notification():
    """Send a test notification to all channels."""
    await notifications.notify(NotifyEvent.SCAN_START, {
        "target": "test-notification",
        "method": "GET",
        "profile": "test",
    })
    return {"status": "sent"}

@app.get("/api/notifications/history")
async def get_notification_history():
    """Get notification history."""
    return {"history": notifications.history[-50:]}

# ============================================================================
# MULTI-AI CONSENSUS API
# ============================================================================

@app.get("/api/ai/providers")
async def get_ai_providers():
    """List available AI providers for consensus."""
    return {"providers": multi_ai.available_providers}

@app.get("/api/ai/consensus/history")
async def get_consensus_history():
    """Get multi-AI consensus history."""
    return {"history": multi_ai.consensus_history[-20:]}

# ============================================================================
# SCAN HISTORY API
# ============================================================================

@app.get("/api/history")
async def get_scan_history(
    limit: int = Query(50, ge=1, le=500),
    target: str = Query('', description="Filter by target"),
    status: str = Query('', description="Filter by status")
):
    """Get scan history."""
    return {
        "scans": scan_history.get_history(limit, target, status),
        "stats": scan_history.get_stats(),
    }

@app.get("/api/history/{session_id}")
async def get_scan_detail(session_id: str):
    """Get details of a specific scan."""
    scan = scan_history.get_scan(session_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/api/history/compare/{id1}/{id2}")
async def compare_scans(id1: str, id2: str):
    """Compare two scan sessions."""
    return scan_history.compare_scans(id1, id2)

@app.get("/api/history/trends/{target:path}")
async def get_target_trends(target: str):
    """Get trend analysis for a target."""
    return scan_history.get_target_trends(target)


# ============================================================================
# XSS SCANNER ENDPOINTS
# ============================================================================

@app.get("/api/xss/payloads")
async def get_xss_payloads():
    """List all available XSS payload categories."""
    return {cat: len(payloads) for cat, payloads in XSS_PAYLOADS.items()}

@app.post("/api/xss/scan")
async def start_xss_scan(params: dict):
    """Start an XSS scan against a target."""
    url = params.get("url", "")
    param = params.get("param", "")
    if not url or not param:
        raise HTTPException(status_code=400, detail="url and param are required")

    xss_scanner.set_broadcast(broadcast_state)
    asyncio.create_task(xss_scanner.run_scan(
        url=url,
        param=param,
        method=params.get("method", "GET"),
        cookies=params.get("cookies", ""),
        delay=float(params.get("delay", 3.0)),
        auto_chain=params.get("auto_chain", False),
        use_tor=params.get("tor", False),
        categories=params.get("categories"),
    ))
    return {"status": "started", "target": url, "param": param}

@app.post("/api/xss/stop")
async def stop_xss_scan():
    """Stop the running XSS scan."""
    xss_scanner.stop()
    return {"status": "stopped"}

@app.get("/api/xss/results")
async def get_xss_results():
    """Get the latest XSS scan results."""
    return xss_scanner._build_summary()

@app.post("/api/xss/variants")
async def generate_xss_variants(params: dict):
    """Generate and test payload variants."""
    payload = params.get("payload", "")
    url = params.get("url", "")
    param = params.get("param", "")
    if not payload or not url or not param:
        raise HTTPException(status_code=400, detail="payload, url, and param are required")

    results = await xss_scanner.generate_and_test_variants(
        url=url, param=param, payload=payload,
        method=params.get("method", "GET"),
        cookies=params.get("cookies", ""),
    )
    return {"variants": results}


# ============================================================================
# ANONYMITY ENDPOINTS
# ============================================================================

@app.get("/api/anonymity/status")
async def get_anonymity_status():
    """Get current anonymity status."""
    return anonymity.get_status()

@app.post("/api/anonymity/tor/enable")
async def enable_tor():
    """Enable Tor for anonymous scanning."""
    success = anonymity.enable_tor()
    return {"enabled": success, "status": anonymity.get_status()}

@app.post("/api/anonymity/tor/disable")
async def disable_tor():
    """Disable Tor."""
    anonymity.disable_tor()
    return {"enabled": False, "status": anonymity.get_status()}


# ============================================================================
# STATIC FILES
# ============================================================================

# Mount static files if directory exists
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=static_path), name="static")

# ============================================================================
# MAIN ENTRY
# ============================================================================
import re

def print_banner(port: int, backend: str, debug: bool):
    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    WHITE = "\033[37m"
    DIM = "\033[2m"
    
    # Fixed width for the box
    width = 70
    inner_width = width  
    
    # Helper to strip ANSI codes for length calculation
    def strip_ansi(text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    # Helper to center text (accounting for ANSI codes)
    def center(text, w=inner_width):
        visible_len = len(strip_ansi(text))
        padding = (w - visible_len) // 2
        return " " * padding + text + " " * (w - visible_len - padding)
    
    # Helper to left align with padding (accounting for ANSI codes)
    def left(text, w=inner_width):
        visible_len = len(strip_ansi(text))
        return text + " " * (w - visible_len)
    
    # Build banner line by line
    lines = []
    lines.append(f"{CYAN}╔" + "═" * width + f"╗{RESET}")
    lines.append(f"{CYAN}║{RESET}" + center(f"{BOLD}{WHITE}SQLMAP Skynet Autonomous AI v2.0.0{RESET} {BOLD}{YELLOW}by Forums DRCrypter.ru{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + center(f"{GREEN}Scan Profiles • Recon • Multi-AI Consensus • SARIF{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + center(f"{GREEN}Notifications • Scan History • RAG • WAF Bypass AI{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + " " * inner_width + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"  {CYAN}BACKEND:{RESET} {GREEN}{backend}{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"  {CYAN}DEBUG:{RESET}   {RED if debug else DIM}{'Enabled' if debug else 'Disabled'}{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"  {CYAN}PORT:{RESET}    {YELLOW}{port}{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + " " * inner_width + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"  {BOLD}{WHITE}API ENDPOINTS:{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {YELLOW}•{RESET} {BLUE}http://0.0.0.0:{port}/api/stats{RESET}    {DIM}(Enumeration data){RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {YELLOW}•{RESET} {BLUE}http://0.0.0.0:{port}/api/health{RESET}   {DIM}(Health check){RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {YELLOW}•{RESET} {MAGENTA}ws://0.0.0.0:{port}/ws{RESET}             {DIM}(WebSocket){RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + " " * inner_width + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"  {BOLD}{WHITE}FEATURES:{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {GREEN}• Scan Profiles (Stealth/Balanced/Aggressive/Deep/Speed/WAF){RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {GREEN}• Target Recon • Multi-AI Consensus • SARIF Reports{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {GREEN}• Discord/Telegram/Webhook Alerts • Scan History & Diff{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + left(f"    {GREEN}• Web Search (7 engines) • RAG Memory • WAF Bypass AI{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + " " * inner_width + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}║{RESET}" + center(f"{BOLD}{YELLOW}Dashboard: http://0.0.0.0:{port}{RESET}") + f"{CYAN}║{RESET}")
    lines.append(f"{CYAN}╚" + "═" * width + f"╝{RESET}")
    
    print("\n" + "\n".join(lines) + "\n")

def main():
    parser = argparse.ArgumentParser(description='SKYNET Neural Core v16')
    parser.add_argument('--port', type=int, default=1337, help='Port to run on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    #=======================#
    parser.add_argument('--mcp', action='store_true', help='Auto-start MCP server with the dashboard')
    parser.add_argument('--mcp-host', type=str, default='127.0.0.1', help='MCP host')
    parser.add_argument('--mcp-port', type=int, default=8055, help='MCP port')
        
    args = parser.parse_args()

    
    
    # Backend is hardcoded to sqlmap.py
    global CURRENT_BACKEND
    CURRENT_BACKEND = "sqlmap.py"

    if args.mcp:
        import threading

        def _run_mcp():
            # IMPORTANT: your mcp/server.py must expose `mcp` at module level
            from mcp.server import mcp
            mcp.run(transport="http", host=args.mcp_host, port=args.mcp_port)

        threading.Thread(target=_run_mcp, daemon=True).start()
        print(f"[MCP] ✅ Running on http://{args.mcp_host}:{args.mcp_port}/mcp")
    
    # Configure logging
    if args.debug:
        logger.enabled = True
        logger.min_level = 'DEBUG'
    
    # Print banner or logo
    print_banner(args.port, CURRENT_BACKEND, args.debug)
    
    # Init components
    logger.info("MAIN", "Initializing components...")
    
    # Check sqlmap
    from scanners.sqlmap_backend import SQLMapBackend
    backend = SQLMapBackend(CURRENT_BACKEND)
    
    if not Path(backend.sqlmap_path).exists():
        logger.error("MAIN", f"sqlmap not found at {backend.sqlmap_path}")
        print(f"\n[!] ERROR: sqlmap.py not found!")
        print(f"    Please install sqlmap: git clone https://github.com/sqlmapproject/sqlmap.git ")
        sys.exit(1)
    
    
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info" if args.debug else "warning"
    )
if __name__ == "__main__":
    main()