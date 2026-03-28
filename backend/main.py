"""CodeGuardianAI — FastAPI backend.

Endpoints:
  POST /api/auth/login       → JWT token
  GET  /api/auth/status      → auth_required flag
  POST /api/scan             → run scan, returns scan_id + results
  GET  /api/scan/{id}        → get scan result by id
  GET  /api/history          → list recent scans
  POST /api/report/download  → generate TXT or JSON report
  WS   /ws/scan              → WebSocket streaming scan progress
"""

import asyncio
import json
import logging
import os
import uuid
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from .auth import auth_is_required, create_access_token, get_current_user, verify_password
from .core.analyzer import SecurityAnalyzer
from .core.reports import (
    build_json_report,
    extract_vulnerabilities,
    generate_text_report,
    verify_all_vulnerabilities,
)
from .models import (
    AuthStatusResponse,
    LoginRequest,
    LoginResponse,
    ReportRequest,
    ScanRequest,
    ScanResult,
    ScanSummary,
)

load_dotenv()

# ── Logging ──────────────────────────────────────────────────────────────────
_log_config = Path("logging_config.json")
if _log_config.exists():
    import logging.config
    with open(_log_config) as _f:
        logging.config.dictConfig(json.load(_f))
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# ── In-memory scan store (ordered, capped at 200) ───────────────────────────
_scan_store: OrderedDict[str, dict] = OrderedDict()
_MAX_SCANS = 200


def _store_scan(scan_id: str, data: dict):
    _scan_store[scan_id] = data
    while len(_scan_store) > _MAX_SCANS:
        _scan_store.popitem(last=False)


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CodeGuardianAI",
    description="AI-powered code security scanner for penetration testers",
    version="2.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.get("/api/auth/status", response_model=AuthStatusResponse)
async def auth_status():
    """Check whether authentication is required."""
    return {"auth_required": auth_is_required()}


@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate with APP_PASSWORD and receive a JWT token."""
    if not auth_is_required():
        token = create_access_token({"sub": "anonymous"})
        return {"access_token": token, "token_type": "bearer", "auth_required": False}

    if not verify_password(request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
        )

    token = create_access_token({"sub": "user"})
    return {"access_token": token, "token_type": "bearer", "auth_required": True}


# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResult)
async def run_scan(
    request: ScanRequest,
    current_user: dict = Depends(get_current_user),
):
    """Run a security scan on the provided code. Returns full results."""
    if len(request.code) > 200 * 1024:
        raise HTTPException(status_code=400, detail="Code exceeds 200KB limit.")

    scan_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    analyzer = SecurityAnalyzer()
    result = analyzer.analyze_code(
        code=request.code,
        user_query=request.query,
        api_type=request.api_type,
        filename=request.filename,
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message", "Analysis failed"))

    analysis_text = result["analysis"]

    # Optional AI verification pass
    if request.verify:
        try:
            analysis_text = verify_all_vulnerabilities(
                analysis_text, request.api_type, request.confidence
            )
        except Exception as e:
            logger.warning(f"Verification pass failed: {e}")

    vulns = extract_vulnerabilities(analysis_text)

    scan_data = {
        "scan_id": scan_id,
        "status": "complete",
        "analysis": analysis_text,
        "vulnerabilities": vulns,
        "metadata": {
            **result.get("metadata", {}),
            "filename": request.filename,
            "language": analyzer._detect_language(request.code, request.filename),
        },
        "timestamp": timestamp,
        "filename": request.filename,
    }

    _store_scan(scan_id, scan_data)
    return scan_data


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieve a previously completed scan by ID."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_store[scan_id]


@app.get("/api/history")
async def get_history(current_user: dict = Depends(get_current_user)):
    """Return the list of recent scans (summary only, no full analysis text)."""
    summaries = []
    for scan_id, scan in reversed(list(_scan_store.items())):
        vulns = scan.get("vulnerabilities", [])
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            sev = v.get("severity", "")
            if sev in counts:
                counts[sev] += 1

        summaries.append({
            "scan_id": scan_id,
            "filename": scan.get("filename", "unknown"),
            "timestamp": scan.get("timestamp", ""),
            "total_vulns": len(vulns),
            "critical": counts["Critical"],
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"],
            "status": scan.get("status", "unknown"),
        })
    return summaries


# ── Report download ───────────────────────────────────────────────────────────

@app.post("/api/report/download")
async def download_report(
    request: ReportRequest,
    current_user: dict = Depends(get_current_user),
):
    """Generate and return a TXT or JSON report for a completed scan."""
    if request.scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = _scan_store[request.scan_id]
    analysis_text = scan["analysis"]

    if request.format == "json":
        report = build_json_report(analysis_text)
        return JSONResponse(
            content=report,
            headers={
                "Content-Disposition": f'attachment; filename="security_analysis_{request.scan_id[:8]}.json"'
            },
        )
    else:
        content, filename = generate_text_report(analysis_text)
        return PlainTextResponse(
            content=content,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


# ── WebSocket streaming scan ─────────────────────────────────────────────────

@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    """WebSocket endpoint that streams scan progress events.

    Client sends JSON: { code, filename, api_type, confidence, verify, query, token? }
    Server emits progress events then a final 'complete' event with scan results.
    """
    await websocket.accept()

    async def emit(event: str, message: str, progress: int, data: Any = None):
        payload: dict = {"event": event, "message": message, "progress": progress}
        if data is not None:
            payload["data"] = data
        await websocket.send_json(payload)

    try:
        raw = await websocket.receive_text()
        req = json.loads(raw)

        # Auth check via token if required
        if auth_is_required():
            from .auth import decode_token
            token = req.get("token")
            if not token or not decode_token(token):
                await emit("error", "Unauthorized", 0)
                await websocket.close(code=4001)
                return

        code = req.get("code", "")
        filename = req.get("filename", "unknown.txt")
        api_type = req.get("api_type", "openai")
        confidence = req.get("confidence", "Medium")
        verify = req.get("verify", True)
        query = req.get("query", "")

        if not code:
            await emit("error", "No code provided", 0)
            return

        if len(code) > 200 * 1024:
            await emit("error", "Code exceeds 200KB limit", 0)
            return

        # Step 1 — language detection
        await emit("detecting", "Detecting language...", 5)
        await asyncio.sleep(0)

        analyzer = SecurityAnalyzer()
        language = analyzer._detect_language(code, filename)
        lang_label = language or "unknown"

        await emit("detected", f"Language detected: {lang_label}", 15)
        await asyncio.sleep(0)

        # Step 2 — AI analysis
        await emit("analyzing", f"Running AI security analysis ({api_type})...", 25)
        await asyncio.sleep(0)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: analyzer.analyze_code(code, query, api_type, filename),
        )

        if result.get("status") == "error":
            await emit("error", result.get("message", "Analysis failed"), 0)
            return

        analysis_text = result["analysis"]
        await emit("ai_complete", "AI analysis complete", 55)
        await asyncio.sleep(0)

        # Step 3 — deterministic checks (already merged inside analyzer, report progress)
        await emit("deterministic", "Running deterministic pattern checks...", 65)
        await asyncio.sleep(0)

        # Step 4 — verification
        if verify:
            await emit("verifying", f"Verifying findings (confidence: {confidence})...", 75)
            await asyncio.sleep(0)
            try:
                analysis_text = await loop.run_in_executor(
                    None,
                    lambda: verify_all_vulnerabilities(analysis_text, api_type, confidence),
                )
            except Exception as e:
                logger.warning(f"WS verification failed: {e}")
            await emit("verified", "Verification complete", 90)
            await asyncio.sleep(0)

        # Step 5 — finalise
        vulns = extract_vulnerabilities(analysis_text)
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        scan_data = {
            "scan_id": scan_id,
            "status": "complete",
            "analysis": analysis_text,
            "vulnerabilities": vulns,
            "metadata": {
                **result.get("metadata", {}),
                "filename": filename,
                "language": lang_label,
            },
            "timestamp": timestamp,
            "filename": filename,
        }
        _store_scan(scan_id, scan_data)

        await emit("complete", "Scan complete", 100, scan_data)

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except json.JSONDecodeError:
        await emit("error", "Invalid JSON payload", 0)
    except Exception as e:
        logger.error(f"WebSocket scan error: {e}", exc_info=True)
        try:
            await emit("error", f"Scan failed: {str(e)}", 0)
        except Exception:
            pass


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "2.3.0",
        "auth_required": auth_is_required(),
        "openai_configured": bool(os.getenv("OPENAI_API_KEY")),
        "deepseek_configured": bool(os.getenv("DEEPSEEK_API_KEY")),
    }
