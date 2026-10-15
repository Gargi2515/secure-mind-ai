"""FastAPI application for the SecureMind AI security gateway prototype."""
from __future__ import annotations

import hmac
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from functools import wraps
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from .config import settings
from .mcp_gateway import MCPGateway
from .policies import PROFILES, SCHEMAS
from .security import decode_token, detect_prompt_injection, issue_token, mask_sensitive_data, risk_score

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securemind")

# Requests scoring above this level must be approved by a human after all hard
# security, profile-access, and input-schema checks pass.
RISK_APPROVAL_THRESHOLD = 60

app = FastAPI(
    title="SecureMind AI Security Gateway",
    description="A reference gateway for AI-agent tool-call policy enforcement.",
    version="1.1.0",
)
allowed_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
# Small per-process sliding-window limiter: no external rate-limit service is needed
# for local development. Use a shared backend (e.g. Redis) for multi-worker deployments.
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def rate_limited(max_requests: int, window_seconds: int = 60):
    def decorate(endpoint):
        @wraps(endpoint)
        async def wrapped(*args, **kwargs):
            request = kwargs.get("request")
            if request is None:
                request = next((arg for arg in args if isinstance(arg, Request)), None)
            if request is None:
                raise RuntimeError("Rate-limited endpoint must accept a Request")
            remote = request.client.host if request.client else "unknown"
            key = f"{request.url.path}:{remote}"
            now = time.monotonic()
            bucket = _rate_buckets[key]
            while bucket and now - bucket[0] >= window_seconds:
                bucket.popleft()
            if len(bucket) >= max_requests:
                audit("rate_limit_exceeded", remote, path=request.url.path)
                raise HTTPException(status_code=429, detail="Rate limit exceeded; try again later")
            bucket.append(now)
            return await endpoint(*args, **kwargs)
        return wrapped
    return decorate

bearer = HTTPBearer(auto_error=False)
gateway = MCPGateway()
# These stores are intentionally in-memory for a local prototype.
audit_events: list[dict[str, Any]] = []
approvals: dict[str, dict[str, Any]] = {}
metrics: dict[str, int] = {"requests": 0, "blocked": 0, "approvals": 0, "errors": 0, "executed": 0}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)
    profile: str = Field(default="enterprise", min_length=1, max_length=50)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    prompt: str = Field(default="", max_length=12000)


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|reject)$")
    note: str = Field(default="", max_length=1000)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(event: str, user: str = "system", **details: Any) -> None:
    audit_events.append({
        "id": str(uuid.uuid4()),
        "timestamp": now_iso(),
        "event": event,
        "user": user,
        "details": details,
    })
    if len(audit_events) > 2000:
        del audit_events[:500]
    logger.info("audit event=%s user=%s", event, user)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        return decode_token(credentials.credentials)
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired token") from None


def admin_user(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def profile_for(user: dict[str, Any]) -> tuple[str, Any]:
    profile_name = user.get("profile", settings.default_profile)
    if profile_name not in PROFILES:
        raise HTTPException(status_code=400, detail="Unknown industry profile")
    return profile_name, PROFILES[profile_name]


def _schema_error(schema: dict[str, Any], value: Any, path: str = "arguments") -> str | None:
    """Validate the JSON-Schema subset used by the included tools."""
    if not isinstance(schema, dict):
        return None
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            return f"{path} must be an object"
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            return f"missing required arguments: {', '.join(missing)}"
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                return f"unknown arguments: {', '.join(extra)}"
        for key, nested in value.items():
            if key in properties:
                error = _schema_error(properties[key], nested, f"{path}.{key}")
                if error:
                    return error
    elif expected == "string":
        if not isinstance(value, str):
            return f"{path} must be a string"
        if len(value) < schema.get("minLength", 0):
            return f"{path} is too short"
        if len(value) > schema.get("maxLength", 100000):
            return f"{path} is too long"
        pattern = schema.get("pattern")
        if pattern and not __import__("re").search(pattern, value):
            return f"{path} does not match the required pattern"
        if schema.get("enum") is not None and value not in schema["enum"]:
            return f"{path} is not an allowed value"
    elif expected == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return f"{path} must be a number"
        if value < schema.get("minimum", float("-inf")):
            return f"{path} is below the minimum"
        if value > schema.get("maximum", float("inf")):
            return f"{path} is above the maximum"
    elif expected == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return f"{path} must be an integer"
        if value < schema.get("minimum", -10**18):
            return f"{path} is below the minimum"
        if value > schema.get("maximum", 10**18):
            return f"{path} is above the maximum"
    elif expected == "boolean" and not isinstance(value, bool):
        return f"{path} must be a boolean"
    elif expected == "array":
        if not isinstance(value, list):
            return f"{path} must be an array"
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 10000):
            return f"{path} has an invalid number of items"
        if schema.get("items"):
            for index, nested in enumerate(value):
                error = _schema_error(schema["items"], nested, f"{path}[{index}]")
                if error:
                    return error
    return None


def validate_args(schema: dict[str, Any], arguments: Any) -> str | None:
    if not isinstance(arguments, dict):
        return "arguments must be a JSON object"
    return _schema_error(schema or {"type": "object", "properties": {}}, arguments)


def inspection_text(prompt: str, arguments: dict[str, Any]) -> str:
    # Scan strings in arguments as well as the prompt for prompt-injection text.
    return f"{prompt}\n{json.dumps(arguments, ensure_ascii=False, default=str)}"


def public_approval(item: dict[str, Any]) -> dict[str, Any]:
    """Do not expose the raw queued arguments/prompt to dashboard list clients."""
    fields = (
        "id", "status", "user", "profile", "tool_name", "risk_score", "created_at",
        "decided_by", "decision_note", "decided_at", "execution_status", "result_summary",
    )
    return {key: item[key] for key in fields if key in item}


@app.get("/")
async def root():
    return {"name": "SecureMind AI", "status": "running", "docs": "/docs"}


@app.get("/api/health")
async def health():
    return {"status": "ok", "mcp_transport": settings.mcp_transport, "environment": settings.app_env}


@app.post("/api/auth/login")
@rate_limited(10)
async def login(body: LoginRequest, request: Request):
    if not settings.allow_demo_login:
        raise HTTPException(status_code=403, detail="Demo login disabled; copy backend/.env.example to backend/.env and enable ALLOW_DEMO_LOGIN=true for local testing")
    if body.profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Unknown industry profile")
    user_matches = hmac.compare_digest(body.username, settings.demo_username)
    password_matches = hmac.compare_digest(body.password, settings.demo_password)
    if not (user_matches and password_matches):
        audit("login_failed", body.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = issue_token(body.username, settings.demo_role, body.profile)
    audit("login_success", body.username, profile=body.profile)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.jwt_ttl_minutes * 60,
        "profile": body.profile,
        "role": settings.demo_role,
    }


@app.get("/api/me")
async def me(user: dict[str, Any] = Depends(current_user)):
    return {"username": user["sub"], "role": user.get("role", "user"), "profile": user.get("profile", settings.default_profile)}


@app.get("/api/profiles")
async def get_profiles():
    return {
        name: {
            "description": profile.description,
            "allowed_tools": sorted(profile.allowed_tools),
            "approval_tools": sorted(profile.approval_tools),
            "risk_approval_threshold": RISK_APPROVAL_THRESHOLD,
        }
        for name, profile in PROFILES.items()
    }


@app.get("/api/tools")
async def get_tools(user: dict[str, Any] = Depends(current_user)):
    profile_name, profile = profile_for(user)
    try:
        tools = await gateway.list_tools()
    except Exception as exc:
        logger.warning("MCP discovery failed: %s", type(exc).__name__)
        audit("mcp_discovery_error", user["sub"])
        raise HTTPException(status_code=502, detail="MCP tool discovery failed; check MCP transport/server configuration") from None
    return {
        "transport": settings.mcp_transport,
        "profile": profile_name,
        "tools": [
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "connected": True,
                "requires_approval": tool["name"] in profile.approval_tools,
                "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
            }
            for tool in tools
        ],
    }


@app.post("/api/execute")
@rate_limited(settings.rate_limit_per_minute)
async def execute(body: ExecuteRequest, request: Request, user: dict[str, Any] = Depends(current_user)):
    metrics["requests"] += 1
    profile_name, profile = profile_for(user)
    scan_text = inspection_text(body.prompt, body.arguments)
    detected = detect_prompt_injection(scan_text)
    score = risk_score(scan_text, body.tool_name, body.arguments)
    if detected:
        metrics["blocked"] += 1
        audit("prompt_injection_blocked", user["sub"], tool=body.tool_name, risk=score, patterns=detected)
        raise HTTPException(status_code=403, detail={"message": "Potential prompt injection detected", "risk_score": score, "patterns": detected, "blocked": True})

    try:
        tools = await gateway.list_tools()
    except Exception:
        metrics["errors"] += 1
        raise HTTPException(status_code=502, detail="MCP server unavailable") from None
    discovered = next((tool for tool in tools if tool.get("name") == body.tool_name), None)
    if discovered is None or body.tool_name not in profile.allowed_tools:
        metrics["blocked"] += 1
        audit("tool_not_allowed", user["sub"], profile=profile_name, tool=body.tool_name, risk=score)
        raise HTTPException(status_code=403, detail={"message": "Tool is unknown or blocked by the selected profile", "status": "BLOCKED", "tool_name": body.tool_name})

    schema = SCHEMAS.get(body.tool_name) or discovered.get("inputSchema") or {"type": "object", "properties": {}}
    schema_error = validate_args(schema, body.arguments)
    if schema_error:
        metrics["blocked"] += 1
        audit("invalid_tool_arguments", user["sub"], tool=body.tool_name, reason=schema_error, risk=score)
        raise HTTPException(status_code=422, detail=schema_error)
    # Money-movement calls always require human approval, even if a future profile
    # configuration accidentally omits the tool from its approval_tools set.
    if body.tool_name == "transfer_funds" or body.tool_name in profile.approval_tools or score > RISK_APPROVAL_THRESHOLD:
        approval_id = str(uuid.uuid4())
        approvals[approval_id] = {
            "id": approval_id,
            "status": "pending",
            "user": user["sub"],
            "profile": profile_name,
            "tool_name": body.tool_name,
            "arguments": body.arguments,
            "prompt": body.prompt,
            "risk_score": score,
            "created_at": now_iso(),
        }
        metrics["approvals"] += 1
        audit("approval_requested", user["sub"], approval_id=approval_id, profile=profile_name, tool=body.tool_name, risk=score)
        return {
            "status": "approval_required",
            "approval_id": approval_id,
            "risk_score": score,
            "message": "Queued for human review. This request has not been executed.",
        }

    try:
        result = await gateway.call_tool(body.tool_name, body.arguments)
        if isinstance(result, dict) and result.get("isError"):
            raise RuntimeError("MCP tool reported an error")
        if profile.mask_responses:
            result = mask_sensitive_data(result)
        metrics["executed"] += 1
        audit("tool_executed", user["sub"], profile=profile_name, tool=body.tool_name, risk=score)
        return {"status": "success", "tool_name": body.tool_name, "risk_score": score, "result": result}
    except Exception:
        metrics["errors"] += 1
        audit("tool_call_error", user["sub"], profile=profile_name, tool=body.tool_name)
        raise HTTPException(status_code=502, detail="MCP tool call failed; check the server and its logs") from None


@app.get("/api/approvals")
async def get_approvals(user: dict[str, Any] = Depends(admin_user)):
    return [public_approval(item) for item in reversed(list(approvals.values()))]


@app.post("/api/approvals/{approval_id}/decision")
async def decide_approval(approval_id: str, body: ApprovalDecision, user: dict[str, Any] = Depends(admin_user)):
    item = approvals.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if item["status"] != "pending":
        raise HTTPException(status_code=409, detail="Approval has already been decided or is being processed")

    item["decided_by"] = user["sub"]
    item["decision_note"] = body.note
    item["decided_at"] = now_iso()
    item["decision"] = body.decision
    if body.decision == "reject":
        item.update(status="rejected", execution_status="not_executed")
        audit("approval_rejected", user["sub"], approval_id=approval_id, tool=item["tool_name"])
        return {"status": "rejected", "execution_status": "not_executed", "message": "Request rejected; tool was not executed."}

    # Atomically take the item out of the pending queue before awaiting I/O to
    # prevent two simultaneous approval clicks from executing it twice.
    item.update(status="processing", execution_status="processing")
    audit("approval_approved", user["sub"], approval_id=approval_id, tool=item["tool_name"])
    try:
        profile = PROFILES.get(item["profile"])
        if profile is None or item["tool_name"] not in profile.allowed_tools:
            item.update(status="execution_failed", execution_status="blocked_by_policy")
            raise HTTPException(status_code=403, detail="Queued tool is no longer allowed by its profile")

        scan_text = inspection_text(item.get("prompt", ""), item["arguments"])
        detected = detect_prompt_injection(scan_text)
        refreshed_score = risk_score(scan_text, item["tool_name"], item["arguments"])
        if detected:
            item.update(status="execution_failed", execution_status="blocked_by_prompt_guard")
            audit("approved_call_blocked_by_guardrail", user["sub"], approval_id=approval_id, patterns=detected)
            raise HTTPException(status_code=403, detail="Approval recorded, but the call was blocked by the prompt-injection guardrail")

        discovered_tools = await gateway.list_tools()
        discovered = next((tool for tool in discovered_tools if tool.get("name") == item["tool_name"]), None)
        if discovered is None:
            item.update(status="execution_failed", execution_status="tool_unavailable")
            raise HTTPException(status_code=502, detail="Approved tool is no longer available")
        schema = SCHEMAS.get(item["tool_name"]) or discovered.get("inputSchema") or {"type": "object", "properties": {}}
        schema_error = validate_args(schema, item["arguments"])
        if schema_error:
            item.update(status="execution_failed", execution_status="invalid_arguments")
            raise HTTPException(status_code=422, detail=f"Approved request failed re-validation: {schema_error}")

        # A human approval releases the queued operation, but all policy checks
        # above run again. The demo tools are synthetic; real MCP tools may have
        # real side effects and should only be configured intentionally.
        result = await gateway.call_tool(item["tool_name"], item["arguments"])
        if isinstance(result, dict) and result.get("isError"):
            item.update(status="execution_failed", execution_status="tool_error")
            raise HTTPException(status_code=502, detail="MCP tool reported an error")
        if profile.mask_responses:
            result = mask_sensitive_data(result)
        item.update(status="approved", execution_status="executed", result_summary=json.dumps(result, ensure_ascii=False, default=str)[:1000])
        metrics["executed"] += 1
        audit("approved_tool_executed", user["sub"], approval_id=approval_id, tool=item["tool_name"], risk=refreshed_score)
        return {"status": "approved", "execution_status": "executed", "result": result, "message": "Approved and executed after policy re-validation."}
    except HTTPException:
        if item.get("status") == "processing":
            item.update(status="execution_failed", execution_status="failed")
        raise
    except Exception:
        metrics["errors"] += 1
        item.update(status="execution_failed", execution_status="failed")
        audit("approved_tool_execution_failed", user["sub"], approval_id=approval_id, tool=item["tool_name"])
        raise HTTPException(status_code=502, detail="Approval was recorded, but tool execution failed") from None


@app.get("/api/logs")
async def get_logs(limit: int = 100, user: dict[str, Any] = Depends(admin_user)):
    safe_limit = max(1, min(limit, 500))
    return audit_events[-safe_limit:]


@app.get("/api/stats")
async def get_stats(user: dict[str, Any] = Depends(admin_user)):
    return {
        **metrics,
        "pending_approvals": sum(item["status"] == "pending" for item in approvals.values()),
        "audit_events": len(audit_events),
        "profile_count": len(PROFILES),
        "mcp_transport": settings.mcp_transport,
    }
