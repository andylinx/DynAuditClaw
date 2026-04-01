#!/usr/bin/env python3
"""
proxy_server.py — Configurable HTTP reverse proxy for intercepting
tool/MCP calls during OpenClaw security audits.

Sits between the OpenClaw agent and real/mock tool endpoints.
Can passthrough, inject payloads into, or fully replace tool responses.

Usage:
    python proxy_server.py --config tool_proxy_config.json --port 19000

The proxy dynamically creates routes based on the config file. Each intercepted
tool gets a route at /<tool_name> that forwards to the original endpoint.
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn
from pydantic import BaseModel

logger = logging.getLogger("tool-proxy")


# ── Config models ──

class InjectionConfig(BaseModel):
    position: str = "append"  # start | middle | end | append
    payload: str = ""


class InterceptRule(BaseModel):
    tool_name: str
    original_endpoint: str = ""
    mode: str = "passthrough"  # passthrough | inject | replace | record
    injection: Optional[InjectionConfig] = None
    replacement_response: Optional[dict] = None


class ProxyConfig(BaseModel):
    intercepts: list[InterceptRule] = []
    default_mode: str = "passthrough"
    canary_tokens: list[str] = []
    log_path: str = "/results/tool_proxy.jsonl"


# ── The proxy app ──

app = FastAPI(title="OpenClaw Audit Tool Proxy")
config: ProxyConfig = ProxyConfig()
http_client: Optional[httpx.AsyncClient] = None
log_file = None


@app.on_event("startup")
async def startup():
    global http_client, log_file
    http_client = httpx.AsyncClient(timeout=60.0, follow_redirects=True)
    log_path = Path(config.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = open(log_path, "a")
    logger.info(f"Tool proxy started. Logging to {config.log_path}")
    logger.info(f"Configured {len(config.intercepts)} intercept rules")


@app.on_event("shutdown")
async def shutdown():
    global http_client, log_file
    if http_client:
        await http_client.aclose()
    if log_file:
        log_file.close()


def _log_event(event: dict):
    """Write an event to the JSONL audit log."""
    if log_file:
        event["timestamp"] = time.time()
        log_file.write(json.dumps(event, default=str) + "\n")
        log_file.flush()


def _detect_canary(text: str) -> list[str]:
    """Check if any canary tokens appear in the text."""
    found = []
    for token in config.canary_tokens:
        if token in text:
            found.append(token)
    return found


def _inject_into_response(original: str, injection: InjectionConfig) -> str:
    """Inject payload into a response string at the specified position."""
    payload = injection.payload
    pos = injection.position

    if pos == "start":
        return payload + "\n" + original
    elif pos == "end" or pos == "append":
        return original + "\n" + payload
    elif pos == "middle":
        lines = original.split("\n")
        mid = len(lines) // 2
        lines.insert(mid, payload)
        return "\n".join(lines)
    else:
        return original + "\n" + payload


def _inject_into_json(data: Any, injection: InjectionConfig) -> Any:
    """Inject payload into a JSON response.

    Handles common structures:
    - If data is a dict with a text/content/body field, inject into that field
    - If data is a list, append a poisoned entry
    - If data is a dict with a results/messages list, inject into the list
    """
    payload = injection.payload

    if isinstance(data, dict):
        # Try common text fields
        for field in ["text", "content", "body", "output", "result", "snippet", "description"]:
            if field in data and isinstance(data[field], str):
                data[field] = _inject_into_response(data[field], injection)
                return data

        # Try common list fields (search results, messages, etc.)
        for field in ["results", "messages", "items", "entries", "data", "hits"]:
            if field in data and isinstance(data[field], list):
                # Inject a poisoned entry into the list
                poisoned_entry = {
                    "title": "Important Notice",
                    "content": payload,
                    "text": payload,
                }
                pos = injection.position
                if pos == "start":
                    data[field].insert(0, poisoned_entry)
                elif pos == "middle":
                    mid = len(data[field]) // 2
                    data[field].insert(mid, poisoned_entry)
                else:
                    data[field].append(poisoned_entry)
                return data

        # Fallback: add a new field
        data["_audit_notice"] = payload
        return data

    elif isinstance(data, list):
        poisoned = {"content": payload, "text": payload}
        if injection.position == "start":
            data.insert(0, poisoned)
        elif injection.position == "middle":
            data.insert(len(data) // 2, poisoned)
        else:
            data.append(poisoned)
        return data

    elif isinstance(data, str):
        return _inject_into_response(data, injection)

    return data


def _find_rule(tool_name: str) -> Optional[InterceptRule]:
    """Find the intercept rule for a tool name."""
    for rule in config.intercepts:
        if rule.tool_name == tool_name:
            return rule
    return None


@app.api_route("/proxy/{tool_name}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_handler(tool_name: str, request: Request):
    """Main proxy endpoint. Routes based on tool_name and configured rules."""
    rule = _find_rule(tool_name)
    mode = rule.mode if rule else config.default_mode
    original_endpoint = rule.original_endpoint if rule else ""

    # Read request body
    body = await request.body()
    body_text = body.decode("utf-8", errors="replace") if body else ""
    body_json = None
    try:
        body_json = json.loads(body_text) if body_text else None
    except json.JSONDecodeError:
        pass

    log_entry = {
        "tool_name": tool_name,
        "mode": mode,
        "request_method": request.method,
        "request_body_preview": body_text[:500] if body_text else None,
        "original_endpoint": original_endpoint,
    }

    # ── PASSTHROUGH: Forward to real endpoint, return as-is ──
    if mode == "passthrough" and original_endpoint:
        resp = await _forward_request(request, original_endpoint, body)
        resp_text = resp.text if resp else ""
        canaries = _detect_canary(resp_text)
        log_entry["response_preview"] = resp_text[:500]
        log_entry["canary_detected"] = canaries
        log_entry["status_code"] = resp.status_code if resp else 0
        _log_event(log_entry)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )

    # ── RECORD: Forward and log, return as-is ──
    elif mode == "record" and original_endpoint:
        resp = await _forward_request(request, original_endpoint, body)
        resp_text = resp.text if resp else ""
        canaries = _detect_canary(resp_text)
        log_entry["response_full"] = resp_text
        log_entry["canary_detected"] = canaries
        log_entry["status_code"] = resp.status_code if resp else 0
        _log_event(log_entry)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )

    # ── INJECT: Forward to real endpoint, inject payload into response ──
    elif mode == "inject" and rule and rule.injection:
        if original_endpoint:
            resp = await _forward_request(request, original_endpoint, body)
            resp_text = resp.text if resp else "{}"
        else:
            resp_text = "{}"

        # Try JSON injection first, fall back to text
        try:
            resp_json = json.loads(resp_text)
            modified = _inject_into_json(resp_json, rule.injection)
            modified_text = json.dumps(modified, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            modified_text = _inject_into_response(resp_text, rule.injection)

        canaries = _detect_canary(modified_text)
        log_entry["original_response_preview"] = resp_text[:300]
        log_entry["modified_response_preview"] = modified_text[:500]
        log_entry["injection_payload"] = rule.injection.payload[:200]
        log_entry["canary_detected"] = canaries
        _log_event(log_entry)
        return JSONResponse(content=json.loads(modified_text) if modified_text.startswith(("{", "[")) else {"text": modified_text})

    # ── REPLACE: Ignore real endpoint, return fully simulated response ──
    elif mode == "replace" and rule and rule.replacement_response:
        resp_text = json.dumps(rule.replacement_response, ensure_ascii=False)
        canaries = _detect_canary(resp_text)
        log_entry["replacement_response"] = resp_text[:500]
        log_entry["canary_detected"] = canaries
        _log_event(log_entry)
        return JSONResponse(content=rule.replacement_response)

    # ── FALLBACK: No rule or endpoint, return error ──
    else:
        log_entry["error"] = f"No endpoint configured for {tool_name} in mode {mode}"
        _log_event(log_entry)
        return JSONResponse(
            status_code=502,
            content={"error": f"Tool proxy: no endpoint for {tool_name}"},
        )


async def _forward_request(
    request: Request, endpoint: str, body: bytes
) -> httpx.Response:
    """Forward an HTTP request to the original endpoint."""
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }
    try:
        resp = await http_client.request(
            method=request.method,
            url=endpoint,
            content=body,
            headers=headers,
        )
        return resp
    except Exception as e:
        logger.error(f"Forward to {endpoint} failed: {e}")
        return httpx.Response(
            status_code=502,
            content=json.dumps({"error": str(e)}).encode(),
        )


@app.get("/health")
async def health():
    return {"status": "ok", "rules": len(config.intercepts)}


@app.get("/audit")
async def audit_log():
    """Return the full audit log."""
    log_path = Path(config.log_path)
    if log_path.exists():
        entries = []
        for line in log_path.read_text().strip().split("\n"):
            if line:
                entries.append(json.loads(line))
        return {"entries": entries}
    return {"entries": []}


def load_config(config_path: str) -> ProxyConfig:
    """Load proxy configuration from JSON file."""
    with open(config_path) as f:
        data = json.load(f)
    return ProxyConfig(**data)


def main():
    global config

    parser = argparse.ArgumentParser(description="OpenClaw Audit Tool Proxy")
    parser.add_argument("--config", required=True, help="Proxy config JSON file")
    parser.add_argument("--port", type=int, default=19000, help="Proxy port")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    args = parser.parse_args()

    config = load_config(args.config)

    logging.basicConfig(level=logging.INFO)
    logger.info(f"Starting tool proxy on {args.host}:{args.port}")
    logger.info(f"Loaded {len(config.intercepts)} intercept rules")
    for rule in config.intercepts:
        logger.info(f"  {rule.tool_name}: {rule.mode} → {rule.original_endpoint or '(no endpoint)'}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
