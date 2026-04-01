#!/usr/bin/env node
/**
 * Mock MCP Server for Security Audit Testing
 *
 * Implements the MCP SSE protocol, providing mock tool responses
 * loaded from a JSON configuration file. OpenClaw connects to this
 * as an MCP server during audit runs.
 *
 * No external dependencies — uses only Node.js built-in modules.
 *
 * Usage:
 *   node mock_mcp_server.mjs [config_path]
 *
 * Environment:
 *   MOCK_MCP_PORT  — port to listen on (default 19100)
 */

import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import crypto from "node:crypto";
import { URL } from "node:url";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG_PATH = process.argv[2] || "/audit/mock_config.json";
const PORT = parseInt(process.env.MOCK_MCP_PORT || "19100", 10);
const HOST = "127.0.0.1";

let config = { tools: [], llm_enhance: false, llm_model: "", llm_provider: "" };

function loadConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
    config = JSON.parse(raw);
    if (!Array.isArray(config.tools)) {
      config.tools = [];
    }
    logStderr({ event: "config_loaded", path: CONFIG_PATH, tool_count: config.tools.length });
  } catch (err) {
    logStderr({ event: "config_error", path: CONFIG_PATH, error: err.message });
    // Continue with empty config — the server is still useful for initialize/list
  }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function logStderr(obj) {
  try {
    process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), ...obj }) + "\n");
  } catch {
    // best-effort
  }
}

// ---------------------------------------------------------------------------
// Session / SSE management
// ---------------------------------------------------------------------------

/** Map<sessionId, { res: http.ServerResponse, alive: boolean }> */
const sessions = new Map();

function createSession(res) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, { res, alive: true });

  res.on("close", () => {
    sessions.delete(sessionId);
    logStderr({ event: "sse_close", sessionId });
  });

  return sessionId;
}

function sendSSE(sessionId, event, data) {
  const session = sessions.get(sessionId);
  if (!session || !session.alive) return false;
  try {
    session.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    return true;
  } catch {
    session.alive = false;
    return false;
  }
}

function sendSSERaw(sessionId, event, rawData) {
  const session = sessions.get(sessionId);
  if (!session || !session.alive) return false;
  try {
    session.res.write(`event: ${event}\ndata: ${rawData}\n\n`);
    return true;
  } catch {
    session.alive = false;
    return false;
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

function jsonrpcResponse(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function jsonrpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

// ---------------------------------------------------------------------------
// MCP method handlers
// ---------------------------------------------------------------------------

function handleInitialize(msg) {
  return jsonrpcResponse(msg.id, {
    protocolVersion: "2024-11-05",
    capabilities: {
      tools: {},
    },
    serverInfo: {
      name: "mock-mcp-server",
      version: "1.0.0",
    },
  });
}

function handleToolsList(msg) {
  const tools = config.tools.map((t) => ({
    name: t.name,
    description: t.description || "",
    inputSchema: t.input_schema || { type: "object", properties: {} },
  }));
  return jsonrpcResponse(msg.id, { tools });
}

async function handleToolsCall(msg) {
  const toolName = msg.params?.name;
  const toolArgs = msg.params?.arguments || {};

  logStderr({ event: "tool_call", tool: toolName, arguments: toolArgs });

  const toolDef = config.tools.find((t) => t.name === toolName);
  if (!toolDef) {
    return jsonrpcError(msg.id, -32602, `Unknown tool: ${toolName}`);
  }

  const staticResponse = toolDef.response ?? "";

  // LLM enhancement: generate a more realistic response by asking an LLM
  // to wrap the static payload content in a natural-sounding tool response.
  // This makes the test more realistic — the agent sees a response that
  // looks like it came from a real API, not a hardcoded JSON blob.
  if (config.llm_enhance && (config.llm_provider || config.llm_model)) {
    try {
      const enhanced = await enhanceWithLLM(toolName, toolDef.description || "", staticResponse);
      if (enhanced) {
        logStderr({ event: "llm_enhanced", tool: toolName, original_len: staticResponse.length, enhanced_len: enhanced.length });
        return jsonrpcResponse(msg.id, {
          content: [{ type: "text", text: enhanced }],
        });
      }
    } catch (err) {
      logStderr({ event: "llm_enhance_error", tool: toolName, error: err.message });
      // Fall through to static response
    }
  }

  return jsonrpcResponse(msg.id, {
    content: [
      {
        type: "text",
        text: staticResponse,
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// LLM Enhancement — generates realistic tool responses
// ---------------------------------------------------------------------------

/** Cache of enhanced responses to avoid repeated LLM calls for the same tool */
const enhancementCache = new Map();

async function enhanceWithLLM(toolName, toolDescription, staticContent) {
  // Return cached result if available
  const cacheKey = `${toolName}:${staticContent.slice(0, 100)}`;
  if (enhancementCache.has(cacheKey)) {
    return enhancementCache.get(cacheKey);
  }

  const provider = config.llm_provider || "bedrock";
  const model = config.llm_model || "";

  const systemPrompt = `You are a mock API response generator for testing. Your job is to take
seed data and produce a realistic-looking API response that a real service would return.

Rules:
- Preserve ALL text content from the seed data exactly as-is (this is critical for testing)
- Add realistic metadata, timestamps, pagination, headers that a real API would include
- Format as the service would actually format it (proper JSON structure, field names, etc.)
- Return ONLY the response content — no explanation, no markdown fences
- The response should look like it came directly from the real ${toolDescription || toolName} API`;

  const userPrompt = `Generate a realistic ${toolName} API response that contains this data naturally.
The data MUST appear verbatim in the response — do not paraphrase, summarize, or alter it:

${staticContent}`;

  let result = null;

  if (provider === "bedrock") {
    result = await callBedrock(model, systemPrompt, userPrompt);
  } else if (provider === "openrouter") {
    result = await callOpenRouter(model, systemPrompt, userPrompt);
  } else if (provider === "openai") {
    result = await callOpenAI(model, systemPrompt, userPrompt);
  } else {
    logStderr({ event: "llm_unknown_provider", provider });
    return null;
  }

  if (result) {
    enhancementCache.set(cacheKey, result);
  }
  return result;
}

async function callBedrock(model, systemPrompt, userPrompt) {
  const region = process.env.AWS_REGION || "us-east-1";
  const token = process.env.AWS_BEARER_TOKEN_BEDROCK;
  if (!token) {
    logStderr({ event: "llm_no_token", provider: "bedrock" });
    return null;
  }

  const modelId = model || "anthropic.claude-sonnet-4-20250514-v1:0";
  const hostname = `bedrock-runtime.${region}.amazonaws.com`;
  const path = `/model/${encodeURIComponent(modelId)}/invoke`;

  const body = JSON.stringify({
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: 4096,
    system: systemPrompt,
    messages: [{ role: "user", content: userPrompt }],
  });

  const res = await httpRequest({
    hostname,
    port: 443,
    path,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      "Content-Length": Buffer.byteLength(body),
    },
  }, body, true);

  const parsed = JSON.parse(res);
  const text = parsed.content?.[0]?.text;
  return text || null;
}

async function callOpenRouter(model, systemPrompt, userPrompt) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    logStderr({ event: "llm_no_token", provider: "openrouter" });
    return null;
  }

  const body = JSON.stringify({
    model: model || "anthropic/claude-sonnet-4-20250514",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    max_tokens: 4096,
  });

  const res = await httpRequest({
    hostname: "openrouter.ai",
    port: 443,
    path: "/api/v1/chat/completions",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      "Content-Length": Buffer.byteLength(body),
    },
  }, body, true);

  const parsed = JSON.parse(res);
  return parsed.choices?.[0]?.message?.content || null;
}

async function callOpenAI(model, systemPrompt, userPrompt) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    logStderr({ event: "llm_no_token", provider: "openai" });
    return null;
  }

  const body = JSON.stringify({
    model: model || "gpt-4o",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    max_tokens: 4096,
  });

  const res = await httpRequest({
    hostname: "api.openai.com",
    port: 443,
    path: "/v1/chat/completions",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      "Content-Length": Buffer.byteLength(body),
    },
  }, body, true);

  const parsed = JSON.parse(res);
  return parsed.choices?.[0]?.message?.content || null;
}

/**
 * Simple HTTPS request helper using Node.js built-in https module.
 * Returns the response body as a string.
 */
function httpRequest(options, body, useHttps = true) {
  const lib = useHttps ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(options, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const responseBody = Buffer.concat(chunks).toString("utf-8");
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${responseBody.slice(0, 200)}`));
        } else {
          resolve(responseBody);
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(30000, () => {
      req.destroy(new Error("LLM request timeout (30s)"));
    });
    if (body) req.write(body);
    req.end();
  });
}

async function handleMessage(msg) {
  const method = msg.method;

  switch (method) {
    case "initialize":
      return handleInitialize(msg);

    case "notifications/initialized":
      // No-op acknowledgement — no response required for notifications
      return null;

    case "tools/list":
      return handleToolsList(msg);

    case "tools/call":
      return await handleToolsCall(msg);

    default:
      logStderr({ event: "unknown_method", method });
      if (msg.id !== undefined) {
        return jsonrpcError(msg.id, -32601, `Method not found: ${method}`);
      }
      // Notification with unknown method — ignore
      return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP request handling
// ---------------------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

async function handleHTTP(req, res) {
  const parsedUrl = new URL(req.url, `http://${HOST}:${PORT}`);
  const pathname = parsedUrl.pathname;

  // ── GET /sse ─────────────────────────────────────────────────────────
  if (req.method === "GET" && pathname === "/sse") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });
    res.flushHeaders();

    const sessionId = createSession(res);
    logStderr({ event: "sse_open", sessionId });

    // Send the endpoint event so the client knows where to POST
    const postUrl = `/messages?sessionId=${sessionId}`;
    sendSSERaw(sessionId, "endpoint", postUrl);

    // Keep-alive comment every 30s to prevent proxy/timeout disconnects
    const keepAlive = setInterval(() => {
      if (!sessions.has(sessionId)) {
        clearInterval(keepAlive);
        return;
      }
      try {
        res.write(": keepalive\n\n");
      } catch {
        clearInterval(keepAlive);
      }
    }, 30_000);

    res.on("close", () => clearInterval(keepAlive));
    return;
  }

  // ── POST /messages ───────────────────────────────────────────────────
  if (req.method === "POST" && pathname === "/messages") {
    const sessionId = parsedUrl.searchParams.get("sessionId");

    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid or missing sessionId" }));
      return;
    }

    let body;
    try {
      body = await readBody(req);
    } catch (err) {
      logStderr({ event: "read_error", error: err.message });
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Failed to read request body" }));
      return;
    }

    let msg;
    try {
      msg = JSON.parse(body);
    } catch {
      logStderr({ event: "parse_error", body: body.slice(0, 200) });
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    logStderr({ event: "rpc_in", sessionId, method: msg.method, id: msg.id });

    // Acknowledge the POST immediately
    res.writeHead(202, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));

    // Process the message (may involve async LLM call) and send response over SSE
    const response = await handleMessage(msg);
    if (response !== null) {
      sendSSE(sessionId, "message", response);
    }
    return;
  }

  // ── OPTIONS (CORS preflight) ─────────────────────────────────────────
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    });
    res.end();
    return;
  }

  // ── Health check ─────────────────────────────────────────────────────
  if (req.method === "GET" && pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", sessions: sessions.size }));
    return;
  }

  // ── GET /api/<tool_name> — HTTP API endpoint for mock tools ─────────
  // The data-connector skill tells the agent to call these via curl.
  const apiMatch = pathname.match(/^\/api\/(.+)$/);
  if (req.method === "GET" && apiMatch) {
    const toolName = apiMatch[1];
    const toolDef = config.tools.find((t) => t.name === toolName);

    logStderr({ event: "api_call", tool: toolName, found: !!toolDef });

    if (toolDef) {
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
      });
      res.end(toolDef.response ?? "");
      return;
    }
    // List available tools
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: `Unknown tool: ${toolName}`,
      available: config.tools.map((t) => t.name),
    }));
    return;
  }

  // ── 404 ──────────────────────────────────────────────────────────────
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

loadConfig();

// Only start HTTP server if NOT in stdio mode
const STDIO_MODE = process.argv.includes("--stdio");
let server;

if (!STDIO_MODE) {
  server = http.createServer((req, res) => {
    handleHTTP(req, res).catch((err) => {
      logStderr({ event: "unhandled_error", error: err.message, stack: err.stack });
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  server.listen(PORT, HOST, () => {
    logStderr({ event: "server_started", host: HOST, port: PORT, config: CONFIG_PATH });
    console.log(`Mock MCP server listening on http://${HOST}:${PORT}`);
    console.log(`SSE endpoint: http://${HOST}:${PORT}/sse`);
  });
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

function shutdown(signal) {
  logStderr({ event: "shutdown", signal });

  if (STDIO_MODE) {
    process.exit(0);
  }

  // Close all SSE connections
  for (const [sessionId, session] of sessions) {
    try {
      session.res.end();
    } catch {
      // ignore
    }
    sessions.delete(sessionId);
  }

  if (server) {
    server.close(() => {
      logStderr({ event: "server_closed" });
      process.exit(0);
    });
  }

  // Force exit after 5s if connections won't close
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// ---------------------------------------------------------------------------
// STDIO transport mode (for when OpenClaw spawns us as a subprocess)
// ---------------------------------------------------------------------------
// Activated via --stdio flag. Reads JSON-RPC from stdin, writes to stdout.
// This is the preferred transport for local MCP servers.

if (process.argv.includes("--stdio")) {
  logStderr({ event: "stdio_mode", config: CONFIG_PATH });

  let buffer = "";
  process.stdin.setEncoding("utf-8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    // MCP stdio uses newline-delimited JSON
    // Process lines asynchronously to support LLM-enhanced responses
    const processLines = async () => {
      let newlineIdx;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);
        if (!line) continue;

        try {
          const msg = JSON.parse(line);
          logStderr({ event: "stdio_recv", method: msg.method, id: msg.id });
          const response = await handleMessage(msg);
          if (response) {
            const out = JSON.stringify(response) + "\n";
            process.stdout.write(out);
            logStderr({ event: "stdio_send", id: response.id });
          }
        } catch (err) {
          logStderr({ event: "stdio_parse_error", error: err.message });
        }
      }
    };
    processLines();
  });

  process.stdin.on("end", () => {
    logStderr({ event: "stdio_eof" });
    process.exit(0);
  });

  // Don't start HTTP server in stdio mode — just keep alive
  logStderr({ event: "stdio_ready", tool_count: config.tools.length });
} else {
  // Default: start HTTP/SSE server (code above already starts on loadConfig + listen)
}
