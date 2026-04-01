#!/usr/bin/env node
/**
 * Send a message to the openclaw agent via the gateway WebSocket API.
 * Uses the Control UI auth bypass protocol (protocol v3).
 *
 * Usage:
 *   node /audit/send_message.mjs "Your prompt here" [timeout_seconds]
 *
 * Output: JSON { text, toolCalls, chatEvents, error }
 */

const message = process.argv[2];
if (!message) {
  console.error("Usage: node send_message.mjs <message> [timeout_seconds]");
  process.exit(1);
}

const timeout = parseInt(process.argv[3] || "300", 10);

const gatewayPort = process.env.OPENCLAW_GATEWAY_PORT || "18789";
const token = process.env.OPENCLAW_GATEWAY_TOKEN || "audit-token-static";
const wsUrl = `ws://127.0.0.1:${gatewayPort}`;

async function main() {
  const { createRequire } = await import("module");
  const require = createRequire("/app/package.json");
  const WebSocket = require("ws");

  function extractFromContent(content) {
    const textParts = [];
    const tools = [];
    if (!Array.isArray(content)) return { text: "", tools };
    for (const part of content) {
      if (!part || typeof part !== "object") continue;
      const partType = part.type;
      if (partType === "text" && part.text) {
        textParts.push(part.text);
      } else if (
        partType === "toolCall" ||
        partType === "tool_call" ||
        partType === "tool-call" ||
        partType === "tool-invocation" ||
        partType === "toolInvocation" ||
        partType === "tool_use"
      ) {
        tools.push({
          id: part.id || part.toolCallId || part.toolUseId || undefined,
          name: part.name || part.toolName || part.tool_name || undefined,
          input: part.input || part.args || part.arguments || part.parameters || undefined,
        });
      }
    }
    // Join multi-turn text blocks with double newline instead of concatenating
    return { text: textParts.join("\n\n"), tools };
  }

  function mergeToolCalls(existing, incoming) {
    for (const tool of incoming) {
      const toolId = tool?.id || tool?.toolCallId;
      if (!toolId || existing.some((entry) => (entry.id || entry.toolCallId) === toolId)) {
        continue;
      }
      existing.push(tool);
    }
  }

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl, {
      origin: `http://127.0.0.1:${gatewayPort}`,
      headers: {
        Origin: `http://127.0.0.1:${gatewayPort}`,
      },
    });

    let requestId = 1;
    let connected = false;
    let collectedText = "";
    let collectedToolCalls = [];
    let chatEvents = [];

    function nextId() {
      return `bench-${requestId++}`;
    }

    let resolved = false;
    function finish(result) {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      ws.close();
      resolve(result);
    }

    // Overall timeout — resolve with whatever we have (don't reject).
    // The session JSONL captured by run_test.sh is the authoritative
    // source; this WebSocket stream just provides supplementary data.
    const timer = setTimeout(() => {
      process.stderr.write(`[send_message] overall timeout ${timeout}s — resolving with collected data\n`);
      finish({
        text: collectedText,
        toolCalls: collectedToolCalls,
        chatEvents,
        error: collectedText ? undefined : "timeout_no_response",
      });
    }, timeout * 1000);

    ws.on("error", (err) => {
      finish({ text: collectedText, toolCalls: collectedToolCalls, chatEvents, error: err.message });
    });

    ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }

      // Step 1: Server sends connect.challenge with nonce
      if (msg.type === "event" && msg.event === "connect.challenge") {
        const connectReq = {
          type: "req",
          method: "connect",
          id: nextId(),
          params: {
            auth: { token },
            minProtocol: 3,
            maxProtocol: 3,
            client: {
              id: "openclaw-control-ui",
              version: "1.0.0",
              platform: "linux",
              mode: "ui",
            },
            role: "operator",
            scopes: [
              "operator.read",
              "operator.write",
              "operator.admin",
            ],
          },
        };
        ws.send(JSON.stringify(connectReq));
        return;
      }

      // Step 2: Server responds to connect with hello-ok
      if (msg.type === "res" && msg.payload?.type === "hello-ok") {
        connected = true;
        // Now send chat.send
        const sessionKey = `benchmark-${Date.now()}`;
        const chatReq = {
          type: "req",
          method: "chat.send",
          id: nextId(),
          params: {
            sessionKey,
            message,
            idempotencyKey: `bench-${Date.now()}-${Math.random().toString(36).slice(2)}`,
          },
        };
        ws.send(JSON.stringify(chatReq));
        return;
      }

      // Step 3: chat.send ACK response
      if (msg.type === "res" && msg.id !== undefined) {
        if (msg.payload?.error || msg.error) {
          const errMsg = msg.payload?.error?.message || msg.error?.message || JSON.stringify(msg.payload?.error || msg.error);
          clearTimeout(timer);
          ws.close();
          resolve({ text: "", toolCalls: [], chatEvents: [], error: errMsg });
          return;
        }
        // ACK — the agent run has started, continue listening for chat events
        process.stderr.write(`[send_message] ACK: ${JSON.stringify(msg.payload || {}).slice(0, 300)}\n`);
        return;
      }

      // Step 4: Collect chat events (agent streaming output)
      if (msg.type === "event" && msg.event === "chat") {
        const p = msg.payload || {};
        chatEvents.push(p);
        const extracted = extractFromContent(p.message?.content);
        // Accumulate text across all non-delta events (not overwrite)
        if (p.state !== "delta" && extracted.text) {
          if (collectedText) {
            collectedText += "\n\n" + extracted.text;
          } else {
            collectedText = extracted.text;
          }
        }
        mergeToolCalls(collectedToolCalls, extracted.tools);

        if (p.state === "delta") {
          process.stderr.write(`[agent-event] delta: ${JSON.stringify(p.message?.content || []).slice(0, 500)}\n`);
        } else if (p.state === "error" || p.state === "aborted") {
          process.stderr.write(`[agent-event] ${p.state}: text_len=${collectedText.length} tools=${collectedToolCalls.length}\n`);
          finish({
            text: collectedText,
            toolCalls: collectedToolCalls,
            chatEvents,
            error: p.state === "error" ? (p.error || "Agent error") : undefined,
          });
          return;
        } else if (p.state === "final") {
          // "final" means this message turn is complete. The agent may have
          // more turns after tool calls. We keep the WebSocket open and let
          // the overall timeout handle closure. The session JSONL (captured
          // by run_test.sh after we return) is the authoritative trace.
          process.stderr.write(`[agent-event] final: text_len=${collectedText.length} tools=${collectedToolCalls.length} — keeping WS open for more turns\n`);
        }
      }

      // Log other events
      if (msg.type === "event" && msg.event !== "chat") {
        process.stderr.write(`[agent-event] ${msg.event}: ${JSON.stringify(msg.payload || {}).slice(0, 200)}\n`);
      }
    });

    ws.on("close", (code, reason) => {
      if (!connected && !resolved) {
        finish({ text: "", toolCalls: [], chatEvents: [], error: `WebSocket closed before connect (code=${code} reason=${reason})` });
      } else {
        // Server closed the connection — resolve with what we have
        finish({ text: collectedText, toolCalls: collectedToolCalls, chatEvents });
      }
    });
  });
}

main()
  .then((result) => {
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  })
  .catch((err) => {
    console.log(JSON.stringify({ text: "", toolCalls: [], chatEvents: [], error: err.message }));
    process.exit(1);
  });
