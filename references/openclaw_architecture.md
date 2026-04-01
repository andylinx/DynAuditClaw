# OpenClaw Architecture Reference

This document describes the architecture of OpenClaw for security audit purposes. It covers how components interact, where trust boundaries exist, and which surfaces are security-relevant.

## Table of Contents

1. [System Overview](#system-overview)
2. [Gateway (Control Plane)](#gateway)
3. [Agent Runtime (Execution Engine)](#agent-runtime)
4. [Channel Adapters](#channel-adapters)
5. [Session Model & Trust Boundaries](#session-model)
6. [Prompt Construction & Skill Injection](#prompt-construction)
7. [Memory & Persistence](#memory-and-persistence)
8. [Tool Execution](#tool-execution)
9. [Extensions & Plugins](#extensions-and-plugins)
10. [Scheduled Automation](#scheduled-automation)
11. [Sandbox & Isolation](#sandbox-and-isolation)
12. [Security-Relevant Configuration Files](#config-files)
13. [Attack Surface Map](#attack-surface-map)

---

## 1. System Overview <a name="system-overview"></a>

OpenClaw is a hub-and-spoke persistent agent system with two core components:

```
                    ┌─────────────────────────────────────────┐
                    │              Gateway                     │
                    │         (Control Plane)                  │
                    │  WebSocket server @ 127.0.0.1:18789     │
                    │                                         │
                    │  ┌─────────┐  ┌──────────┐  ┌───────┐  │
                    │  │ Channel │  │ Access   │  │ Route │  │
                    │  │Adapters │  │ Control  │  │ Logic │  │
                    │  └────┬────┘  └────┬─────┘  └───┬───┘  │
                    └───────┼────────────┼────────────┼───────┘
                            │            │            │
                    ┌───────┼────────────┼────────────┼───────┐
                    │       ▼            ▼            ▼       │
                    │            Agent Runtime                 │
                    │         (Execution Engine)               │
                    │                                         │
                    │  ┌──────────┐ ┌────────┐ ┌──────────┐  │
                    │  │ Session  │ │ Prompt │ │   Tool   │  │
                    │  │ Resolver │ │Assembly│ │ Executor │  │
                    │  └──────────┘ └────────┘ └──────────┘  │
                    │  ┌──────────┐ ┌────────┐ ┌──────────┐  │
                    │  │ Memory   │ │ Skills │ │  State   │  │
                    │  │ Manager  │ │ Loader │ │ Persist  │  │
                    │  └──────────┘ └────────┘ └──────────┘  │
                    └─────────────────────────────────────────┘
```

Key architectural properties:
- **Persistent**: State survives across sessions (memory, skills, files)
- **Multi-session**: Multiple concurrent sessions with different trust levels
- **Tool-augmented**: Agent can execute shell commands, file operations, network requests
- **Extensible**: Plugins, skills, and extensions expand capabilities
- **Multi-channel**: Ingress from CLI, Web UI, Slack, Discord, Telegram, WhatsApp, etc.

---

## 2. Gateway (Control Plane) <a name="gateway"></a>

The Gateway handles transport, authentication, and routing.

- **Default binding**: `127.0.0.1:18789` (loopback only)
- **Remote access**: Requires explicit setup (SSH tunnel, Tailscale, etc.)
- **Protocol**: WebSocket
- **Responsibilities**:
  - Accept and normalize messages from channel adapters
  - Enforce access control (allowlists, pairing flows)
  - Route messages to the appropriate session in the runtime
  - Manage connection lifecycle

**Security relevance**: The Gateway is the network boundary. If bound to `0.0.0.0` or exposed via tunnel without authentication, external parties can send messages to the agent.

---

## 3. Agent Runtime (Execution Engine) <a name="agent-runtime"></a>

The Runtime is where reasoning and action happen.

**Execution loop**:
1. Receive normalized message from Gateway
2. Resolve session identity (determines trust boundary)
3. Assemble prompt context (history, memory, skills, tools)
4. Invoke the LLM
5. Intercept and execute tool calls
6. Stream results back into the generation loop
7. Persist updated state (memory, files, turn history)

**Security relevance**: The Runtime has direct access to the filesystem, shell, network, and memory. Tool calls are the primary mechanism through which the agent takes real-world action.

---

## 4. Channel Adapters <a name="channel-adapters"></a>

Channel adapters bridge external messaging systems to the Gateway.

**Supported channels**:
- CLI (direct terminal access)
- Web UI (browser-based)
- macOS app
- Mobile nodes (camera, location, screen, Canvas)
- Slack
- Discord
- Telegram
- WhatsApp
- iMessage
- Email (in some configurations)

Each adapter implements:
- Authentication
- Inbound parsing
- Access control
- Outbound formatting

**Security relevance**: Each channel is an ingress point. Messages from untrusted channels (DMs, group chats) can carry indirect prompt injection payloads. Mobile nodes expand the action surface to device capabilities.

---

## 5. Session Model & Trust Boundaries <a name="session-model"></a>

OpenClaw uses session-based trust tiers:

| Session Type | Trust Level | Typical Capabilities | Sandboxing |
|-------------|-------------|---------------------|------------|
| `main` (operator) | HIGH | Full tool access, host filesystem | None (runs on host) |
| DM sessions | MEDIUM-LOW | Scoped tools, limited filesystem | Docker sandbox by default |
| Group chat sessions | LOW | Restricted tools, read-only or no filesystem | Docker sandbox by default |

Sessions encode:
- **Who** is talking (identity)
- **Through what** channel (origin)
- **In what context** (workspace, model, system prompt overrides, sandbox settings)

**Security relevance**: Trust boundary misconfiguration is a high-impact vulnerability. A DM session with `main`-level permissions bypasses sandboxing entirely. Cross-session leakage (one session reading another's history) can propagate compromises.

---

## 6. Prompt Construction & Skill Injection <a name="prompt-construction"></a>

The system prompt is assembled from multiple sources:

```
┌────────────────────────────────────────────┐
│              Assembled Prompt               │
│                                            │
│  1. Base instructions (runtime)            │
│  2. AGENTS.md (core agent instructions)    │
│  3. SOUL.md (personality/style)            │
│  4. TOOLS.md (tool-use conventions)        │
│  5. Relevant skills (SKILL.md files)       │
│  6. Memory search results                  │
│  7. Auto-generated tool definitions        │
│  8. Session history                        │
│  9. User message                           │
└────────────────────────────────────────────┘
```

### Skills are first-class prompt material

Skills are structured task guides loaded from `skills/<skill-name>/SKILL.md`. They are **not** merely metadata — they become direct behavioral instructions at prompt time.

**Skill selection**: OpenClaw selectively injects only skills deemed relevant to the current turn (not all skills every time). This reduces bloat but means the *selected* skill has outsized influence.

**Security relevance**:
- A malicious SKILL.md becomes runtime instruction authority
- Skill selection/retrieval is itself an attack surface
- AGENTS.md and TOOLS.md can be poisoned to persistently alter behavior
- Memory search results can inject fabricated context

---

## 7. Memory & Persistence <a name="memory-and-persistence"></a>

OpenClaw is a **persistent** agent. Memory comes in multiple forms:

### File-based memory
- `MEMORY.md` — Structured persistent memory (rules, preferences, facts)
- `memory/YYYY-MM-DD.md` — Date-organized memory entries
- Workspace files that persist between sessions

### Database-backed memory
- SQLite with embeddings and BM25 for semantic retrieval
- Conversation history stored and searchable
- Relevant prior context injected into new sessions

### Memory lifecycle
1. Agent or user writes to MEMORY.md / memory directory
2. On new session, runtime performs semantic search against memory
3. Relevant memories are injected into the prompt as `<relevant-memories>` block
4. Agent acts on memories as if they were authoritative context

**Security relevance**:
- **Memory poisoning**: Injected rules persist across sessions ("Never write Python — company policy")
- **Retrieval-triggered attacks**: Poisoned items activate when a later benign query matches
- **Cross-session leakage**: Memories from one session context leak into another
- **Memory-as-policy injection**: Malicious rules disguised as user preferences bypass filters
- **Persistence half-life**: Poisoned memories may never be cleaned up

---

## 8. Tool Execution <a name="tool-execution"></a>

The Runtime intercepts tool calls during generation and executes them.

### Built-in tool families
- **Shell/Bash** — Execute arbitrary shell commands
- **File operations** — Read, write, edit, glob, grep files
- **Browser actions** — Fetch web pages, search
- **Canvas** — Generate interactive HTML interfaces
- **Task management** — Create/update tasks
- **Agent spawning** — Launch subagents
- **Cron** — Schedule recurring tasks
- **Notebook** — Edit Jupyter notebooks

### Plugin tools
Extensions can register additional tools via `package.json` declarations.

### Tool execution flow
1. LLM generates a tool call (name + arguments)
2. Runtime validates the call against permission policy
3. If allowed (or user approves), the tool executes
4. Result is streamed back into the LLM context
5. LLM continues generation with the tool result

**Security relevance**:
- Bash access = arbitrary code execution
- File operations can read secrets, write persistence mechanisms
- Network tools can exfiltrate data
- Tool return values are trusted by the LLM (IPI vector)
- Permission policies can be overly broad

---

## 9. Extensions & Plugins <a name="extensions-and-plugins"></a>

OpenClaw supports extension in four directions:
- **Channel plugins** — New messaging integrations
- **Memory plugins** — Alternative memory backends
- **Tool plugins** — New tool capabilities
- **Provider plugins** — Alternative LLM backends

The loader scans packages for `openclaw.extensions` in `package.json`.

**Security relevance**:
- Third-party extensions are code-level trust decisions
- A malicious extension can register tools that exfiltrate data
- Extension manifests can override tool policies
- Supply chain attacks via typosquatting or dependency confusion

---

## 10. Scheduled Automation <a name="scheduled-automation"></a>

OpenClaw supports several automation mechanisms:

- **Cron jobs** — Recurring tasks on a schedule
- **Webhooks** — External triggers that invoke agent actions
- **Session tools** — Agent-to-agent communication and delegation

**Security relevance**:
- Cron jobs provide persistence (survive session boundaries)
- Webhooks are external ingress points (potential IPI)
- Agent-to-agent delegation can propagate compromises across trust boundaries

---

## 11. Sandbox & Isolation <a name="sandbox-and-isolation"></a>

### Docker sandboxing
- DM and group sessions run tools in ephemeral Docker containers
- Configurable filesystem exposure (bind mounts)
- Optional network access
- Resource limits (CPU, memory)

### Tool policy layering
- Permissions narrow as trust decreases
- Layered policy: global → session type → specific session

### Prompt injection defense
- Structural separation between system instructions and user messages
- Tool outputs wrapped as structured data
- Source metadata preserved
- Stronger models used when tools/files are involved

**Security relevance**:
- Sandbox bypasses (symlink escape, mount misconfiguration) grant host access
- `main` session typically has no sandboxing
- Tool policy misconfiguration can grant excessive permissions
- Prompt injection defenses are heuristic, not formally enforced

---

## 12. Security-Relevant Configuration Files <a name="config-files"></a>

| File | Purpose | Security Impact |
|------|---------|-----------------|
| `AGENTS.md` | Core agent behavior instructions | Poisoning alters all agent decisions |
| `SOUL.md` | Personality and style | Can weaken safety behaviors |
| `TOOLS.md` | Tool-use conventions | Can authorize dangerous tool patterns |
| `MEMORY.md` | Persistent memory | Poisoning persists across sessions |
| `skills/*/SKILL.md` | Skill definitions | Malicious skills become instructions |
| `settings.json` | Permissions, hooks, env vars | Overly permissive configs weaken defenses |
| `package.json` | Extension declarations | Malicious extensions get code execution |
| `.env` / env files | API keys, secrets | Exfiltration targets |
| `hooks/` | Event-triggered scripts | Can be modified for persistence |

---

## 13. Attack Surface Map <a name="attack-surface-map"></a>

```
                    External Inputs
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼─────┐   ┌─────▼─────┐
    │ Channel │    │   Files   │   │   Web /   │
    │Messages │    │ (IPI via  │   │  Tool     │
    │(DPI/IPI)│    │  README,  │   │  Returns  │
    │         │    │  docs)    │   │  (IPI)    │
    └────┬────┘    └─────┬─────┘   └─────┬─────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
                    ┌────▼────┐
                    │ Prompt  │ ◄── AGENTS.md, SOUL.md, TOOLS.md
                    │Assembly │ ◄── Skills (SKILL.md)
                    │         │ ◄── Memory (MEMORY.md, retrieval)
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │   LLM   │
                    │Decision │
                    └────┬────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────▼───┐ ┌───▼────┐ ┌───▼────┐
         │  Bash  │ │  File  │ │Network │
         │  Exec  │ │  Ops   │ │  Ops   │
         └────┬───┘ └───┬────┘ └───┬────┘
              │         │          │
              ▼         ▼          ▼
         Host System  Filesystem  External
         (processes,  (secrets,   Services
          resources)   configs)   (exfil)
```

### High-value targets for attackers
1. **API keys / secrets** in `.env`, environment variables, config files
2. **SSH keys** in `~/.ssh/`
3. **MEMORY.md** for persistent behavioral poisoning
4. **AGENTS.md / TOOLS.md** for instruction override
5. **Skills directory** for supply chain compromise
6. **Cron configuration** for persistence installation
7. **Host filesystem** for sandbox escape
8. **Network** for data exfiltration
