#!/bin/bash
# find_openclaw.sh - Discover the OpenClaw installation on this system
#
# Searches common locations and running processes to find OpenClaw.
# Outputs the detected path and configuration summary.
#
# Usage:
#   bash find_openclaw.sh                          # Human-readable text output
#   bash find_openclaw.sh --json OUT               # Machine-readable JSON manifest to OUT
#   bash find_openclaw.sh --path DIR               # Use DIR directly (skip auto-detection)
#   bash find_openclaw.sh --path DIR --json OUT    # Use DIR directly, output JSON

set -euo pipefail

JSON_MODE=false
JSON_OUT=""
FOUND=""

while [ $# -gt 0 ]; do
    case "$1" in
        --json)
            JSON_MODE=true
            JSON_OUT="${2:-/tmp/openclaw_discovery.json}"
            shift 2
            ;;
        --path)
            if [ -z "${2:-}" ]; then
                echo "[!] --path requires a directory argument" >&2
                exit 1
            fi
            FOUND="$2"
            shift 2
            ;;
        *)
            echo "[!] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# ── Helper: check if a file exists and return its path or "null" ──
file_or_null() { [ -f "$1" ] && echo "\"$1\"" || echo "null"; }
# Check multiple candidate paths, return the first that exists
file_or_null_multi() { for p in "$@"; do [ -f "$p" ] && echo "\"$p\"" && return; done; echo "null"; }

log() { $JSON_MODE || echo "$@"; }

if [ -n "$FOUND" ]; then
    # --path was provided, validate it
    if [ ! -d "$FOUND" ]; then
        echo "[!] Specified path does not exist: $FOUND" >&2
        if $JSON_MODE; then
            echo "{\"openclaw_root\": null, \"error\": \"Specified path does not exist: $FOUND\"}" > "$JSON_OUT"
            echo "$JSON_OUT"
        fi
        exit 1
    fi
    log "[+] Using specified path: $FOUND"
else

log "=== OpenClaw Installation Discovery ==="
log ""

# 1. Check environment variables
for VAR in OPENCLAW_HOME CLAW_HOME OPENCLAW_DIR OPENCLAW_STATE_DIR; do
    VAL="${!VAR:-}"
    if [ -n "$VAL" ] && [ -d "$VAL" ]; then
        log "[+] Found via \$$VAR: $VAL"
        FOUND="$VAL"
        break
    fi
done

# 2. Check common installation paths
if [ -z "$FOUND" ]; then
    COMMON_PATHS=(
        "$HOME/.openclaw"
        "$HOME/.config/openclaw"
        "$HOME/openclaw"
        "/opt/openclaw"
        "/usr/local/openclaw"
        "$HOME/.local/share/openclaw"
    )
    for P in "${COMMON_PATHS[@]}"; do
        if [ -d "$P" ]; then
            log "[+] Found at common path: $P"
            FOUND="$P"
            break
        fi
    done
fi

# 3. Check for OpenClaw-style config files in current directory tree
if [ -z "$FOUND" ]; then
    AGENTS_FILE=$(find "${PWD}" -maxdepth 3 -name "AGENTS.md" -type f 2>/dev/null | head -1)
    if [ -n "$AGENTS_FILE" ]; then
        FOUND=$(dirname "$AGENTS_FILE")
        log "[+] Found AGENTS.md at: $FOUND"
    fi
fi

# 4. Check for .claude directory (Claude Code / OpenClaw config)
if [ -z "$FOUND" ]; then
    CLAUDE_DIRS=(
        "$HOME/.claude"
        "${PWD}/.claude"
    )
    for P in "${CLAUDE_DIRS[@]}"; do
        if [ -d "$P" ]; then
            log "[+] Found .claude directory: $P"
            FOUND="$P"
            break
        fi
    done
fi

# 5. Check running processes
if [ -z "$FOUND" ]; then
    PROCS=$(pgrep -af "openclaw|claw-gateway|claw-runtime" 2>/dev/null || true)
    if [ -n "$PROCS" ]; then
        log "[+] Found running OpenClaw processes:"
        log "$PROCS"
        PROC_PATH=$(echo "$PROCS" | grep -oP '(?<=--config\s|--root\s|--home\s)\S+' | head -1)
        if [ -n "$PROC_PATH" ] && [ -d "$PROC_PATH" ]; then
            FOUND="$PROC_PATH"
        fi
    fi
fi

# 6. Check npm global installs
if [ -z "$FOUND" ]; then
    NPM_PATH=$(npm list -g --depth=0 2>/dev/null | grep -i "openclaw" | head -1 || true)
    if [ -n "$NPM_PATH" ]; then
        log "[+] Found npm global install: $NPM_PATH"
    fi
fi

# 7. Check pip installs
if [ -z "$FOUND" ]; then
    PIP_PATH=$(pip show openclaw 2>/dev/null | grep "Location:" | awk '{print $2}' || true)
    if [ -n "$PIP_PATH" ]; then
        log "[+] Found pip install: $PIP_PATH"
        FOUND="$PIP_PATH"
    fi
fi

log ""

if [ -z "$FOUND" ]; then
    if $JSON_MODE; then
        echo '{"openclaw_root": null, "error": "OpenClaw installation not found"}' > "$JSON_OUT"
        echo "$JSON_OUT"
    else
        echo "[!] OpenClaw installation not found automatically."
        echo "[!] Please provide the installation path manually."
        echo "OPENCLAW_ROOT=NOT_FOUND"
    fi
    exit 1
fi

fi  # end of --path vs auto-detection branch

# ── Detect OpenClaw runtime binary ──
OPENCLAW_BIN=""
for BIN in \
    "$(which openclaw 2>/dev/null || true)" \
    "$FOUND/openclaw.mjs" \
    "$FOUND/dist/entry.js" \
    "$(npm root -g 2>/dev/null)/@anthropic/openclaw/openclaw.mjs" \
    "$(npm root -g 2>/dev/null)/openclaw/openclaw.mjs"; do
    if [ -n "$BIN" ] && [ -f "$BIN" ]; then
        OPENCLAW_BIN="$BIN"
        break
    fi
done

# ── Detect OpenClaw version ──
OC_VERSION="unknown"
if [ -n "$OPENCLAW_BIN" ]; then
    OC_VERSION=$(node "$OPENCLAW_BIN" --version 2>/dev/null | head -1 || echo "unknown")
elif [ -f "$FOUND/package.json" ]; then
    OC_VERSION=$(python3 -c "import json; print(json.load(open('$FOUND/package.json')).get('version','unknown'))" 2>/dev/null || echo "unknown")
fi

# ── Detect Node.js version ──
NODE_VERSION=$(node --version 2>/dev/null || echo "not found")

# ── Profile config files ──
_agents_md=$(file_or_null_multi "$FOUND/AGENTS.md" "$FOUND/workspace/AGENTS.md")
_soul_md=$(file_or_null_multi "$FOUND/SOUL.md" "$FOUND/workspace/SOUL.md")
_tools_md=$(file_or_null_multi "$FOUND/TOOLS.md" "$FOUND/workspace/TOOLS.md")
_memory_md=$(file_or_null_multi "$FOUND/MEMORY.md" "$FOUND/workspace/MEMORY.md")
_openclaw_json=$(file_or_null "$FOUND/openclaw.json")
_package_json=$(file_or_null "$FOUND/package.json")
_boot_md=$(file_or_null "$FOUND/workspace/BOOT.md")

# Try alternate paths for .env
_env_file="null"
for EF in "$FOUND/.env" "$FOUND/workspace/.env" "$HOME/.openclaw/.env"; do
    if [ -f "$EF" ]; then _env_file="\"$EF\""; break; fi
done

# Settings
_settings_json="null"
for SF in "$FOUND/settings.json" "$FOUND/.claude/settings.json" "$HOME/.claude/settings.json"; do
    if [ -f "$SF" ]; then _settings_json="\"$SF\""; break; fi
done

# ── Skills ──
SKILLS_DIR=""
SKILLS_LIST="[]"
for SD in "$FOUND/workspace/skills" "$FOUND/skills" "$FOUND/.claude/skills" "$FOUND/plugins"; do
    if [ -d "$SD" ]; then
        SKILLS_DIR="$SD"
        # Build JSON array of skill names
        SKILLS_LIST=$(find "$SD" -name "SKILL.md" -type f 2>/dev/null | while read SK; do
            dirname "$SK" | xargs basename
        done | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
        break
    fi
done

# ── Memory ──
MEMORY_DIR=""
MEMORY_TYPE="none"
MEM_ENTRY_COUNT=0
for MD in "$FOUND/memory" "$FOUND/workspace/memory" "$FOUND/.claude/memory" "$FOUND/memories" "$FOUND/agents/default/sessions"; do
    if [ -d "$MD" ]; then
        MEMORY_DIR="$MD"
        MEM_ENTRY_COUNT=$(find "$MD" -name "*.md" -o -name "*.json" 2>/dev/null | wc -l)
        MEMORY_TYPE="file"
        break
    fi
done
# Check for SQLite memory
if find "$FOUND" -maxdepth 3 -name "*.db" -o -name "*.sqlite" 2>/dev/null | head -1 | grep -q .; then
    MEMORY_TYPE="sqlite"
fi
if [ "$MEMORY_TYPE" = "file" ] && find "$FOUND" -maxdepth 3 -name "*.db" -o -name "*.sqlite" 2>/dev/null | head -1 | grep -q .; then
    MEMORY_TYPE="both"
fi
[ -f "$FOUND/MEMORY.md" ] && [ "$MEMORY_TYPE" = "none" ] && MEMORY_TYPE="file"

# ── Hooks ──
HOOKS_DIR=""
HOOKS_LIST="[]"
for HD in "$FOUND/workspace/hooks" "$FOUND/hooks" "$FOUND/.claude/hooks"; do
    if [ -d "$HD" ]; then
        HOOKS_DIR="$HD"
        HOOKS_LIST=$(ls -1 "$HD" 2>/dev/null | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
        break
    fi
done

# ── Workspace ──
WORKSPACE_DIR=""
for WD in "$FOUND/workspace" "$FOUND/.openclaw/workspace"; do
    if [ -d "$WD" ]; then WORKSPACE_DIR="$WD"; break; fi
done

# ── Cron ──
HAS_CRON=false
CRON_LIST="[]"
CRON_ENTRIES=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || true)
if [ -n "$CRON_ENTRIES" ]; then
    HAS_CRON=true
    CRON_LIST=$(echo "$CRON_ENTRIES" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo "[]")
fi

# ── Gateway binding ──
GATEWAY_BIND="unknown"
if [ -f "$FOUND/openclaw.json" ]; then
    GATEWAY_BIND=$(python3 -c "
import json
with open('$FOUND/openclaw.json') as f:
    c = json.load(f)
gw = c.get('gateway', {})
bind = gw.get('bind', '127.0.0.1')
port = gw.get('port', 18789)
print(f'{bind}:{port}')
" 2>/dev/null || echo "unknown")
fi

# ── MCP servers ──
MCP_CONFIGS="[]"
for MC in "$FOUND/.mcp.json" "$FOUND/workspace/.mcp.json" "$FOUND/mcp.json"; do
    if [ -f "$MC" ]; then
        MCP_CONFIGS=$(python3 -c "
import json
with open('$MC') as f:
    data = json.load(f)
servers = data.get('mcpServers', data.get('servers', {}))
result = []
for name, cfg in servers.items():
    result.append({'name': name, 'config_path': '$MC'})
print(json.dumps(result))
" 2>/dev/null || echo "[]")
        break
    fi
done

# ── Extensions / plugins ──
EXTENSIONS_LIST="[]"
if [ -f "$FOUND/openclaw.json" ]; then
    EXTENSIONS_LIST=$(python3 -c "
import json
with open('$FOUND/openclaw.json') as f:
    c = json.load(f)
plugins = list(c.get('plugins', {}).keys())
print(json.dumps(plugins))
" 2>/dev/null || echo "[]")
fi

# ════════════════════════════════════════════
# Output
# ════════════════════════════════════════════

if $JSON_MODE; then
    # ── JSON manifest ──
    cat > "$JSON_OUT" << JSONEOF
{
  "openclaw_root": "$FOUND",
  "openclaw_version": "$OC_VERSION",
  "openclaw_binary": $([ -n "$OPENCLAW_BIN" ] && echo "\"$OPENCLAW_BIN\"" || echo "null"),
  "node_version": "$NODE_VERSION",
  "gateway_binding": "$GATEWAY_BIND",
  "config_files": {
    "agents_md": $_agents_md,
    "soul_md": $_soul_md,
    "tools_md": $_tools_md,
    "memory_md": $_memory_md,
    "openclaw_json": $_openclaw_json,
    "env_file": $_env_file,
    "settings_json": $_settings_json,
    "package_json": $_package_json,
    "boot_md": $_boot_md
  },
  "skills_dir": $([ -n "$SKILLS_DIR" ] && echo "\"$SKILLS_DIR\"" || echo "null"),
  "skills": $SKILLS_LIST,
  "memory_dir": $([ -n "$MEMORY_DIR" ] && echo "\"$MEMORY_DIR\"" || echo "null"),
  "memory_type": "$MEMORY_TYPE",
  "memory_entry_count": $MEM_ENTRY_COUNT,
  "hooks_dir": $([ -n "$HOOKS_DIR" ] && echo "\"$HOOKS_DIR\"" || echo "null"),
  "hooks": $HOOKS_LIST,
  "workspace_dir": $([ -n "$WORKSPACE_DIR" ] && echo "\"$WORKSPACE_DIR\"" || echo "null"),
  "has_cron": $HAS_CRON,
  "cron_entries": $CRON_LIST,
  "mcp_servers": $MCP_CONFIGS,
  "extensions": $EXTENSIONS_LIST
}
JSONEOF
    echo "$JSON_OUT"
else
    # ── Human-readable text output ──
    echo "=== Installation Profile ==="
    echo "OPENCLAW_ROOT=$FOUND"
    echo "OPENCLAW_VERSION=$OC_VERSION"
    echo "OPENCLAW_BINARY=${OPENCLAW_BIN:-not found}"
    echo "NODE_VERSION=$NODE_VERSION"
    echo "GATEWAY_BINDING=$GATEWAY_BIND"
    echo ""

    echo "--- Configuration Files ---"
    for FILE in AGENTS.md SOUL.md TOOLS.md MEMORY.md openclaw.json package.json .env; do
        FULL="$FOUND/$FILE"
        if [ -f "$FULL" ]; then
            SIZE=$(wc -l < "$FULL" 2>/dev/null || echo "?")
            echo "  [PRESENT] $FILE ($SIZE lines)"
        else
            echo "  [ABSENT]  $FILE"
        fi
    done

    echo ""
    echo "--- Skills ---"
    if [ -n "$SKILLS_DIR" ]; then
        SKILL_COUNT=$(find "$SKILLS_DIR" -name "SKILL.md" -type f 2>/dev/null | wc -l)
        echo "  Skills directory: $SKILLS_DIR ($SKILL_COUNT skills)"
        find "$SKILLS_DIR" -name "SKILL.md" -type f 2>/dev/null | while read SK; do
            echo "    - $(dirname "$SK" | xargs basename)"
        done
    else
        echo "  [NO SKILLS DIRECTORY FOUND]"
    fi

    echo ""
    echo "--- Memory ---"
    if [ -n "$MEMORY_DIR" ]; then
        echo "  Memory directory: $MEMORY_DIR ($MEM_ENTRY_COUNT entries)"
    fi
    [ -f "$FOUND/MEMORY.md" ] && echo "  MEMORY.md: present ($(wc -l < "$FOUND/MEMORY.md") lines)"
    echo "  Memory type: $MEMORY_TYPE"

    echo ""
    echo "--- MCP Servers ---"
    echo "  $MCP_CONFIGS"

    echo ""
    echo "--- Hooks & Automation ---"
    if [ -n "$HOOKS_DIR" ]; then
        echo "  Hooks directory: $HOOKS_DIR"
        ls -1 "$HOOKS_DIR" 2>/dev/null | while read H; do echo "    - $H"; done
    fi
    echo "  Cron: $HAS_CRON ($CRON_LIST)"

    echo ""
    echo "--- Extensions ---"
    echo "  $EXTENSIONS_LIST"

    echo ""
    echo "--- Settings ---"
    if [ "$_settings_json" != "null" ]; then
        SF=$(echo "$_settings_json" | tr -d '"')
        echo "  Settings file: $SF"
        cat "$SF" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for k, v in d.items():
        if 'key' in k.lower() or 'token' in k.lower() or 'secret' in k.lower():
            print(f'    {k}: [REDACTED]')
        else:
            print(f'    {k}: {v}')
except: pass
" 2>/dev/null || echo "    (could not parse)"
    fi

    echo ""
    echo "=== Discovery Complete ==="
fi
