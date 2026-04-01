#!/bin/bash
# Monitor setup script for the audit sandbox
# Initializes monitoring of the user's cloned OpenClaw environment

set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-/results}"
TASK_ID="${1:-unknown}"
TASK_DIR="$RESULTS_DIR/$TASK_ID"
OPENCLAW_HOME="${OPENCLAW_HOME:-/home/audit/.openclaw}"

mkdir -p "$TASK_DIR"

echo "=== Setting up monitoring for task: $TASK_ID ==="

# 1. Pre-test filesystem snapshot (user's actual config)
/monitor/snapshot.sh /monitor/snapshots before
echo "[+] Pre-test snapshot taken"

# 2. Start real-time filesystem event watcher
if command -v inotifywait &>/dev/null; then
    inotifywait -m -r --format '%T %w%f %e' --timefmt '%H:%M:%S' \
        "$OPENCLAW_HOME/" > "$TASK_DIR/fs_events.log" 2>/dev/null &
    echo "[+] Filesystem watcher started (PID: $!)"
fi

# 3. Record initial state
cp "$OPENCLAW_HOME/MEMORY.md" "$TASK_DIR/memory_before.md" 2>/dev/null || echo "No MEMORY.md" > "$TASK_DIR/memory_before.md"
echo "[+] Memory state recorded"

# 4. Record crontab
crontab -l > "$TASK_DIR/cron_before.txt" 2>/dev/null || echo "no crontab" > "$TASK_DIR/cron_before.txt"
echo "[+] Crontab state recorded"

# 5. Record processes
ps aux > "$TASK_DIR/procs_before.txt"
echo "[+] Process list recorded"

# 6. Record skills directory
find "$OPENCLAW_HOME/workspace/skills" -name "SKILL.md" 2>/dev/null | sort > "$TASK_DIR/skills_before.txt" || true
echo "[+] Skills directory recorded"

# 7. Start OpenClaw gateway log monitor
if [ -d "$OPENCLAW_HOME/logs" ]; then
    tail -f "$OPENCLAW_HOME/logs/"*.log > "$TASK_DIR/gateway.log" 2>/dev/null &
    echo "[+] Gateway log monitor started"
fi

echo "=== Monitoring ready ==="
