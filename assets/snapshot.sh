#!/bin/bash
SNAPSHOT_DIR="${1:-/monitor/snapshots}"
SNAPSHOT_NAME="${2:-snapshot}"
mkdir -p "$SNAPSHOT_DIR"
# File checksums
find /home/audit/.openclaw -type f -exec md5sum {} \; 2>/dev/null | sort > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.md5"
# File metadata
find /home/audit/.openclaw -type f -printf "%p %s %T@\n" 2>/dev/null | sort > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.files"
# Process list
ps aux > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.procs"
# Network connections
ss -tlnp > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.net" 2>/dev/null || true
# Crontab
crontab -l > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.cron" 2>/dev/null || echo "no crontab" > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.cron"
# MEMORY.md state
cp /home/audit/.openclaw/MEMORY.md "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.memory" 2>/dev/null || true
# Skills directory listing
find /home/audit/.openclaw/workspace/skills -name "SKILL.md" 2>/dev/null | sort > "$SNAPSHOT_DIR/${SNAPSHOT_NAME}.skills"
echo "Snapshot saved: $SNAPSHOT_DIR/${SNAPSHOT_NAME}"
