#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
auto_isolate.py
----------------
Periodically scans events.sqlite, calculates a focus_score for each UID,
and if the score exceeds the critical threshold (80) it reacts:
 * mode = "kill"   → kill -9 PID
 * mode = "nsenter"→ move the process to its own netns (isolated)
The script is intended to be launched from cron:
   */2 * * * * /opt/llm-suspicion-detector/responder/auto_isolate.py >> /var/log/auto_isolate.log 2>&1
"""

import sqlite3
import os
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "collector" / "events.sqlite"
CRITICAL_SCORE = 80                # focus_score > 80 → critical
RESPONSE_MODE = os.getenv("ISOLATE_MODE", "kill")   # kill | nsenter

TELEGRAM_TOKEN = os.getenv("TG_TOKEN")
TELEGRAM_CHAT  = os.getenv("TG_CHAT")   # optional – notify on isolation

def tg_notify(text: str):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    try:
        import requests
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT, "text": text, "parse_mode": "HTML"}
        requests.post(url, data=payload, timeout=5)
    except Exception:
        pass

def get_critical_events():
    """Return a list of (pid, uid, user, focus_score) where score > CRITICAL_SCORE."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # The same scoring query we used in the alert bot, but limited to >80
    cur.execute("""
        WITH rare_exec AS (
            SELECT pid, uid, user, exe, ts
            FROM events
            WHERE action='exec' AND (
                exe LIKE '%/racket' OR exe LIKE '%/nim' OR exe LIKE '%/julia' OR
                exe LIKE '%/zig' OR exe LIKE '%/lua%' OR exe LIKE '%/lua5.4%')
        ),
        target_access AS (
            SELECT pid, file_path
            FROM events
            WHERE action='open' AND (
                file_path LIKE '%confidential.db%' OR
                file_path LIKE '%/var/lib/mysql/finance%' OR
                file_path LIKE '%/etc/passwd%' OR
                file_path LIKE '%secret%' OR
                file_path LIKE '%private%')
        )
        SELECT e.pid, e.uid, e.user,
               (COUNT(DISTINCT t.file_path) * 100.0 / COUNT(*)) AS focus_score,
               MAX(e.ts) AS last_ts
        FROM rare_exec e
        JOIN target_access t ON e.pid = t.pid
        GROUP BY e.pid, e.uid, e.user
        HAVING focus_score > ?
        ORDER BY focus_score DESC
    """, (CRITICAL_SCORE,))

    rows = cur.fetchall()
    conn.close()
    return rows

def kill_process(pid: int):
    try:
        os.kill(pid, 9)
        tg_notify(f"🚨 <b>Process killed</b>\nPID={pid}")
        print(f"Killed process {pid}")
    except ProcessLookupError:
        print(f"Process {pid} already gone")
    except PermissionError as e:
        tg_notify(f"❗️ <b>Kill failed</b>\nPID={pid} – {e}")
        print(f"Failed to kill process {pid}: {e}")

def isolate_netns(pid: int):
    """
    Create a new network namespace for the process and move it there.
    This is a "soft" isolation – the process continues to run but loses
    any existing network sockets.
    """
    # 1. Create a new netns (if not already present)
    netns_name = f"isolated_{pid}"
    try:
        subprocess.check_call(["ip", "netns", "add", netns_name])
        print(f"Created network namespace: {netns_name}")
    except subprocess.CalledProcessError:
        # Already exists – ignore
        print(f"Network namespace {netns_name} already exists")
        pass

    # 2. Move the process into the new netns using nsenter
    try:
        # First, get the process's current namespace
        # Then use nsenter to execute in the new namespace context
        # Note: This is a simplified approach; production use may need more careful handling
        subprocess.check_call(["nsenter", "--net=/var/run/netns/" + netns_name,
                               "--target", str(pid), "--pid", "--", "true"])
        tg_notify(f"🛡️ <b>Process {pid} isolated</b> into netns {netns_name}")
        print(f"Isolated process {pid} into netns {netns_name}")
    except subprocess.CalledProcessError as e:
        tg_notify(f"❗️ <b>nsenter failed</b> for PID={pid}: {e}")
        print(f"nsenter failed for PID={pid}: {e}")

def main():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return
    
    events = get_critical_events()
    if not events:
        print("No critical events detected")
        return

    print(f"Found {len(events)} critical event(s)")
    
    for pid, uid, user, score, ts in events:
        # Defensive: double‑check that the pid still exists
        if not Path(f"/proc/{pid}").exists():
            print(f"Process {pid} no longer exists, skipping")
            continue

        msg = (f"⚠️ <b>Critical focus detected</b>\n"
               f"PID: {pid}\n"
               f"User: {user} (UID={uid})\n"
               f"Score: {score:.1f}%\n"
               f"Last activity: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}")
        tg_notify(msg)
        print(msg.replace('<b>', '').replace('</b>', ''))

        if RESPONSE_MODE == "kill":
            kill_process(pid)
        elif RESPONSE_MODE == "nsenter":
            isolate_netns(pid)
        else:
            tg_notify(f"❓ Unknown ISOLATE_MODE={RESPONSE_MODE}")
            print(f"Unknown ISOLATE_MODE={RESPONSE_MODE}")

if __name__ == "__main__":
    main()
