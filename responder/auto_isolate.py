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
import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "collector" / "events.sqlite"
STATE_PATH = Path(__file__).resolve().parents[1] / "collector" / "handled_events.json"
CRITICAL_SCORE = 80                # focus_score > 80 → critical
RESPONSE_MODE = os.getenv("ISOLATE_MODE", "kill")   # kill | nsenter
TIME_WINDOW = 3600                 # Only consider events from last hour (3600 seconds)

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

def load_handled_events():
    """Load the set of handled event IDs from persistent state."""
    if not STATE_PATH.exists():
        return {}
    try:
        with open(STATE_PATH, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_handled_events(handled):
    """Save the set of handled event IDs to persistent state."""
    try:
        with open(STATE_PATH, 'w') as f:
            json.dump(handled, f)
    except:
        pass

def get_critical_events():
    """Return a list of (pid, uid, user, focus_score, ts) where score > CRITICAL_SCORE and within TIME_WINDOW."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Only consider recent events within the time window
    cutoff_time = int(time.time()) - TIME_WINDOW

    # The same scoring query we used in the alert bot, but limited to >80 and recent events
    cur.execute("""
        WITH rare_exec AS (
            SELECT pid, uid, user, exe, ts
            FROM events
            WHERE action='exec' AND ts >= ? AND (
                exe LIKE '%/racket' OR exe LIKE '%/nim' OR exe LIKE '%/julia' OR
                exe LIKE '%/zig' OR exe LIKE '%/lua%' OR exe LIKE '%/lua5.4%')
        ),
        target_access AS (
            SELECT pid, file_path
            FROM events
            WHERE action='open' AND ts >= ? AND (
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
    """, (cutoff_time, cutoff_time, CRITICAL_SCORE))

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
    nsenter cannot genuinely move an existing process to a new namespace.
    Fall back to kill mode as the nsenter approach is ineffective.
    For genuine containment, eBPF, cgroups, or firewall rules would be needed.
    Note: Absolute paths /usr/sbin/ip and /usr/bin/nsenter would be used if this were implemented.
    """
    print(f"Warning: nsenter mode cannot genuinely isolate PID {pid}")
    tg_notify(f"⚠️ <b>nsenter mode ineffective</b>\nFalling back to kill for PID={pid}")
    kill_process(pid)

def main():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    # Load previously handled events
    handled = load_handled_events()

    events = get_critical_events()
    if not events:
        print("No critical events detected")
        return

    print(f"Found {len(events)} critical event(s)")

    for pid, uid, user, score, ts in events:
        # Create stable event ID based on PID and timestamp
        event_id = f"{pid}_{ts}"

        # Skip if already handled
        if event_id in handled:
            print(f"Event {event_id} already handled, skipping")
            continue

        # Defensive: double‑check that the pid still exists
        if not Path(f"/proc/{pid}").exists():
            print(f"Process {pid} no longer exists, skipping")
            # Mark as handled to avoid future checks
            handled[event_id] = time.time()
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

        # Mark event as handled after processing
        handled[event_id] = time.time()

    # Clean up old handled events (older than TIME_WINDOW)
    cutoff = time.time() - TIME_WINDOW
    handled = {k: v for k, v in handled.items() if v > cutoff}

    # Save updated state
    save_handled_events(handled)

if __name__ == "__main__":
    main()
