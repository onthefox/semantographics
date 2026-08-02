#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
parser.py
---------
Simple Python parser that reads auditd logs and inserts events into SQLite.
Creates events.sqlite in the same directory if it doesn't exist.

Run as root to read auditd logs:
    sudo python3 parser.py
"""

import sqlite3
import re
import os
import sys
import time
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "events.sqlite"
AUDIT_LOG = "/var/log/audit/audit.log"

def init_db():
    """Create the events table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            pid INTEGER,
            uid INTEGER,
            user TEXT,
            cmd TEXT,
            exe TEXT,
            action TEXT,
            file_path TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pid ON events(pid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_user ON events(user)")
    conn.commit()
    conn.close()

def parse_audit_line(line):
    """Parse a single auditd log line and extract relevant fields."""
    event = {}
    
    # Extract timestamp
    ts_match = re.search(r'msg=audit\((\d+\.?\d*)', line)
    if ts_match:
        event['ts'] = int(float(ts_match.group(1)))
    
    # Extract syscall type
    if 'syscall=59' in line or 'execve' in line:
        event['action'] = 'exec'
    elif 'syscall=2' in line or 'syscall=257' in line or 'open' in line:
        event['action'] = 'open'
    elif 'syscall=42' in line or 'connect' in line:
        event['action'] = 'connect'
    elif 'syscall=41' in line or 'socket' in line:
        event['action'] = 'socket'
    else:
        return None
    
    # Extract pid
    pid_match = re.search(r'pid=(\d+)', line)
    if pid_match:
        event['pid'] = int(pid_match.group(1))
    
    # Extract uid
    uid_match = re.search(r'uid=(\d+)', line)
    if uid_match:
        event['uid'] = int(uid_match.group(1))
    
    # Extract exe (executable path)
    exe_match = re.search(r'exe="([^"]+)"', line)
    if exe_match:
        event['exe'] = exe_match.group(1)
    
    # Extract comm (command name)
    comm_match = re.search(r'comm="([^"]+)"', line)
    if comm_match:
        event['cmd'] = comm_match.group(1)
    
    # Extract full cmdline if available
    cmdline_match = re.search(r'argc=\d+ argv=\[([^\]]+)\]', line)
    if cmdline_match:
        event['cmd'] = cmdline_match.group(1)
    
    # Extract file path for open calls
    path_match = re.search(r'name="([^"]+)"', line)
    if path_match:
        event['file_path'] = path_match.group(1)
    
    # Extract network info for connect calls
    saddr_match = re.search(r'saddr=([0-9A-Fa-f]+)', line)
    if saddr_match:
        # Simple hex to IP conversion (IPv4 only)
        addr_hex = saddr_match.group(1)
        if len(addr_hex) == 8:
            try:
                octets = [int(addr_hex[i:i+2], 16) for i in range(0, 8, 2)]
                # Convert from network byte order
                event['dst_ip'] = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}"
            except:
                pass
    
    dport_match = re.search(r'dport=(\d+)', line)
    if dport_match:
        event['dst_port'] = int(dport_match.group(1))
    
    return event if event else None

def get_username(uid):
    """Convert UID to username."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)

def insert_event(conn, event):
    """Insert a parsed event into the database."""
    if 'uid' in event and 'user' not in event:
        event['user'] = get_username(event['uid'])
    
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (ts, pid, uid, user, cmd, exe, action, file_path, src_ip, dst_ip, dst_port)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get('ts', int(time.time())),
        event.get('pid'),
        event.get('uid'),
        event.get('user'),
        event.get('cmd'),
        event.get('exe'),
        event.get('action'),
        event.get('file_path'),
        event.get('src_ip'),
        event.get('dst_ip'),
        event.get('dst_port')
    ))
    conn.commit()

def tail_log(log_path):
    """Tail the audit log file and yield new lines."""
    if not os.path.exists(log_path):
        print(f"Warning: {log_path} does not exist. Waiting...", file=sys.stderr)
        while not os.path.exists(log_path):
            time.sleep(1)
    
    with open(log_path, 'r') as f:
        # Go to the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()

def main():
    print(f"Initializing database at {DB_PATH}")
    init_db()
    
    print(f"Starting audit log parser, watching {AUDIT_LOG}")
    conn = sqlite3.connect(DB_PATH)
    
    try:
        for line in tail_log(AUDIT_LOG):
            if not line or 'type=' not in line:
                continue
            
            event = parse_audit_line(line)
            if event:
                insert_event(conn, event)
                print(f"[{datetime.fromtimestamp(event.get('ts', time.time()))}] {event.get('action')} pid={event.get('pid')} exe={event.get('exe')}")
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
