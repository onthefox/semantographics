#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, g
import sqlite3
from pathlib import Path
import os
import datetime

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "collector" / "events.sqlite"

app = Flask(__name__)

def get_db():
    """Get the SQLite database connection for the current application context.
    
    Returns:
    	sqlite3.Connection: The cached database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    """Close the request-scoped database connection when one is available."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/', methods=['GET'])
def index():
    """
    Render the event listing page with optional PID, user, and timestamp filters.
    
    Invalid timestamp filters are ignored. Results are ordered from newest to oldest and limited to 500 events.
    
    Returns:
        Response: The rendered event listing page.
    """
    db = get_db()
    # Simple filter handling
    pid   = request.args.get('pid')
    user  = request.args.get('user')
    start = request.args.get('start')
    end   = request.args.get('end')

    query = "SELECT rowid, ts, pid, uid, user, cmd, exe, action, file_path, src_ip, dst_ip, dst_port FROM events"
    conditions = []
    params = []

    if pid:
        conditions.append("pid = ?")
        params.append(pid)
    if user:
        conditions.append("user = ?")
        params.append(user)
    if start:
        try:
            ts_start = int(datetime.datetime.strptime(start, "%Y-%m-%d %H:%M:%S").timestamp())
            conditions.append("ts >= ?")
            params.append(ts_start)
        except ValueError:
            pass
    if end:
        try:
            ts_end = int(datetime.datetime.strptime(end, "%Y-%m-%d %H:%M:%S").timestamp())
            conditions.append("ts <= ?")
            params.append(ts_end)
        except ValueError:
            pass

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY ts DESC LIMIT 500"

    cur = db.execute(query, params)
    rows = cur.fetchall()
    return render_template('index.html', rows=rows, request=request)

@app.template_filter('datetime')
def datetime_filter(ts):
    """
    Format a Unix timestamp for display in templates.
    
    Parameters:
        ts: The Unix timestamp to format.
    
    Returns:
        str: The formatted timestamp, an empty string for None, or the original value converted to a string when the timestamp is invalid or unsupported.
    """
    if ts is None:
        return ""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, OSError):
        return str(ts)

if __name__ == '__main__':
    # Run on localhost only – expose via reverse‑proxy if needed
    app.run(host='0.0.0.0', port=5000, debug=False)
