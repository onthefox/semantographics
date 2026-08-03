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
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/', methods=['GET'])
def index():
    db = get_db()
    # Simple filter handling
    pid   = request.args.get('pid')
    user  = request.args.get('user')
    start = request.args.get('start')
    end   = request.args.get('end')
    errors = []

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
            errors.append(f"Invalid start date format: {start}. Expected YYYY-MM-DD HH:MM:SS")
    if end:
        try:
            ts_end = int(datetime.datetime.strptime(end, "%Y-%m-%d %H:%M:%S").timestamp())
            conditions.append("ts <= ?")
            params.append(ts_end)
        except ValueError:
            errors.append(f"Invalid end date format: {end}. Expected YYYY-MM-DD HH:MM:SS")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    # Check if results are truncated
    count_query = "SELECT COUNT(*) FROM events"
    if conditions:
        count_query += " WHERE " + " AND ".join(conditions)

    total_count = db.execute(count_query, params).fetchone()[0]
    truncated = total_count > 500

    query += " ORDER BY ts DESC LIMIT 500"

    cur = db.execute(query, params)
    rows = cur.fetchall()
    return render_template('index.html', rows=rows, request=request, errors=errors, truncated=truncated, total_count=total_count)

@app.template_filter('datetime')
def datetime_filter(ts):
    """Convert Unix timestamp to formatted datetime string."""
    if ts is None:
        return ""
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, OSError):
        return str(ts)

if __name__ == '__main__':
    # Run on localhost only – expose via authenticated reverse‑proxy if needed
    host = os.getenv('WEBUI_HOST', '127.0.0.1')
    if host != '127.0.0.1':
        print("Warning: Binding to non-localhost. Ensure an authenticated reverse proxy is in place.")
    app.run(host=host, port=5000, debug=False)
