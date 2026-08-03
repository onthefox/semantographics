#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
check_commit.py
----------------
Utility used by both client‑side pre‑commit and server‑side pre‑receive
hooks. It receives a list of file paths (one per line) on stdin,
examines the content and exits with:
  0 – ok
  1 – violation detected
"""

import sys
import re
import os
import html
from pathlib import Path

RARE_INTERPRETERS = re.compile(r'\b(racket|nim|julia|zig|lua)\b', re.IGNORECASE)
SECRET_KEY_USAGE = re.compile(r'\bSECRET_KEY\b')

# Telegram notification (optional – set env vars TG_TOKEN & TG_CHAT)
TG_TOKEN = os.getenv('TG_TOKEN')
TG_CHAT  = os.getenv('TG_CHAT')

def tg_notify(text: str):
    if not TG_TOKEN or not TG_CHAT:
        return
    try:
        import requests
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        requests.post(url, data={'chat_id': TG_CHAT, 'text': text, 'parse_mode': 'HTML'}, timeout=4)
    except Exception:
        pass

def main():
    violated = False
    offending = []

    for line in sys.stdin:
        # Each line is expected to be either:
        # - NUL-delimited: <path>\0<blob_content>
        # - or just path (fallback to worktree read)
        parts = line.rstrip('\n').split('\0', 1)
        path = parts[0].strip()
        if not path:
            continue

        try:
            if len(parts) == 2:
                # Blob content was provided
                content = parts[1]
            else:
                # Fallback to reading from worktree
                if not Path(path).is_file():
                    continue
                content = Path(path).read_text(errors='ignore')
        except Exception:
            continue

        if RARE_INTERPRETERS.search(content) and SECRET_KEY_USAGE.search(content):
            violated = True
            offending.append(path)

    if violated:
        msg = ("🚫 <b>Git‑hook violation</b>\n"
               "Files contain a rare interpreter *and* reference to <code>SECRET_KEY</code>:\n"
               + "\n".join(f"- <code>{html.escape(p, quote=True)}</code>" for p in offending))
        tg_notify(msg)
        sys.stderr.write("\n".join(offending) + "\n")
        sys.exit(1)

    sys.exit(0)

if __name__ == '__main__':
    main()
