# LLM Suspicion Detector

A comprehensive security monitoring system that detects suspicious activity involving rare programming language interpreters, polymorphic payloads, and sensitive file access patterns.

## Repository Layout

```
llm‑suspicion‑detector/
├─ README.md
├─ requirements.txt
│
├─ falco/
│   ├─ falco.yaml                     # Falco daemon config (incl. YARA)
│   └─ rules/
│       ├─ rare_interpreter.rules     # Falco rules that fire on rare runtimes
│       └─ yara_rules.yar             # YARA signatures (polymorphic payloads)
│
├─ collector/
│   ├─ auditd_rules.conf              # auditd rules to capture exec/open/connect
│   ├─ parser.py                      # Simple Python parser → SQLite (events.sqlite)
│   └─ events.sqlite                  # (created at first run)
│
├─ responder/
│   └─ auto_isolate.py                # Reacts to high focus_score (kill / net‑ns)
│
├─ git‑hooks/
│   ├─ pre‑commit                     # Git pre‑commit hook (POSIX shell wrapper)
│   ├─ pre-receive                    # Git server-side pre-receive hook
│   └─ check_commit.py                # Python helper that scans the diff
│
└─ webui/
    ├─ app.py                         # Flask UI (read‑only view of events.sqlite)
    └─ templates/
        └─ index.html
```

## Components

### 1. Falco + YARA (Polymorphic Payload Detection)

Falco monitors for execution of rare interpreters (Racket, Nim, Julia, Zig, Lua) and uses YARA to scan process memory for known Metasploit-style shellcode patterns.

**Deploy:**
```bash
sudo cp -r falco/* /etc/falco/
sudo systemctl restart falco
```

### 2. Event Collector

The collector uses `auditd` to capture system calls (execve, open, connect) and stores them in a SQLite database for analysis.

**Setup:**
```bash
sudo cp collector/auditd_rules.conf /etc/audit/rules.d/auditd_rules.rules
sudo augenrules --load
sudo python3 collector/parser.py &
```

### 3. Auto-Isolate Responder

Periodically scans the events database for processes with high "focus scores" (processes that execute rare interpreters AND access sensitive files). Can either:
- **Kill** the process immediately
- **Isolate** it in a separate network namespace

**Schedule via cron:**
```bash
*/2 * * * * ISOLATE_MODE=kill /path/to/responder/auto_isolate.py >> /var/log/auto_isolate.log 2>&1
```

Set mode by placing `ISOLATE_MODE=kill` or `ISOLATE_MODE=nsenter` inline before the command in the crontab entry

### 4. Git Hooks

Blocks commits that contain both:
- References to rare interpreters (racket, nim, julia, zig, lua)
- References to `SECRET_KEY`

**Client-side install:**
```bash
cp git-hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

**Server-side install:**
```bash
cp git-hooks/pre-receive /path/to/bare/repo/hooks/
chmod +x /path/to/bare/repo/hooks/pre-receive
```

### 5. Web UI

Flask-based read-only interface for analysts to explore captured events.

**Run:**
```bash
cd webui
pip install -r requirements.txt
python3 app.py
```

Then browse to `http://localhost:5000/`

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
sudo apt-get install -y auditd falco iproute2

# Enable auditd rules
sudo cp collector/auditd_rules.conf /etc/audit/rules.d/auditd_rules.rules
sudo augenrules --load

# Start the collector
sudo python3 collector/parser.py &

# Deploy Falco
sudo cp -r falco/* /etc/falco/
sudo systemctl restart falco

# Install and schedule responder
sudo mkdir -p /opt/llm-suspicion-detector/responder
sudo cp responder/auto_isolate.py /opt/llm-suspicion-detector/responder/auto_isolate.py
sudo chmod 755 /opt/llm-suspicion-detector/responder/auto_isolate.py
sudo chown root:root /opt/llm-suspicion-detector/responder/auto_isolate.py
echo "*/2 * * * * root ISOLATE_MODE=kill /opt/llm-suspicion-detector/responder/auto_isolate.py >> /var/log/auto_isolate.log 2>&1" | sudo tee -a /etc/crontab

# Install git hooks
cp git-hooks/pre-commit .git/hooks/

# Run web UI
cd webui && python3 app.py
```

## Security Notes

- **auto_isolate.py** runs as root – limit execution via cron only
- **Telegram tokens** should be set via environment variables, never committed
- **Web UI** is read-only but should be behind authentication if exposed
- **SQLite DB** should have restricted permissions: `chmod 660 collector/events.sqlite`

## License

MIT
