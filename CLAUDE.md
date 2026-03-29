# AssistantAudit-Agent — Project Knowledge Base

**Last updated:** 2026-03-28

## OVERVIEW

Lightweight Windows daemon that runs on the technician's machine during IT security audits. Connects to the AssistantAudit server via mTLS + WebSocket, receives task dispatches, executes audit tools (nmap, ORADAD, AD collectors), and uploads results.

- **Language:** Python 3.13
- **Platform:** Windows 10/11 (the technician's laptop, never domain-joined)
- **Server:** AssistantAudit backend at `https://<server>:8000`
- **Communication:** WebSocket over mTLS for real-time tasks, HTTPS for file upload
- **Auth:** JWT agent tokens, mTLS client certificates

## STRUCTURE

```
AssistantAudit-Agent/
├── src/
│   └── assistant_audit_agent/
│       ├── __init__.py
│       ├── main.py              Entry point — CLI and daemon startup
│       ├── config.py            Settings from agent.json + env
│       ├── enrollment.py        First-run enrollment flow
│       ├── websocket_client.py  WebSocket connection + reconnect
│       ├── heartbeat.py         Periodic heartbeat to server
│       ├── task_runner.py       Task execution dispatcher
│       ├── tools/               One module per audit tool
│       │   ├── __init__.py
│       │   ├── nmap_tool.py
│       │   ├── oradad_tool.py
│       │   └── ad_collector_tool.py
│       ├── uploader.py          Result upload via HTTPS + mTLS
│       └── logging_config.py    Structured logging
├── certs/                       mTLS certificates (created at enrollment)
│   ├── ca.pem
│   ├── agent.pem
│   └── agent.key
├── agent.json                   Local config (created at enrollment)
├── queue/                       Offline result queue (files waiting to upload)
├── tests/
├── pyproject.toml
├── CLAUDE.md                    This file
└── README.md
```

## HOW TO RUN

### First run (enrollment)
```powershell
assistant-audit-agent enroll --server https://server:8000 --code ABCD1234
```
This contacts the server, exchanges the enrollment code for a JWT + mTLS certs, and writes `agent.json`.

### Normal run (daemon)
```powershell
assistant-audit-agent start
```
Connects via WebSocket, sends heartbeats, waits for tasks.

### Install as Windows service (production)
```powershell
assistant-audit-agent install-service
assistant-audit-agent start-service
```

### Tests
```bash
pytest -q
```

## ARCHITECTURE

```
main.py
  └── enrollment.py (first run only)
  └── websocket_client.py (persistent connection)
        ├── heartbeat.py (every 30s)
        ├── task_runner.py (on task received)
        │     └── tools/nmap_tool.py
        │     └── tools/oradad_tool.py
        │     └── tools/ad_collector_tool.py
        └── uploader.py (on task complete)
```

## IMPLEMENTATION DECISIONS (BINDING)

1. **Python, not PowerShell** — The agent is a Python package, not a PS script. PowerShell is called only to execute specific tools (nmap, ORADAD).
2. **Single async event loop** — The agent uses asyncio for WebSocket + heartbeat + task execution. One event loop, no threads (except for subprocess execution).
3. **Offline queue** — If the server is unreachable, results are queued locally and uploaded when connectivity resumes.
4. **No DB** — The agent has no local database. State is in `agent.json` (config) and `queue/` (pending results).
5. **mTLS in production** — The agent uses client certificates for HTTPS and WebSocket connections.
6. **Tools are subprocess only** — The agent never imports tool code directly. nmap, ORADAD, and AD collectors are always executed as subprocesses.
7. **Server is the source of truth** — The agent never decides what to run. It waits for task dispatch from the server and executes exactly what's asked.

## ANTI-PATTERNS — NEVER DO THESE

- **NEVER store secrets in plaintext on disk**
- **NEVER execute arbitrary commands** — only whitelisted tools (nmap, oradad, ad_collector)
- **NEVER send results over plain HTTP** — always mTLS
- **NEVER hardcode the server URL** — read from agent.json
- **NEVER log credentials, JWT tokens, or enrollment codes**
- **NEVER use shell=True in subprocess calls**
- **NEVER modify the server's code from this repo**

## WORKFLOW RULES — ALWAYS DO THESE

- ALWAYS commit after completing a step
- ALWAYS run tests after each modification
- ALWAYS read this file before any structural change

## LANGUAGE CONVENTIONS

- **UI text, user-facing strings, comments, docstrings:** French
- **Code identifiers, variables, function names:** English

## CONFIG

Configuration is stored in `agent.json`, created automatically during enrollment.
