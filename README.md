# Insider Threat Detector
<img width="1905" height="865" alt="image" src="https://github.com/user-attachments/assets/45ef2b6f-6b48-49a0-b5d6-6e4318e9dd5d" />

A full-stack insider threat monitoring system for Windows lab environments. A compiled C agent silently monitors endpoints and ships telemetry to a Python backend that scores risk and surfaces alerts through a real-time web dashboard.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Windows Endpoint                                               │
│                                                                 │
│  agent.exe  (C, native Win32 APIs, no dependencies)            │
│  ├── Thread: Process monitor   (Toolhelp32 snapshots)          │
│  ├── Thread: USB monitor       (WM_DEVICECHANGE messages)      │
│  ├── Thread: Clipboard monitor (OpenClipboard polling)         │
│  ├── Thread: Window monitor    (GetForegroundWindow polling)   │
│  ├── Thread: Network monitor   (GetIfTable byte deltas)        │
│  └── Thread: Flush             (WinHTTP POST every 30s)        │
│             │                                                   │
│             │  HTTP POST /api/report                           │
│             │  X-Agent-Key: <psk>                              │
│             │  JSON batch of events                            │
└─────────────┼───────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Server  (Python, Flask + sqlite3 — stdlib only)               │
│                                                                 │
│  POST /api/report  → auth check → risk score → SQLite insert   │
│  GET  /api/events  → query with since/client/level filters     │
│  GET  /api/clients → all known endpoints                       │
│  GET  /api/stats   → aggregate counts                          │
│  GET  /           → serves the React dashboard HTML            │
│                                                                 │
│  Alert engine: webhook + email on score ≥ threshold            │
└─────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Dashboard  (React, single HTML file, no build step)           │
│                                                                 │
│  Polls /api/* every 5 seconds                                  │
│  Shows real-time event feed with HIGH/MED/LOW risk badges      │
│  Left sidebar: connected endpoints sorted by risk score        │
│  Demo mode: fake data stream, no agent required                │
└─────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
InsiderThreatDetector/
├── agent.c                    C source — the Windows monitoring agent
├── Makefile                   MinGW build instructions
├── server_backend.py          Flask server — ingestion, scoring, alerts
└── static/
│   └── index.html             React dashboard (CDN React + Babel, no build)
└── InsiderThreatDashboard.jsx React component source (CRA-compatible version)
```

---

## Prerequisites

| Component | Requirement |
|---|---|
| Agent build | MSYS2 MinGW-w64 (`gcc --version` should show "MSYS2 project") |
| Server | Python 3.8+ |
| Server deps | `pip install flask flask-cors` |
| Dashboard | Any modern browser (Chrome, Firefox, Edge) |

---

## Quick Start

### 1. Configure the agent

Open `agent.c` and set the server IP at the top of the file:

```c
#define SERVER_HOST  L"192.168.1.50"   // IP of the machine running server_backend.py
#define SERVER_PORT  5000
#define PSK_KEY      L"changeme"        // Must match PSK_SECRET on the server
```

### 2. Build the agent

Run from PowerShell or an MSYS2 terminal where `gcc --version` reports MSYS2:

```powershell
make
```

This produces `agent.exe` — a silent Windows executable with no console window.

### 3. Start the server

```powershell
python server_backend.py
```

Optional environment variables:

```powershell
$env:PSK_SECRET      = "your-secret-key"   # Agent auth key (default: changeme)
$env:ALERT_THRESHOLD = "75"                # Risk score that fires alerts (default: 80)
$env:WEBHOOK_URL     = "https://..."       # Webhook endpoint for alerts (optional)
$env:SMTP_HOST       = "smtp.gmail.com"    # Email alerts (optional)
$env:SMTP_PORT       = "587"
$env:SMTP_USER       = "you@gmail.com"
$env:SMTP_PASS       = "app-password"
$env:SMTP_TO         = "soc@yourorg.com"
```

### 4. Open the dashboard

Navigate to **`http://localhost:5000/`** in any browser.

Click **Demo OFF** to toggle demo mode and see realistic fake events immediately — no agent needed.

### 5. Deploy the agent

Copy `agent.exe` to any Windows machine on the same network as the server and run it. It starts silently with no window. Events appear in the dashboard within 30 seconds.

To verify the agent is running without a UI, open Task Manager and look for `agent.exe` in the process list.

---

## How It Works

### The C Agent (`agent.c`)

The agent is written in pure C using only native Windows APIs — no external libraries, no runtime installers. It compiles to a single self-contained `.exe`.

**Entry point: `WinMain`**

The agent uses `WinMain` instead of the standard `main` function. Combined with the `-mwindows` linker flag, this suppresses the console window entirely. The process runs silently in the background.

```c
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
```

**Thread-safe ring buffer**

All monitor threads write events into a shared fixed-size ring buffer (1000 slots). A `CRITICAL_SECTION` guards head/tail access. When the buffer is full, the oldest event is silently overwritten — recent events are always preserved. A dedicated flush thread drains the buffer every 30 seconds.

```
Monitor threads → ring_push() → [slot 0][slot 1]...[slot 999] → ring_drain() → Flush thread
                  CRITICAL_SECTION lock                          CRITICAL_SECTION lock
```

**Process monitor**

Uses the `Toolhelp32` API to snapshot the running process list every 2 seconds. Compares the new snapshot against a stored array of previously seen PIDs and emits an event only for genuinely new processes. No event spam for processes that were already running.

```c
HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
Process32FirstW(snap, &pe);  // iterate with Process32NextW
```

**USB monitor**

Creates a hidden message-only window (`HWND_MESSAGE`) and registers for device notifications via `RegisterDeviceNotificationW`. The thread runs a standard Windows message loop. `WM_DEVICECHANGE` messages arrive with `DBT_DEVICEARRIVAL` or `DBT_DEVICEREMOVECOMPLETE` when a USB device connects or disconnects.

This is purely event-driven — zero CPU usage between events.

**Clipboard monitor**

Polls `OpenClipboard` and `GetClipboardData(CF_UNICODETEXT)` every 2 seconds. Scans clipboard text against a keyword list using case-insensitive wide-string search. Critically: the actual clipboard content is never logged or transmitted — only the matched keyword name and character count. This avoids the monitor itself becoming a data exfiltration vector.

**Window title monitor**

Calls `GetForegroundWindow` and `GetWindowTextW` every 3 seconds. Only emits an event when the foreground window actually changes (HWND comparison), avoiding event floods when the user stays on the same window.

**Network upload monitor**

Calls `GetIfTable` from `iphlpapi.dll` every 10 seconds and sums the `dwOutOctets` counter across all network interfaces. Maintains a 3-sample rolling window (30 seconds). If the delta exceeds 10 MB, a `NETWORK_UPLOAD` event is emitted. Handles the 32-bit counter wrap-around correctly.

**After-hours detection**

Not a separate thread — `is_after_hours()` is called inline by every monitor when building an event. It checks `GetLocalTime` against configurable work hours (8am–6pm) and flags weekends. The server applies a +20 risk score modifier to any event flagged as after-hours.

**Screenshot capture**

On high-risk events (risk score ≥ 80 based on local heuristics), the agent captures a screenshot using GDI32:

1. `GetForegroundWindow` → `GetWindowRect` to get the active window bounds
2. `PrintWindow(PW_RENDERFULLCONTENT)` to render the window content (handles DWM-composited windows)
3. Falls back to `BitBlt` from the desktop DC if `PrintWindow` fails
4. `GetDIBits` extracts raw pixel data
5. A proper BMP file is assembled in memory (BITMAPFILEHEADER + BITMAPINFOHEADER + pixels)
6. Base64-encoded inline and attached to the event JSON as `screenshot_b64`

**WinHTTP POST**

The flush thread serializes all drained events into a JSON array using hand-rolled `snprintf` chains — no JSON library. The payload is POST'd via `WinHttpOpenRequest` / `WinHttpSendRequest`. Supports HTTPS by setting `WINHTTP_FLAG_SECURE` and can skip certificate validation for lab environments with self-signed certs.

Auth is a pre-shared key sent as a custom HTTP header: `X-Agent-Key: <psk>`.

**Persistence**

On startup, the agent writes its own executable path to the Windows registry run key:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor
```

This causes the agent to re-launch automatically on user login, surviving reboots.

---

### The Flask Server (`server_backend.py`)

**Why Flask?**

Flask is minimal — the only dependencies are `flask` and `flask-cors`. Everything else (SQLite, HTTP alerts, email) uses Python's standard library. The server stays small enough to read and audit in a single sitting.

**SQLite storage**

Events are stored in a local SQLite database (`events.db`). WAL journal mode is enabled at startup, which allows reads and writes to happen concurrently — critical because the dashboard is polling while the agent is inserting.

The schema is intentionally simple:

```sql
events  (id, timestamp, client_id, hostname, event_type, data_json, risk_score, risk_level)
clients (id, client_id, hostname, ip, last_seen, max_risk_score)
```

`client_id` is derived server-side as `SHA-256(hostname + ip)[:16]`. This means the agent doesn't need to know its own identifier — the server computes it from what the agent reports.

**Risk scoring**

Every event is scored 0–100 by `RiskScorer.score()` using rule-based logic with no machine learning:

- Process names are checked against a table of known attack tools (`mimikatz` → 100, `wireshark` → 85, `nmap` → 80, etc.)
- Clipboard events are scored based on which sensitive keyword was matched
- USB insertions score 50, removals 40
- Network uploads over 10 MB in 30 seconds score 70, scaling up to 90 for very large transfers
- After-hours activity adds +20 to any event score

Scores are bucketed: ≥ 80 → HIGH, ≥ 50 → MED, else LOW.

**Alert deduplication**

When an event scores above `ALERT_THRESHOLD`, the server fires a webhook POST and/or email. To prevent alert floods, a per-(client, event_type) timestamp is maintained in memory. The same client triggering the same event type will only generate one alert per 5-minute window.

Alerts fire in a daemon thread so they never block the HTTP response back to the agent.

**Incremental polling**

The `GET /api/events` endpoint accepts a `since=<id>` parameter. The dashboard always sends the highest event ID it has seen, so the server only returns new rows. This keeps the poll payload small even after thousands of events are stored.

---

### The Dashboard (`static/index.html`)

The dashboard is a single HTML file served directly by Flask. It uses React 18 loaded from CDN and Babel Standalone to transpile JSX in the browser at load time — no Node.js, no npm, no build step.

**State management**

All UI state lives in a single `useReducer`. There is no `localStorage` — page refresh returns to a clean state and the dashboard re-polls from the server. The highest seen event ID is tracked in a `useRef` (not state) so it can be updated without triggering re-renders.

**Real-time updates**

A `setInterval` running every 5 seconds fires three parallel `fetch` calls:

```
Promise.all([/api/events?since=N, /api/clients, /api/stats])
```

New events are prepended to the event list (newest first) and capped at 500 entries. The sidebar and stat cards update on every poll cycle.

**Demo mode**

Clicking "Demo OFF" switches to a local data generator. Fake events are injected every 2 seconds using a weighted random picker across event types, hostnames, and risk levels — no server connection required. Demo mode is useful for presentations or testing the UI without a running agent.

---

## Risk Score Reference

| Event | Score | Notes |
|---|---|---|
| mimikatz, Cobalt Strike | 100 | Confirmed attack tools |
| Metasploit, msfconsole | 95 | |
| fgdump, pwdump, psexec | 90 | Credential dumping / lateral movement |
| wireshark, netcat, procdump | 85 | Dual-use tools with high abuse rate |
| nmap, lazagne | 80 | Reconnaissance / credential harvesting |
| Clipboard: private key, API key | 75–80 | Sensitive data in clipboard |
| Clipboard: password, credit card | 65–70 | |
| USB insertion | 50 | Data exfiltration vector |
| Large network upload (>10 MB/30s) | 70–90 | Scales with transfer size |
| USB removal | 40 | |
| Unknown process | 20 | Unrecognized binary |
| After-hours modifier | +20 | Applied on top of any event score |

**HIGH** = score ≥ 80 · **MED** = score ≥ 50 · **LOW** = score < 50

---

## Security Notes

- The pre-shared key (`PSK_KEY` / `PSK_SECRET`) should be changed from the default `changeme` before deployment
- Enable HTTPS by setting `USE_HTTPS 1` in `agent.c` — WinHTTP handles TLS natively
- `SKIP_CERT_VALIDATION 1` is intended for lab use with self-signed certificates only; disable it in production
- Clipboard content is never transmitted — only the matched keyword name
- The agent writes to `HKCU` (current user), not `HKLM`, so it does not require administrator privileges to install persistence
- The server does not authenticate dashboard GET requests — add session auth before exposing this to an untrusted network

---

## Extending the System

**Add a new suspicious process**

In `server_backend.py`, add an entry to `RiskScorer.PROCESS_SCORES`:

```python
'newmalware': 95,
```

No agent rebuild required — scoring is entirely server-side.

**Add a new clipboard keyword**

In `server_backend.py`, add to `RiskScorer.CLIP_KEYWORD_SCORES`:

```python
'stripe_key': 80,
```

**Change the alert threshold**

```powershell
$env:ALERT_THRESHOLD = "70"
python server_backend.py
```

**Enable HTTPS**

1. Set `USE_HTTPS 1` and `SKIP_CERT_VALIDATION 0` in `agent.c`
2. Set `SERVER_PORT 443`
3. Run Flask behind nginx or use a self-signed cert with `SKIP_CERT_VALIDATION 1` for lab use
4. Rebuild: `make`

**Switch to a production WSGI server**

```powershell
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 server_backend:app
```

---

## Troubleshooting

**Agent builds but no events appear**
- Confirm `SERVER_HOST` in `agent.c` matches the server's IP
- Confirm `PSK_KEY` in `agent.c` matches `PSK_SECRET` on the server
- Check the server console for `401 Unauthorized` responses
- Events batch every 30 seconds — wait at least one cycle

**`winhttp.h: No such file or directory` during build**
- You are using MinGW.org's old gcc, not MSYS2's MinGW-w64
- Run `gcc --version` — it must say "MSYS2 project"
- Install MSYS2 from msys2.org and use its MinGW-w64 shell

**Dashboard shows "Cannot reach server"**
- The server is not running, or is on a different port
- Check `python server_backend.py` is running and listening on 0.0.0.0:5000
- Check Windows Firewall is not blocking port 5000

**`events.db` grows large**
- Add a scheduled task to truncate old events:
  ```sql
  DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 10000);
  ```
