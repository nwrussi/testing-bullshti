"""
Insider Threat Detection — Flask Backend
Receives telemetry from C agents, scores risk, stores in SQLite, fires alerts.

Environment variables:
  PSK_SECRET       Pre-shared key agents must send in X-Agent-Key header (default: changeme)
  DB_PATH          Path to SQLite database file (default: events.db)
  ALERT_THRESHOLD  Risk score that triggers an alert (default: 80)
  WEBHOOK_URL      HTTP(S) URL to POST alert JSON to (optional)
  SMTP_HOST        SMTP server hostname (optional)
  SMTP_PORT        SMTP port — 465=SSL, 587=STARTTLS (default: 465)
  SMTP_USER        SMTP username
  SMTP_PASS        SMTP password
  SMTP_TO          Alert recipient email address
"""

import os
import json
import time
import hashlib
import sqlite3
import threading
import smtplib
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PSK_SECRET      = os.environ.get("PSK_SECRET", "changeme")
DB_PATH         = os.environ.get("DB_PATH", "events.db")
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "80"))
WEBHOOK_URL     = os.environ.get("WEBHOOK_URL", "")
SMTP_HOST       = os.environ.get("SMTP_HOST", "")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER       = os.environ.get("SMTP_USER", "")
SMTP_PASS       = os.environ.get("SMTP_PASS", "")
SMTP_TO         = os.environ.get("SMTP_TO", "")

ACTIVE_CLIENT_WINDOW = 300   # seconds — client is "active" if seen within this window
DEDUP_WINDOW         = 300   # seconds — suppress repeat alerts for same client+type

app = Flask(__name__, static_folder="static")
CORS(app)


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db():
    """Return a per-request SQLite connection stored in Flask's g object."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and indexes. Safe to call on every startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            client_id   TEXT NOT NULL,
            hostname    TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            data_json   TEXT NOT NULL,
            risk_score  INTEGER NOT NULL DEFAULT 0,
            risk_level  TEXT NOT NULL DEFAULT 'LOW'
        );

        CREATE TABLE IF NOT EXISTS clients (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id      TEXT UNIQUE NOT NULL,
            hostname       TEXT NOT NULL,
            ip             TEXT NOT NULL,
            last_seen      TEXT NOT NULL,
            max_risk_score INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_events_client_id
            ON events(client_id);
        CREATE INDEX IF NOT EXISTS idx_events_risk_level
            ON events(risk_level);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_composite
            ON events(client_id, timestamp DESC);
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Risk Scorer
# ---------------------------------------------------------------------------
class RiskScorer:
    # Process name → base score (match on lowercase substring)
    PROCESS_SCORES = {
        "mimikatz":      100,
        "cobaltstrike":  100,
        "cobalt strike": 100,
        "metasploit":    95,
        "msfconsole":    95,
        "msfvenom":      95,
        "wce.exe":       95,
        "wce":           95,
        "fgdump":        90,
        "pwdump":        90,
        "psexec":        90,
        "lazagne":       85,
        "wireshark":     85,
        "tshark":        85,
        "netcat":        85,
        "nc.exe":        85,
        "ncat":          85,
        "procdump":      85,
        "dumpert":       90,
        "rubeus":        90,
        "sharphound":    85,
        "bloodhound":    85,
        "crackmapexec":  90,
        "cme":           85,
        "nmap":          80,
        "masscan":       80,
        "zenmap":        80,
        "angryip":       70,
        "processhacker": 65,
        "autoruns":      50,
        "procmon":       45,
        "regshot":       55,
        "volatility":    60,
        "x64dbg":        60,
        "ollydbg":       60,
        "immunity debugger": 65,
        "putty":         30,
        "winscp":        30,
        "filezilla":     35,
        "torproject":    70,
        "tor.exe":       75,
        "veracrypt":     60,
    }

    # Clipboard keyword → score (match case-insensitive)
    CLIP_KEYWORD_SCORES = {
        "-----begin":         80,
        "private key":        80,
        "-----begin rsa":     85,
        "-----begin ec":      85,
        "api_key":            75,
        "api key":            75,
        "apikey":             75,
        "access_key":         75,
        "secret_key":         75,
        "secret key":         75,
        "aws_secret":         80,
        "ssn":                75,
        "social security":    75,
        "credit card":        70,
        "card number":        70,
        "cvv":                65,
        "password":           65,
        "passwd":             65,
        "passphrase":         65,
        "secret":             60,
        "token":              55,
        "bearer":             55,
        "authorization":      50,
    }

    @classmethod
    def score(cls, event_type: str, data: dict, after_hours: bool) -> tuple[int, str]:
        """
        Returns (score, risk_level).
        score is 0-100. risk_level is HIGH / MED / LOW.
        """
        base = 0
        et = event_type.upper()

        if et == "PROCESS":
            name = data.get("name", "").lower()
            for keyword, s in cls.PROCESS_SCORES.items():
                if keyword in name:
                    base = max(base, s)
            if base == 0:
                # Unknown process — low-grade flag
                base = 20

        elif et == "CLIPBOARD":
            keyword = data.get("keyword", "").lower()
            for kw, s in cls.CLIP_KEYWORD_SCORES.items():
                if kw in keyword:
                    base = max(base, s)
            if base == 0:
                base = 40  # matched something suspicious even if keyword unknown

        elif et == "USB_INSERT":
            base = 50

        elif et == "USB_REMOVE":
            base = 40

        elif et == "NETWORK_UPLOAD":
            bytes_out = data.get("bytes_out", 0)
            # Scale: 10MB=70, 50MB=80, 100MB=90
            if bytes_out >= 100 * 1024 * 1024:
                base = 90
            elif bytes_out >= 50 * 1024 * 1024:
                base = 80
            else:
                base = 70

        elif et == "WINDOW":
            # Window titles themselves are not risk-scored; logged for context
            base = 0

        elif et == "AFTERHOURS":
            base = 30

        else:
            base = 10

        # After-hours modifier
        if after_hours and base > 0:
            base = min(100, base + 20)

        # Bucket into levels
        if base >= 80:
            level = "HIGH"
        elif base >= 50:
            level = "MED"
        else:
            level = "LOW"

        return base, level


# ---------------------------------------------------------------------------
# Alert Engine
# ---------------------------------------------------------------------------
_alert_cache: dict[tuple, float] = {}
_cache_lock = threading.Lock()


def _should_alert(client_id: str, event_type: str) -> bool:
    """Returns True if we should fire an alert (dedup by client+type, 5min window)."""
    key = (client_id, event_type)
    now = time.monotonic()
    with _cache_lock:
        last = _alert_cache.get(key, 0.0)
        if now - last > DEDUP_WINDOW:
            _alert_cache[key] = now
            return True
    return False


def _send_webhook(payload: dict):
    if not WEBHOOK_URL:
        return
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
    except Exception as exc:
        app.logger.warning("Webhook failed: %s", exc)


def _send_email(subject: str, body: str):
    if not SMTP_HOST or not SMTP_TO:
        return
    try:
        msg = f"Subject: {subject}\nFrom: {SMTP_USER}\nTo: {SMTP_TO}\n\n{body}"
        if SMTP_PORT == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, SMTP_TO, msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, SMTP_TO, msg)
    except Exception as exc:
        app.logger.warning("Email failed: %s", exc)


def _dispatch_alert(event_row: dict, score: int):
    """Fire webhook and email alert in a background thread."""
    payload = {
        "alert": "HIGH_RISK_EVENT",
        "score": score,
        "hostname": event_row.get("hostname"),
        "client_id": event_row.get("client_id"),
        "event_type": event_row.get("event_type"),
        "timestamp": event_row.get("timestamp"),
        "data": event_row.get("data_json"),
    }
    subject = (
        f"[ALERT] {event_row.get('event_type')} on {event_row.get('hostname')} "
        f"— risk score {score}"
    )
    body = json.dumps(payload, indent=2)
    t = threading.Thread(target=lambda: (_send_webhook(payload), _send_email(subject, body)), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_client_id(hostname: str, ip: str) -> str:
    raw = f"{hostname.lower()}:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.before_request
def auth_check():
    # Allow CORS preflight through
    if request.method == "OPTIONS":
        return

    # Only POST endpoints require the agent PSK
    if request.method == "POST" and request.path.startswith("/api/"):
        key = request.headers.get("X-Agent-Key", "")
        if key != PSK_SECRET:
            return jsonify({"error": "Unauthorized"}), 401


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/report", methods=["POST"])
def report():
    """
    Receive a batch of events from a C agent.

    Expected JSON body:
    {
        "hostname": "WORKSTATION-01",
        "events": [
            {
                "event_type": "PROCESS",
                "data_json": "{\"name\":\"mimikatz.exe\",\"pid\":1234}",
                "timestamp": "2024-01-15T09:30:00",
                "after_hours": false
            },
            ...
        ]
    }
    """
    try:
        body = request.get_json(force=True, silent=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if not body or "events" not in body:
        return jsonify({"error": "Missing events field"}), 400

    hostname = body.get("hostname", "unknown")
    client_ip = request.remote_addr or "0.0.0.0"
    client_id = _make_client_id(hostname, client_ip)
    events = body.get("events", [])

    if not isinstance(events, list):
        return jsonify({"error": "events must be an array"}), 400

    db = get_db()
    inserted = 0
    max_score_this_batch = 0

    for ev in events:
        if not isinstance(ev, dict):
            continue

        event_type = str(ev.get("event_type", "UNKNOWN")).upper()
        data_json_raw = ev.get("data_json", "{}")
        timestamp = ev.get("timestamp") or _utc_now()
        after_hours = bool(ev.get("after_hours", False))

        # Parse data for scoring
        try:
            data_dict = json.loads(data_json_raw) if isinstance(data_json_raw, str) else data_json_raw
        except (json.JSONDecodeError, TypeError):
            data_dict = {}

        # Ensure data_json stored is always valid JSON string
        if isinstance(data_json_raw, dict):
            data_json_str = json.dumps(data_json_raw)
        else:
            data_json_str = data_json_raw

        score, level = RiskScorer.score(event_type, data_dict, after_hours)
        max_score_this_batch = max(max_score_this_batch, score)

        db.execute(
            """INSERT INTO events
               (timestamp, client_id, hostname, event_type, data_json, risk_score, risk_level)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, client_id, hostname, event_type, data_json_str, score, level),
        )

        if score >= ALERT_THRESHOLD and _should_alert(client_id, event_type):
            _dispatch_alert(
                {
                    "hostname": hostname,
                    "client_id": client_id,
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "data_json": data_json_str,
                },
                score,
            )

        inserted += 1

    # Upsert client record
    db.execute(
        """INSERT INTO clients (client_id, hostname, ip, last_seen, max_risk_score)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(client_id) DO UPDATE SET
               hostname=excluded.hostname,
               ip=excluded.ip,
               last_seen=excluded.last_seen,
               max_risk_score=MAX(clients.max_risk_score, excluded.max_risk_score)""",
        (client_id, hostname, client_ip, _utc_now(), max_score_this_batch),
    )

    db.commit()
    return jsonify({"status": "ok", "inserted": inserted}), 200


@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Query parameters:
      since=<int>       Return only events with id > since (default: 0)
      client_id=<str>   Filter by client_id
      level=<str>       Filter by risk_level: HIGH | MED | LOW
      limit=<int>       Max results (default: 200, max: 500)
    """
    since = int(request.args.get("since", 0))
    client_id = request.args.get("client_id", "")
    level = request.args.get("level", "").upper()
    limit = min(int(request.args.get("limit", 200)), 500)

    query = "SELECT * FROM events WHERE id > ?"
    params: list = [since]

    if client_id:
        query += " AND client_id = ?"
        params.append(client_id)
    if level in ("HIGH", "MED", "LOW"):
        query += " AND risk_level = ?"
        params.append(level)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    db = get_db()
    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/clients", methods=["GET"])
def get_clients():
    """Return all known clients sorted by max risk score descending."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM clients ORDER BY max_risk_score DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return aggregate counts and active client count."""
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    high  = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='HIGH'").fetchone()[0]
    med   = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='MED'").fetchone()[0]
    low   = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='LOW'").fetchone()[0]

    # Active = seen within last ACTIVE_CLIENT_WINDOW seconds
    cutoff = datetime.now(timezone.utc).timestamp() - ACTIVE_CLIENT_WINDOW
    # last_seen stored as ISO8601; compare lexicographically (works for UTC)
    cutoff_str = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
    active = db.execute(
        "SELECT COUNT(*) FROM clients WHERE last_seen >= ?", (cutoff_str,)
    ).fetchone()[0]

    return jsonify({
        "total": total,
        "high": high,
        "med": med,
        "low": low,
        "active_clients": active,
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": _utc_now()})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print(f"[*] InsiderThreat backend starting")
    print(f"[*] DB: {DB_PATH}")
    print(f"[*] Alert threshold: {ALERT_THRESHOLD}")
    print(f"[*] Webhook: {WEBHOOK_URL or 'disabled'}")
    print(f"[*] Email: {'enabled' if SMTP_HOST and SMTP_TO else 'disabled'}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
