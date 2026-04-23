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
import io
import csv
import json
import time
import secrets
import hashlib
import sqlite3
import threading
import smtplib
import ssl
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g, send_from_directory, Response
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PSK_SECRET      = os.environ.get("PSK_SECRET", "changeme")
DB_PATH         = os.environ.get("DB_PATH", "events.db")
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "80"))
ADMIN_PASSWORD  = os.environ.get("ADMIN_PASSWORD", "admin")
WEBHOOK_URL     = os.environ.get("WEBHOOK_URL", "")
SMTP_HOST       = os.environ.get("SMTP_HOST", "")
SMTP_PORT       = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER       = os.environ.get("SMTP_USER", "")
SMTP_PASS       = os.environ.get("SMTP_PASS", "")
SMTP_TO         = os.environ.get("SMTP_TO", "")

ACTIVE_CLIENT_WINDOW = 300   # seconds — client is "active" if seen within this window
DEDUP_WINDOW         = 300   # seconds — suppress repeat alerts for same client+type

# Runtime-mutable config (can be changed via admin API without restart)
_config_lock = threading.Lock()
_runtime_config: dict = {"alert_threshold": ALERT_THRESHOLD}

# In-memory admin token set (cleared on restart; that's intentional)
_admin_lock = threading.Lock()
_admin_tokens: set[str] = set()


def get_alert_threshold() -> int:
    with _config_lock:
        return int(_runtime_config["alert_threshold"])

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
    # Process name → base score
    PROCESS_SCORES = {
        # Tier 1: Purely Malicious / Exploit Frameworks
        "mimikatz": 100, "cobaltstrike": 100, "msfconsole": 100, "bloodhound": 100,
        "rubeus": 100, "sharphound": 100, 
        
        # Tier 2: Dual-Use Admin/Net Tools (Suspicious for normal users, normal for IT)
        "psexec": 50, "wireshark": 50, "nmap": 50, "procdump": 50, 
        "tor.exe": 50, "angryip": 40, "putty": 30, "filezilla": 30,
        
        # Tier 3: LoLBins (Living off the Land) - Extremely common, low base score
        "powershell": 20, "cmd.exe": 20, "certutil": 20, "wscript": 20, "cscript": 20
    }

    # Clipboard keyword → base score
    CLIP_KEYWORD_SCORES = {
        "-----begin": 40, "private key": 40, "aws_access_key": 40, 
        "api_key": 30, "ssn": 20, "password": 15, "secret": 15, "bearer": 15
    }

    # In-memory tracker for kill-chain compounding
    _history = defaultdict(list)
    TIME_WINDOW_SEC = 300  # 5 minutes

    @staticmethod
    def get_tactic(event_type: str, data: dict) -> str:
        """Map event types to Kill-Chain tactics."""
        et = event_type.upper()
        if et == "PROCESS":
            return "EXECUTION"
        elif et == "WINDOW":
            return "RECON"
        elif et == "CLIPBOARD":
            return "COLLECTION"
        elif et in ("USB_INSERT", "NETWORK_UPLOAD"):
            return "EXFILTRATION"
        return "OTHER"

    @classmethod
    def score(cls, client_id: str, event_type: str, data: dict, after_hours: bool) -> tuple[int, str]:
        base = 0
        et = event_type.upper()

        # 1. Calculate Base Score
        if et == "PROCESS":
            name = data.get("name", "").lower()
            for keyword, s in cls.PROCESS_SCORES.items():
                if keyword in name:
                    base = max(base, s)
            if base == 0: base = 0 
            
        elif et == "CLIPBOARD":
            keyword = data.get("keyword", "").lower()
            for kw, s in cls.CLIP_KEYWORD_SCORES.items():
                if kw in keyword:
                    base = max(base, s)
            if base == 0: base = 10
            
        elif et == "USB_INSERT":
            base = 25 
            
        elif et == "USB_REMOVE":
            base = 10
            
        elif et == "NETWORK_UPLOAD":
            bytes_out = data.get("bytes_out", 0)
            if bytes_out >= 500 * 1024 * 1024:
                base = 70
            elif bytes_out >= 100 * 1024 * 1024:
                base = 45
            elif bytes_out >= 50 * 1024 * 1024:
                base = 30
            else:
                base = 10

        elif et == "AFTERHOURS":
            base = 10 

        if after_hours and base > 0:
            base = min(100, base + 10)

        # 2. Kill-Chain Compounding Logic
        now = time.time()
        tactic = cls.get_tactic(et, data)
        
        cls._history[client_id] = [e for e in cls._history[client_id] if now - e['ts'] <= cls.TIME_WINDOW_SEC]
        
        if tactic != "OTHER" and base > 0:
            cls._history[client_id].append({'ts': now, 'tactic': tactic, 'score': base})

        unique_tactics = set(e['tactic'] for e in cls._history[client_id])
        
        multiplier = 1.0
        if len(unique_tactics) == 2:
            multiplier = 1.5
        elif len(unique_tactics) >= 3:
            multiplier = 2.0
        
        final_score = min(100, int(base * multiplier))

        # 3. Bucket into levels
        if final_score >= 80:
            level = "HIGH"
        elif final_score >= 50:
            level = "MED"
        else:
            level = "LOW"

        return final_score, level


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
    if request.method == "OPTIONS":
        return

    path = request.path

    if path.startswith("/api/admin/"):
        if path == "/api/admin/login":
            return
        token = request.headers.get("X-Admin-Token", "")
        with _admin_lock:
            if not token or token not in _admin_tokens:
                return jsonify({"error": "Admin unauthorized"}), 401
        return

    if request.method == "POST" and path.startswith("/api/"):
        key = request.headers.get("X-Agent-Key", "")
        if key != PSK_SECRET:
            return jsonify({"error": "Unauthorized"}), 401


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/report", methods=["POST"])
def report():
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

        try:
            data_dict = json.loads(data_json_raw) if isinstance(data_json_raw, str) else data_json_raw
        except (json.JSONDecodeError, TypeError):
            data_dict = {}

        if isinstance(data_json_raw, dict):
            data_json_str = json.dumps(data_json_raw)
        else:
            data_json_str = data_json_raw

        # Pass client_id to the scorer for state tracking
        score, level = RiskScorer.score(client_id, event_type, data_dict, after_hours)
        max_score_this_batch = max(max_score_this_batch, score)

        db.execute(
            """INSERT INTO events
               (timestamp, client_id, hostname, event_type, data_json, risk_score, risk_level)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, client_id, hostname, event_type, data_json_str, score, level),
        )

        if score >= get_alert_threshold() and _should_alert(client_id, event_type):
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
    db = get_db()
    rows = db.execute(
        "SELECT * FROM clients ORDER BY max_risk_score DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats", methods=["GET"])
def get_stats():
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    high  = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='HIGH'").fetchone()[0]
    med   = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='MED'").fetchone()[0]
    low   = db.execute("SELECT COUNT(*) FROM events WHERE risk_level='LOW'").fetchone()[0]

    cutoff = datetime.now(timezone.utc).timestamp() - ACTIVE_CLIENT_WINDOW
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
# Admin endpoints
# ---------------------------------------------------------------------------
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    body = request.get_json(force=True, silent=True) or {}
    password = body.get("password", "")
    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Invalid password"}), 401
    token = secrets.token_urlsafe(24)
    with _admin_lock:
        _admin_tokens.add(token)
    return jsonify({"token": token})


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    token = request.headers.get("X-Admin-Token", "")
    with _admin_lock:
        _admin_tokens.discard(token)
    return jsonify({"status": "ok"})


@app.route("/api/admin/check", methods=["GET"])
def admin_check():
    return jsonify({"status": "ok"})


@app.route("/api/admin/events", methods=["DELETE"])
def admin_delete_events():
    client_id = request.args.get("client_id", "")
    db = get_db()
    if client_id:
        cur = db.execute("DELETE FROM events WHERE client_id = ?", (client_id,))
    else:
        cur = db.execute("DELETE FROM events")
    deleted = cur.rowcount
    db.commit()
    return jsonify({"deleted": deleted})


@app.route("/api/admin/clients/<client_id>", methods=["DELETE"])
def admin_delete_client(client_id):
    db = get_db()
    db.execute("DELETE FROM events WHERE client_id = ?", (client_id,))
    cur = db.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
    deleted = cur.rowcount
    db.commit()
    return jsonify({"deleted": deleted})


@app.route("/api/admin/config", methods=["GET", "PUT"])
def admin_config():
    if request.method == "GET":
        return jsonify({"alert_threshold": get_alert_threshold()})

    body = request.get_json(force=True, silent=True) or {}
    threshold = body.get("alert_threshold")
    try:
        threshold = int(threshold)
    except (TypeError, ValueError):
        return jsonify({"error": "alert_threshold must be an integer"}), 400
    if threshold < 0 or threshold > 100:
        return jsonify({"error": "alert_threshold must be between 0 and 100"}), 400
    with _config_lock:
        _runtime_config["alert_threshold"] = threshold
    return jsonify({"alert_threshold": threshold})


@app.route("/api/admin/vacuum", methods=["POST"])
def admin_vacuum():
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    try:
        conn.execute("VACUUM")
    finally:
        conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/admin/export", methods=["GET"])
def admin_export():
    fmt = request.args.get("format", "json").lower()
    db = get_db()
    rows = db.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
    data = [dict(r) for r in rows]

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if fmt == "csv":
        buf = io.StringIO()
        fieldnames = ["id", "timestamp", "client_id", "hostname",
                      "event_type", "risk_score", "risk_level", "data_json"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition":
                     f"attachment; filename=events_full_{today}.csv"},
        )

    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":
                 f"attachment; filename=events_full_{today}.json"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print(f"[*] InsiderThreat backend starting")
    print(f"[*] DB: {DB_PATH}")
    print(f"[*] Alert threshold: {ALERT_THRESHOLD}")
    print(f"[*] Admin password: {'default (admin)' if ADMIN_PASSWORD == 'admin' else 'custom'}")
    print(f"[*] Webhook: {WEBHOOK_URL or 'disabled'}")
    print(f"[*] Email: {'enabled' if SMTP_HOST and SMTP_TO else 'disabled'}")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)