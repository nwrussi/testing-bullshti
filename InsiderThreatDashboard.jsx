/**
 * Insider Threat Detection Dashboard
 *
 * Single-file React component. No build step required if used with Babel CDN.
 * For CRA: import and render as <InsiderThreatDashboard />.
 *
 * No localStorage. No external state libs. Polling via setInterval.
 */

import React, {
  useReducer,
  useEffect,
  useRef,
  useCallback,
  useState,
} from "react";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const API_BASE = "/api";
const POLL_INTERVAL = 5000;
const MAX_EVENTS = 500;

const RISK = {
  HIGH: { bg: "#fee2e2", color: "#991b1b", border: "#fca5a5", dot: "#ef4444" },
  MED:  { bg: "#fef3c7", color: "#92400e", border: "#fcd34d", dot: "#f59e0b" },
  LOW:  { bg: "#d1fae5", color: "#065f46", border: "#6ee7b7", dot: "#10b981" },
};

// ---------------------------------------------------------------------------
// Demo mode data
// ---------------------------------------------------------------------------
const DEMO_HOSTS = [
  "DESKTOP-ALICE", "LAPTOP-BOB", "WS-CHARLIE", "FINANCE-01", "HR-PC-02",
];
const DEMO_EVENT_TYPES = [
  { type: "PROCESS",         weight: 35 },
  { type: "CLIPBOARD",       weight: 15 },
  { type: "USB_INSERT",      weight: 10 },
  { type: "USB_REMOVE",      weight: 8  },
  { type: "WINDOW",          weight: 25 },
  { type: "NETWORK_UPLOAD",  weight: 7  },
];
const DEMO_PROCESSES = [
  ["chrome.exe",     "LOW"],
  ["excel.exe",      "LOW"],
  ["outlook.exe",    "LOW"],
  ["teams.exe",      "LOW"],
  ["wireshark.exe",  "HIGH"],
  ["psexec.exe",     "HIGH"],
  ["mimikatz.exe",   "HIGH"],
  ["nmap.exe",       "HIGH"],
  ["putty.exe",      "MED"],
  ["filezilla.exe",  "MED"],
  ["procmon.exe",    "MED"],
];
const DEMO_KEYWORDS = ["password", "api_key", "-----BEGIN PRIVATE KEY", "ssn", "credit card"];
const DEMO_WINDOWS = [
  "Microsoft Excel - Q4_Salaries.xlsx",
  "Chrome - Gmail",
  "Notepad - credentials.txt",
  "FileZilla",
  "Windows PowerShell",
  "Task Manager",
];

let _demoId = 1000;

function pickWeighted(arr) {
  const total = arr.reduce((s, x) => s + x.weight, 0);
  let r = Math.random() * total;
  for (const x of arr) {
    r -= x.weight;
    if (r <= 0) return x;
  }
  return arr[arr.length - 1];
}

function rand(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateDemoEvent() {
  const host = rand(DEMO_HOSTS);
  const clientId = host.toLowerCase().replace(/-/g, "");
  const { type } = pickWeighted(DEMO_EVENT_TYPES);
  const after_hours = Math.random() < 0.2;
  let data_json = "{}";
  let risk_level = "LOW";
  let risk_score = 10;

  if (type === "PROCESS") {
    const [name, lvl] = rand(DEMO_PROCESSES);
    risk_level = lvl;
    risk_score = lvl === "HIGH" ? 85 + Math.floor(Math.random() * 15)
               : lvl === "MED"  ? 50 + Math.floor(Math.random() * 25)
               : 10 + Math.floor(Math.random() * 30);
    data_json = JSON.stringify({ name, pid: 1000 + Math.floor(Math.random() * 30000) });
  } else if (type === "CLIPBOARD") {
    const keyword = rand(DEMO_KEYWORDS);
    risk_level = "HIGH";
    risk_score = 75 + Math.floor(Math.random() * 20);
    data_json = JSON.stringify({ keyword, char_count: 50 + Math.floor(Math.random() * 500) });
  } else if (type === "USB_INSERT") {
    risk_level = "MED";
    risk_score = after_hours ? 70 : 50;
    data_json = JSON.stringify({ device_type: "mass_storage", event: "arrival" });
  } else if (type === "USB_REMOVE") {
    risk_level = "LOW";
    risk_score = 40;
    data_json = JSON.stringify({ device_type: "mass_storage", event: "removal" });
  } else if (type === "WINDOW") {
    const title = rand(DEMO_WINDOWS);
    risk_level = "LOW";
    risk_score = 0;
    data_json = JSON.stringify({ title });
  } else if (type === "NETWORK_UPLOAD") {
    const bytes = (10 + Math.floor(Math.random() * 90)) * 1024 * 1024;
    risk_level = after_hours ? "HIGH" : "MED";
    risk_score = after_hours ? 90 : 70;
    data_json = JSON.stringify({ bytes_out: bytes, window_sec: 30 });
  }

  if (after_hours && risk_score > 0) {
    risk_score = Math.min(100, risk_score + 20);
    if (risk_score >= 80) risk_level = "HIGH";
    else if (risk_score >= 50) risk_level = "MED";
  }

  return {
    id: ++_demoId,
    timestamp: new Date().toISOString(),
    client_id: clientId,
    hostname: host,
    event_type: type,
    data_json,
    risk_score,
    risk_level,
    after_hours,
  };
}

function buildDemoClients(events) {
  const map = {};
  for (const ev of events) {
    if (!map[ev.client_id]) {
      map[ev.client_id] = {
        client_id: ev.client_id,
        hostname: ev.hostname,
        ip: "192.168.1." + (Math.floor(Math.random() * 200) + 10),
        last_seen: ev.timestamp,
        max_risk_score: ev.risk_score,
      };
    } else {
      if (ev.risk_score > map[ev.client_id].max_risk_score)
        map[ev.client_id].max_risk_score = ev.risk_score;
      if (ev.timestamp > map[ev.client_id].last_seen)
        map[ev.client_id].last_seen = ev.timestamp;
    }
  }
  return Object.values(map).sort((a, b) => b.max_risk_score - a.max_risk_score);
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------
const initialState = {
  events: [],
  clients: [],
  stats: { total: 0, high: 0, med: 0, low: 0, active_clients: 0 },
  filter: "ALL",
  selectedClient: null,
  demoMode: false,
  error: null,
};

function appReducer(state, action) {
  switch (action.type) {
    case "PREPEND_EVENTS": {
      const merged = [...action.payload, ...state.events].slice(0, MAX_EVENTS);
      return { ...state, events: merged, error: null };
    }
    case "SET_CLIENTS":
      return { ...state, clients: action.payload };
    case "SET_STATS":
      return { ...state, stats: action.payload };
    case "SET_FILTER":
      return { ...state, filter: action.payload };
    case "SELECT_CLIENT":
      return { ...state, selectedClient: action.payload };
    case "TOGGLE_DEMO": {
      const demoMode = !state.demoMode;
      return {
        ...initialState,
        demoMode,
        // seed demo with a few initial events
        events: demoMode ? Array.from({ length: 12 }, generateDemoEvent).reverse() : [],
      };
    }
    case "SET_ERROR":
      return { ...state, error: action.payload };
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Utility components
// ---------------------------------------------------------------------------
function RiskBadge({ level, score }) {
  const s = RISK[level] || RISK.LOW;
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 4,
      padding: "2px 8px",
      borderRadius: 9999,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: "0.05em",
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.border}`,
      whiteSpace: "nowrap",
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: s.dot, flexShrink: 0 }} />
      {level} {score != null ? score : ""}
    </span>
  );
}

function formatTime(ts) {
  if (!ts) return "";
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function formatBytes(n) {
  if (n == null) return "";
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(1) + " KB";
  return n + " B";
}

function parseEventData(ev) {
  try {
    return typeof ev.data_json === "string" ? JSON.parse(ev.data_json) : ev.data_json;
  } catch {
    return {};
  }
}

function eventSummary(ev) {
  const d = parseEventData(ev);
  switch (ev.event_type) {
    case "PROCESS":
      return `${d.name || "?"} (PID ${d.pid || "?"})`;
    case "CLIPBOARD":
      return `Keyword: "${d.keyword || "?"}" — ${d.char_count || "?"} chars`;
    case "USB_INSERT":
      return `USB device arrived (${d.device_type || "unknown"})`;
    case "USB_REMOVE":
      return `USB device removed (${d.device_type || "unknown"})`;
    case "WINDOW":
      return d.title ? `"${d.title}"` : "(no title)";
    case "NETWORK_UPLOAD":
      return `${formatBytes(d.bytes_out)} uploaded in ${d.window_sec || 30}s`;
    case "AFTERHOURS":
      return "Activity outside business hours";
    default:
      return ev.data_json || "";
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function TopBar({ demoMode, onToggleDemo, error }) {
  return (
    <div style={{
      background: "#0f172a",
      color: "#f8fafc",
      padding: "0 24px",
      height: 56,
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      borderBottom: "1px solid #1e293b",
      flexShrink: 0,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em" }}>
          Insider Threat Monitor
        </span>
        {error && (
          <span style={{
            fontSize: 12, color: "#fca5a5",
            background: "#450a0a", border: "1px solid #7f1d1d",
            borderRadius: 6, padding: "2px 10px",
          }}>
            {error}
          </span>
        )}
      </div>
      <button
        onClick={onToggleDemo}
        style={{
          padding: "6px 16px",
          borderRadius: 8,
          border: "none",
          cursor: "pointer",
          fontWeight: 600,
          fontSize: 13,
          background: demoMode ? "#7c3aed" : "#334155",
          color: demoMode ? "#ede9fe" : "#94a3b8",
          transition: "all 0.15s",
        }}
      >
        {demoMode ? "Demo ON" : "Demo OFF"}
      </button>
    </div>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div style={{
      background: "#1e293b",
      border: "1px solid #334155",
      borderRadius: 10,
      padding: "14px 20px",
      flex: 1,
      minWidth: 110,
    }}>
      <div style={{ fontSize: 26, fontWeight: 800, color: accent || "#f1f5f9" }}>
        {value}
      </div>
      <div style={{ fontSize: 12, color: "#94a3b8", marginTop: 2, fontWeight: 500 }}>
        {label}
      </div>
    </div>
  );
}

function StatCards({ stats }) {
  return (
    <div style={{ display: "flex", gap: 12, padding: "16px 20px 0", flexWrap: "wrap" }}>
      <StatCard label="Total Events"    value={stats.total}          accent="#e2e8f0" />
      <StatCard label="High Risk"       value={stats.high}           accent="#f87171" />
      <StatCard label="Medium Risk"     value={stats.med}            accent="#fbbf24" />
      <StatCard label="Low Risk"        value={stats.low}            accent="#34d399" />
      <StatCard label="Active Clients"  value={stats.active_clients} accent="#60a5fa" />
    </div>
  );
}

function ClientSidebar({ clients, selectedClient, onSelect }) {
  return (
    <div style={{
      width: 220,
      flexShrink: 0,
      background: "#0f172a",
      borderRight: "1px solid #1e293b",
      overflowY: "auto",
      display: "flex",
      flexDirection: "column",
    }}>
      <div style={{
        padding: "12px 16px 8px",
        fontSize: 11,
        fontWeight: 700,
        color: "#475569",
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        borderBottom: "1px solid #1e293b",
      }}>
        Endpoints ({clients.length})
      </div>
      {clients.length === 0 && (
        <div style={{ padding: "20px 16px", color: "#475569", fontSize: 13 }}>
          No clients yet
        </div>
      )}
      {clients.map((c) => {
        const selected = selectedClient?.client_id === c.client_id;
        const lvl = c.max_risk_score >= 80 ? "HIGH" : c.max_risk_score >= 50 ? "MED" : "LOW";
        return (
          <div
            key={c.client_id}
            onClick={() => onSelect(selected ? null : c)}
            style={{
              padding: "10px 16px",
              cursor: "pointer",
              background: selected ? "#1e293b" : "transparent",
              borderLeft: selected ? `3px solid ${RISK[lvl].dot}` : "3px solid transparent",
              transition: "background 0.1s",
            }}
          >
            <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {c.hostname}
            </div>
            <div style={{ marginTop: 4, display: "flex", alignItems: "center", gap: 6 }}>
              <RiskBadge level={lvl} score={c.max_risk_score} />
            </div>
            <div style={{ fontSize: 11, color: "#475569", marginTop: 3 }}>
              {c.ip}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function FilterBar({ filter, onChange }) {
  const options = ["ALL", "HIGH", "MED", "LOW"];
  return (
    <div style={{
      display: "flex",
      gap: 8,
      padding: "12px 20px",
      borderBottom: "1px solid #1e293b",
      flexShrink: 0,
    }}>
      {options.map((opt) => {
        const active = filter === opt;
        const color = opt !== "ALL" ? RISK[opt]?.dot : "#60a5fa";
        return (
          <button
            key={opt}
            onClick={() => onChange(opt)}
            style={{
              padding: "4px 14px",
              borderRadius: 9999,
              border: active ? `1.5px solid ${color}` : "1.5px solid #334155",
              background: active ? "#1e293b" : "transparent",
              color: active ? color : "#94a3b8",
              fontWeight: active ? 700 : 500,
              fontSize: 13,
              cursor: "pointer",
              transition: "all 0.12s",
            }}
          >
            {opt}
          </button>
        );
      })}
    </div>
  );
}

function ClientDetail({ client, onClear }) {
  if (!client) return null;
  const lvl = client.max_risk_score >= 80 ? "HIGH" : client.max_risk_score >= 50 ? "MED" : "LOW";
  return (
    <div style={{
      background: "#1e293b",
      borderBottom: "1px solid #334155",
      padding: "14px 20px",
      display: "flex",
      alignItems: "center",
      gap: 16,
      flexShrink: 0,
    }}>
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: "#f1f5f9" }}>{client.hostname}</span>
          <RiskBadge level={lvl} score={client.max_risk_score} />
        </div>
        <div style={{ marginTop: 4, fontSize: 12, color: "#64748b" }}>
          {client.ip} &nbsp;·&nbsp; Last seen: {formatTime(client.last_seen)}
        </div>
      </div>
      <button
        onClick={onClear}
        style={{
          background: "transparent",
          border: "1px solid #334155",
          color: "#94a3b8",
          borderRadius: 6,
          padding: "4px 12px",
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        Clear filter
      </button>
    </div>
  );
}

function EventCard({ ev }) {
  const lvl = ev.risk_level || "LOW";
  const s = RISK[lvl] || RISK.LOW;
  const typeColors = {
    PROCESS:        "#7c3aed",
    CLIPBOARD:      "#d97706",
    USB_INSERT:     "#0891b2",
    USB_REMOVE:     "#6b7280",
    WINDOW:         "#374151",
    NETWORK_UPLOAD: "#dc2626",
    AFTERHOURS:     "#9333ea",
  };

  return (
    <div style={{
      background: "#1e293b",
      border: "1px solid #334155",
      borderLeft: `3px solid ${s.dot}`,
      borderRadius: 8,
      padding: "10px 14px",
      display: "flex",
      gap: 12,
      alignItems: "flex-start",
    }}>
      <div style={{ paddingTop: 1 }}>
        <RiskBadge level={lvl} score={ev.risk_score} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{
            fontSize: 11,
            fontWeight: 700,
            color: "#fff",
            background: typeColors[ev.event_type] || "#334155",
            borderRadius: 4,
            padding: "1px 7px",
            letterSpacing: "0.04em",
          }}>
            {ev.event_type}
          </span>
          <span style={{ fontSize: 13, fontWeight: 600, color: "#cbd5e1" }}>
            {ev.hostname}
          </span>
          {ev.after_hours && (
            <span style={{ fontSize: 11, color: "#9333ea", fontWeight: 600 }}>
              after-hours
            </span>
          )}
        </div>
        <div style={{ fontSize: 13, color: "#94a3b8", marginTop: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {eventSummary(ev)}
        </div>
      </div>
      <div style={{ fontSize: 11, color: "#475569", whiteSpace: "nowrap", paddingTop: 2 }}>
        {formatTime(ev.timestamp)}
      </div>
    </div>
  );
}

function EventFeed({ events, filter, selectedClient }) {
  const filtered = events.filter((ev) => {
    if (filter !== "ALL" && ev.risk_level !== filter) return false;
    if (selectedClient && ev.client_id !== selectedClient.client_id) return false;
    return true;
  });

  if (filtered.length === 0) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#475569", fontSize: 14 }}>
        No events match the current filter
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "12px 20px", display: "flex", flexDirection: "column", gap: 8 }}>
      {filtered.map((ev) => (
        <EventCard key={ev.id} ev={ev} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function InsiderThreatDashboard() {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const lastIdRef = useRef(0);

  // ---------------------------------------------------------------------------
  // Live polling
  // ---------------------------------------------------------------------------
  const poll = useCallback(async () => {
    try {
      const [eventsRes, clientsRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/events?since=${lastIdRef.current}&limit=50`),
        fetch(`${API_BASE}/clients`),
        fetch(`${API_BASE}/stats`),
      ]);

      if (!eventsRes.ok || !clientsRes.ok || !statsRes.ok) {
        throw new Error(`HTTP ${eventsRes.status}`);
      }

      const newEvents = await eventsRes.json();
      const clients   = await clientsRes.json();
      const stats     = await statsRes.json();

      if (newEvents.length > 0) {
        // Events are returned newest-first (ORDER BY id DESC)
        lastIdRef.current = newEvents[0].id;
        dispatch({ type: "PREPEND_EVENTS", payload: newEvents });
      }
      dispatch({ type: "SET_CLIENTS", payload: clients });
      dispatch({ type: "SET_STATS",   payload: stats });
      dispatch({ type: "SET_ERROR",   payload: null });
    } catch (e) {
      dispatch({ type: "SET_ERROR", payload: "Cannot reach server" });
    }
  }, []);

  useEffect(() => {
    if (state.demoMode) return;
    poll();
    const id = setInterval(poll, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [state.demoMode, poll]);

  // ---------------------------------------------------------------------------
  // Demo mode ticker
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!state.demoMode) return;
    const id = setInterval(() => {
      const ev = generateDemoEvent();
      dispatch({ type: "PREPEND_EVENTS", payload: [ev] });
    }, 2000);
    return () => clearInterval(id);
  }, [state.demoMode]);

  // Keep demo clients and stats derived from demo events
  useEffect(() => {
    if (!state.demoMode) return;
    const clients = buildDemoClients(state.events);
    dispatch({ type: "SET_CLIENTS", payload: clients });
    const high = state.events.filter((e) => e.risk_level === "HIGH").length;
    const med  = state.events.filter((e) => e.risk_level === "MED").length;
    const low  = state.events.filter((e) => e.risk_level === "LOW").length;
    dispatch({
      type: "SET_STATS",
      payload: { total: state.events.length, high, med, low, active_clients: clients.length },
    });
  }, [state.events, state.demoMode]);

  // Reset lastIdRef when switching out of demo mode
  const handleToggleDemo = useCallback(() => {
    lastIdRef.current = 0;
    dispatch({ type: "TOGGLE_DEMO" });
  }, []);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      height: "100vh",
      background: "#0f172a",
      color: "#f1f5f9",
      fontFamily: "'Inter', 'Segoe UI', system-ui, sans-serif",
      overflow: "hidden",
    }}>
      <TopBar
        demoMode={state.demoMode}
        onToggleDemo={handleToggleDemo}
        error={state.error}
      />

      <StatCards stats={state.stats} />

      {/* Two-column layout */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden", marginTop: 16 }}>
        <ClientSidebar
          clients={state.clients}
          selectedClient={state.selectedClient}
          onSelect={(c) => dispatch({ type: "SELECT_CLIENT", payload: c })}
        />

        {/* Main panel */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <FilterBar
            filter={state.filter}
            onChange={(f) => dispatch({ type: "SET_FILTER", payload: f })}
          />
          <ClientDetail
            client={state.selectedClient}
            onClear={() => dispatch({ type: "SELECT_CLIENT", payload: null })}
          />
          <EventFeed
            events={state.events}
            filter={state.filter}
            selectedClient={state.selectedClient}
          />
        </div>
      </div>
    </div>
  );
}
