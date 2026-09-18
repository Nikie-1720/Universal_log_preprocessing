import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, ArrowDown, ArrowRight, CheckCircle2, ChevronDown, ChevronRight,
  CircleDot, Clock3, Copy, Database, FileSearch, Fingerprint, GitBranch,
  Globe2, Layers3, LockKeyhole, Menu, Moon, Network, Play, PlugZap,
  Radio, RefreshCw, Search, Server, ShieldCheck, Sparkles, Sun, Terminal,
  Upload, Download, X, Zap, AlertTriangle, Eye, Cpu, Boxes, Workflow, MessageCircle
} from "lucide-react";
import {
  AreaChart, Area, ResponsiveContainer, Tooltip, XAxis, YAxis
} from "recharts";
import "./styles.css";

const SAMPLES = {
  forti: `date=2026-09-09 time=18:10:32 devname="FW-01" devid="FG100F3X21000001" type="traffic" subtype="forward" level="notice" srcip=192.168.1.25 srcport=51542 srcintf="LAN" dstip=8.8.8.8 dstport=443 dstintf="WAN" proto=6 action="accept" service="HTTPS" policyid=12 sentbyte=1240 rcvdbyte=5820`,
  cisco: `%ASA-6-302013: Built outbound TCP connection 12345 for inside:192.168.1.25/51542 to outside:8.8.8.8/443`,
  cef: `CEF:0|DemoFirewall|EdgeGate|1.0|100|Outbound connection|5|src=192.168.1.25 dst=8.8.8.8 spt=51542 dpt=443 proto=TCP act=allow`,
  json: `{"timestamp":"2026-09-09T18:10:32Z","src_ip":"192.168.1.25","dst_ip":"8.8.8.8","dst_port":443,"action":"allow","service":"HTTPS","user":"alice"}`,
  syslog: `Sep  9 18:10:32 host sshd[1204]: Failed password for user alice from 192.168.1.25 port 51542 ssh2`
};

const SOURCES = [
  { label: "FortiGate", format: "KV / Syslog", icon: ShieldCheck },
  { label: "Cisco ASA", format: "Syslog", icon: Network },
  { label: "CEF Firewall", format: "CEF", icon: Globe2 },
  { label: "Application", format: "JSON", icon: Boxes },
  { label: "Host / System", format: "Syslog", icon: Server }
];

const NAV_ITEMS = ["Overview", "Live Ingest", "Events", "Forensics", "Correlations", "Agents", "Plugins"];

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const text = await response.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; }
  catch { throw new Error(`Invalid API response (${response.status})`); }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function isRuntimePlugin(plugin) {
  const marker = [
    plugin?.path,
    plugin?._path,
    plugin?.plugin_path,
    plugin?.manifest_path,
    plugin?.entrypoint
  ]
    .filter(Boolean)
    .join(" ")
    .split("\\").join("/");

  return Boolean(
    plugin?.manifest ||
    plugin?.plugin_type === "runtime" ||
    plugin?.type === "runtime" ||
    /(^|\/)plugins\//i.test(marker) ||
    /runtime/i.test(String(plugin?.kind || ""))
  );
}

function correlationTraceIds(caseItem) {
  const direct = caseItem?.trace_ids || caseItem?.evidence_trace_ids || caseItem?.evidence_ids || [];
  const evidence = Array.isArray(caseItem?.evidence) ? caseItem.evidence : [];
  const evidenceIds = evidence.map(item =>
    item?.trace_id || item?.trace?.trace_id || item?.event?.trace?.trace_id
  ).filter(Boolean);
  return [...new Set([...direct, ...evidenceIds].map(String))];
}

function flattenObject(obj, prefix = "") {
  return Object.entries(obj || {}).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    return v && typeof v === "object" && !Array.isArray(v) ? flattenObject(v, key) : [[key, v]];
  });
}

function eventText(event) {
  return JSON.stringify(event || {}).toLowerCase();
}

function getField(event, names) {
  const flat = flattenObject(event?.ues || event?.normalized || {});
  const wanted = names.map(x => x.toLowerCase());
  const found = flat.find(([k]) => wanted.some(w => k.toLowerCase().endsWith(w) || k.toLowerCase() === w));
  return found?.[1];
}

function correlationAnalysis(events, current) {
  if (!current) return "No event is selected yet. Normalize at least one log first.";
  const fields = [
    ["source IP", ["source.ip", "src_ip", "srcip", "src.ip"]],
    ["destination IP", ["destination.ip", "dst_ip", "dstip", "dst.ip"]],
    ["user", ["user.name", "user", "username"]],
    ["destination port", ["destination.port", "dst_port", "dstport"]],
    ["action", ["event.action", "action"]]
  ];
  const matches = [];
  for (const other of events) {
    if (other === current) continue;
    const shared = fields.filter(([, names]) => {
      const a = getField(current, names);
      const b = getField(other, names);
      return a != null && b != null && String(a).toLowerCase() === String(b).toLowerCase();
    }).map(([label]) => label);
    if (shared.length) matches.push({ other, shared });
  }
  if (!matches.length) return `I found no direct field correlation with the other ${Math.max(0, events.length - 1)} loaded event(s). Correlation is based on shared normalized values, not a threat verdict.`;
  const top = matches.slice(0, 6).map(m => {
    const id = String(m.other?.trace?.trace_id || "event").slice(0, 18);
    return `• ${id}: ${m.shared.join(", ")}`;
  }).join("\n");
  return `Found ${matches.length} correlated event(s) using shared normalized fields:\n${top}\n\nThis is evidence correlation only; it does not prove causality.`;
}

function analyzeLogQuestion(question, events, latest) {
  const q = question.toLowerCase().trim();
  if (!events.length) return "No normalized logs are loaded yet. Ingest or normalize a log and I can analyze it.";
  if (/correlat|related|relation|link|connect/.test(q)) return correlationAnalysis(events, latest);

  const target = latest || events[0];
  const suspiciousWords = ["failed", "deny", "denied", "drop", "blocked", "error", "attack", "malware", "unauthorized", "invalid"];
  const suspicious = events.filter(e => suspiciousWords.some(w => eventText(e).includes(w)));
  const vendors = {};
  const formats = {};
  events.forEach(e => {
    const vendor = e?.ues?.device?.vendor || "Unknown";
    const format = e?.meta?.format || "unknown";
    vendors[vendor] = (vendors[vendor] || 0) + 1;
    formats[format] = (formats[format] || 0) + 1;
  });

  if (/how many|count|total|number|kitne|kitna/.test(q)) {
    if (/suspicious|threat|attack|risk|failed|error|blocked|deny/.test(q))
      return `${suspicious.length} of ${events.length} loaded event(s) contain heuristic security/error indicators. This is not a confirmed threat verdict.`;
    return `There are ${events.length} normalized event(s) currently loaded in the dashboard.`;
  }

  if (/vendor|source|device/.test(q)) {
    return `Source distribution:\n${Object.entries(vendors).map(([k,v]) => `• ${k}: ${v}`).join("\n")}`;
  }

  if (/format|type/.test(q)) {
    return `Format distribution:\n${Object.entries(formats).map(([k,v]) => `• ${k}: ${v}`).join("\n")}`;
  }

  if (/raw|original|evidence|lossless|hash/.test(q)) {
    return `For the current event: raw evidence is ${target?.raw ? "present and preserved" : "not available in the loaded record"}; SHA-256 is ${target?.trace?.raw_hash ? "recorded" : "not recorded in this event"}; trace ID is ${target?.trace?.trace_id || "unavailable"}.`;
  }

  if (/lineage|mapping|parser|normalize|normalized|ues|universal/.test(q)) {
    const trace = target?.trace || {};
    const meta = target?.meta || {};
    const fieldCount = flattenObject(target?.ues || target?.normalized || {}).length;
    return `Current event pipeline:\n• Parser: ${meta.parser || "unavailable"}\n• Format: ${meta.format || "unknown"}\n• Universal fields: ${fieldCount}\n• Trace ID: ${trace.trace_id || "unavailable"}\n• Raw hash: ${trace.raw_hash || "unavailable"}\n\nFor field-by-field mapping, open Forensics and click any universal field.`;
  }

  if (/ip|source|destination|port|user|action|service|protocol|time|timestamp|field|details|detail|analy[sz]e|about|everything|a to z/.test(q)) {
    const flat = flattenObject(target?.ues || target?.normalized || {});
    const preview = flat.slice(0, 22).map(([k,v]) => `• ${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`).join("\n");
    return `Current log analysis:\n• Source: ${target?.meta?.source_type || "unknown"}\n• Format: ${target?.meta?.format || "unknown"}\n• Parser: ${target?.meta?.parser || "unknown"}\n• Trace ID: ${target?.trace?.trace_id || "unknown"}\n• Integrity hash: ${target?.trace?.raw_hash || "unknown"}\n• Fields:\n${preview || "No normalized fields available."}\n\nHeuristic indicators across loaded logs: ${suspicious.length}/${events.length}.`;
  }

  if (/help|what can|can you|kya kar/.test(q)) {
    return "I can analyze the loaded normalized logs: fields, source/vendor, format, parser, raw evidence, hashes, lineage, heuristic indicators, event counts, and correlations between events. Ask a specific question like \"correlate these logs by IP and time\" or \"explain this event\".";
  }

  return `I can answer from the ${events.length} normalized event(s) currently loaded. Try asking about fields, IPs, users, actions, timestamps, raw evidence, lineage, parser/format, suspicious indicators, counts, or correlations.`;
}

// ============ ALERT GROUPING HELPERS ============

function parseTime(value) {
  if (!value) return 0;
  try {
    const text = String(value).replace("Z", "+00:00");
    return new Date(text).getTime();
  } catch {
    return 0;
  }
}

function alertFingerprint(alert) {
  const rule = String(alert?.rule || alert?.rule_id || "");
  const source = String(alert?.source_ip || "unknown");
  const reason = String(alert?.reason || "");
  let action = "";
  for (const token of reason.replace(/,/g, " ").split(" ")) {
    if (token.startsWith("action=")) {
      action = token.split("=")[1];
      break;
    }
  }
  return action ? `${rule}|${source}|${action}` : `${rule}|${source}`;
}

function groupAlerts(rawAlerts, windowSeconds = 300) {
  const groups = new Map();
  const correlations = [];

  for (const alert of rawAlerts) {
    const rule = String(alert.rule || alert.rule_id || "");
    if (rule.startsWith("correlation-") || alert.correlation_id) {
      correlations.push(alert);
      continue;
    }
    if (!["threat-intel-match", "high-severity", "security-failure"].includes(rule)) {
      continue;
    }

    const fp = alertFingerprint(alert);
    if (!groups.has(fp)) groups.set(fp, []);
    groups.get(fp).push(alert);
  }

  const grouped = [];

  for (const [, items] of groups.entries()) {
    items.sort((a, b) => parseTime(a.created_at) - parseTime(b.created_at));

    let currentWindow = [];
    const windows = [];

    for (const item of items) {
      const ts = parseTime(item.created_at);
      if (!currentWindow.length) {
        currentWindow = [item];
      } else {
        const prev = parseTime(currentWindow[currentWindow.length - 1].created_at);
        if (ts - prev <= windowSeconds * 1000) {
          currentWindow.push(item);
        } else {
          windows.push(currentWindow);
          currentWindow = [item];
        }
      }
    }
    if (currentWindow.length) windows.push(currentWindow);

    for (const win of windows) {
      const first = win[0];
      const last = win[win.length - 1];
      const rule = String(first.rule || first.rule_id);
      const src = first.source_ip || "unknown";

      const traceIds = [];
      const alertIds = [];
      const parsers = new Set();
      const actions = new Set();
      let topSeverity = "low";
      const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };

      for (const a of win) {
        if (a.trace_id && !traceIds.includes(String(a.trace_id))) {
          traceIds.push(String(a.trace_id));
        }
        (a.evidence_trace_ids || []).forEach(t => {
          if (t && !traceIds.includes(String(t))) traceIds.push(String(t));
        });
        if (a.alert_id) alertIds.push(String(a.alert_id));
        if (a.parser) parsers.add(String(a.parser));
        const reason = String(a.reason || "");
        for (const token of reason.replace(/,/g, " ").split(" ")) {
          if (token.startsWith("action=")) actions.add(token.split("=")[1]);
        }
        const sev = String(a.severity || "low").toLowerCase();
        if (severityRank[sev] > severityRank[topSeverity]) topSeverity = sev;
      }

      const count = win.length;
      const baseTitle = first.title || "Security alert";
      const title = count > 1 ? `${baseTitle} (${count} events)` : baseTitle;

      const firstTs = first.created_at;
      const lastTs = last.created_at;
      const duration = Math.max(0, Math.floor((parseTime(lastTs) - parseTime(firstTs)) / 1000));

      grouped.push({
        alert_id: `GROUP-${rule}-${src}-${alertIds[0] || "x"}`,
        group: count > 1,
        group_size: count,
        created_at: lastTs,
        rule,
        rule_id: rule,
        title,
        severity: topSeverity,
        reason: count > 1
          ? `${count} related ${rule} events from ${src}${actions.size ? ` (action: ${[...actions].join(", ")})` : ""}. Duration: ${duration}s.`
          : first.reason,
        source_ip: src,
        parser: [...parsers].join(", ") || first.parser,
        trace_id: traceIds[traceIds.length - 1] || null,
        trace_ids: traceIds,
        evidence_trace_ids: traceIds,
        alert_ids: alertIds,
        event_count: count,
        first_seen: firstTs,
        last_seen: lastTs,
        duration_seconds: duration,
        acknowledged: win.every(a => a.acknowledged),
        actions: [...actions],
        is_correlation: false,
        risk_score: first.risk_score,
      });
    }
  }

  for (const c of correlations) {
    grouped.push({
      ...c,
      group: false,
      group_size: c.event_count || 1,
      trace_ids: c.evidence_trace_ids || c.trace_ids || [c.trace_id].filter(Boolean),
      alert_ids: [c.alert_id],
      first_seen: c.first_seen || c.created_at,
      last_seen: c.last_seen || c.created_at,
      duration_seconds: c.duration_seconds || 0,
      is_correlation: true,
    });
  }

  return grouped.sort((a, b) => parseTime(b.created_at) - parseTime(a.created_at));
}

// ============ MAIN APP ============

function App() {
  const [theme, setTheme] = useState(localStorage.ulpfTheme || "dark");
  const [active, setActive] = useState("Overview");
  const [raw, setRaw] = useState(SAMPLES.forti);
  const [sample, setSample] = useState("forti");
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({ received: 0, parsed: 0, failed: 0, threat_hits: 0 });
  const [plugins, setPlugins] = useState([]);
  const [busy, setBusy] = useState(false);
  const [live, setLive] = useState(false);
  const [message, setMessage] = useState("");
  const [drawer, setDrawer] = useState(null);
  const [search, setSearch] = useState("");
  const [mobileNav, setMobileNav] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [rawAlerts, setRawAlerts] = useState([]);
  const [lastAlertId, setLastAlertId] = useState(null);
  const [alertPopup, setAlertPopup] = useState(null);
  const [expandedAlertId, setExpandedAlertId] = useState(null);
  const fileInputRef = useRef(null);
  const [agents, setAgents] = useState([]);
  const [correlationCases, setCorrelationCases] = useState([]);
  const [correlationLoading, setCorrelationLoading] = useState(false);
  const [forensicEvent, setForensicEvent] = useState(null);
  const [forensicTrace, setForensicTrace] = useState(null);
  const [agentSetupOpen, setAgentSetupOpen] = useState(false);
  const [agentDownloaded, setAgentDownloaded] = useState(false);
  const [airgap, setAirgap] = useState(null);
  const alerts = useMemo(() => groupAlerts(rawAlerts), [rawAlerts]);

  const realAlerts = useMemo(
    () => alerts.filter(a =>
      ["threat-intel-match", "high-severity", "security-failure"].includes(a.rule) ||
      String(a.rule || "").startsWith("correlation-")
    ),
    [alerts]
  );

  const runtimePlugins = useMemo(() => plugins.filter(isRuntimePlugin), [plugins]);
  const parserIntegrations = useMemo(() => plugins.filter(p => !isRuntimePlugin(p)), [plugins]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.ulpfTheme = theme;
  }, [theme]);

  async function refresh() {
    try {
      const [e, p, s, a, ag, c,air] = await Promise.all([
        api("/api/events?limit=200"),
        api("/api/plugins"),
        api("/api/stats"),
        api("/api/alerts?limit=100"),
        api("/api/agents"),
        api("/api/correlations?limit=200").catch(() => ({ correlations: [], cases: [] })),
        api("/api/security/airgap").catch(() => null)
      ]);
      setEvents(e.events || []);
      setPlugins(p.plugins || []);
      setStats(s?.counters || {});
      setRawAlerts(a?.alerts || []);
      setAgents(ag?.agents || []);
      setCorrelationCases(c?.correlations || c?.cases || []);
      setAirgap(air);
      setCorrelationLoading(false);
    } catch (err) {
      setCorrelationLoading(false);
      setMessage(err.message);
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const newest = realAlerts[0];
    if (!newest || newest.alert_id === lastAlertId) return;
    if (lastAlertId !== null && "Notification" in window) {
      if (Notification.permission === "granted") {
        new Notification(`ULPF Alert: ${newest.title}`, { body: newest.reason || "Suspicious event detected" });
      } else if (Notification.permission === "default") {
        Notification.requestPermission().catch(() => {});
      }
      setAlertPopup(newest);
      if ("speechSynthesis" in window) {
        window.speechSynthesis.cancel();
        window.speechSynthesis.speak(new SpeechSynthesisUtterance("Suspicious activity detected"));
      }
      window.setTimeout(() => setAlertPopup(null), 5000);
    }
    setLastAlertId(newest.alert_id);
  }, [realAlerts, lastAlertId]);

  useEffect(() => {
    if (!live) return undefined;
    const id = setInterval(async () => {
      const keys = Object.keys(SAMPLES);
      const key = keys[Math.floor(Math.random() * keys.length)];
      try {
        await api("/api/normalize", {
          method: "POST",
          body: JSON.stringify({ raw: SAMPLES[key], source_type: "live-demo", address: `${key}-source` })
        });
        await refresh();
        setMessage(`Live source received • ${key.toUpperCase()} event normalized`);
      } catch (err) {
        setMessage(err.message);
      }
    }, 5500);
    return () => clearInterval(id);
  }, [live]);

  function downloadAgentPlugin() {
    const link = document.createElement("a");
    link.href = "/api/agent-plugin/download";
    link.download = "ULPF-Agent-Plugin.zip";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setAgentDownloaded(true);
    setAgentSetupOpen(true);
  }

  async function normalize() {
    if (!raw.trim()) return setMessage("Paste a log or choose a sample first.");
    setBusy(true);
    setMessage("Running deterministic preprocessing…");
    try {
      const d = await api("/api/normalize", {
        method: "POST",
        body: JSON.stringify({ raw })
      });
      setMessage(`${d.count} event${d.count === 1 ? "" : "s"} normalized • lineage recorded`);
      await refresh();
      setActive("Events");
    } catch (err) {
      setMessage(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function uploadLog(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setBusy(true);
    setMessage(`Reading ${file.name}…`);
    try {
      const content = await file.text();
      if (!content.trim()) throw new Error("Selected log file is empty.");
      setRaw(content);
      setSample("");
      const d = await api("/api/normalize", {
        method: "POST",
        body: JSON.stringify({ raw: content, source_type: "file-upload", address: file.name })
      });
      setMessage(`${d.count} event${d.count === 1 ? "" : "s"} normalized from ${file.name}`);
      await refresh();
      setActive("Events");
    } catch (err) {
      setMessage(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function normalizeSystem() {
    setBusy(true);
    setMessage("Reading available host/system log files…");
    try {
      const d = await api("/api/normalize-system", {
        method: "POST",
        body: JSON.stringify({ limit: 50 })
      });
      setMessage(`${d.count} system event${d.count === 1 ? "" : "s"} normalized from local log files`);
      await refresh();
      setActive("Events");
    } catch (err) {
      setMessage(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function openLineage(event, field) {
    const trace = event?.trace?.trace_id;
    if (!trace) return;
    try {
      const d = await api(`/api/events/${encodeURIComponent(trace)}/lineage`);
      const item = (d.lineage || []).find(x =>
        x.normalized_field === field || x.target === field
      );
      setForensicEvent(event);
      setDrawer({ event, field, data: d, item });
      setActive("Forensics");
    } catch (err) {
      setMessage(err.message);
    }
  }

  async function openAlertTrace(alert) {
    try {
      const trace = await api(`/api/alerts/${encodeURIComponent(alert.alert_id)}/trace`);
      const ids = (trace.trace_ids || trace.evidence_trace_ids || alert.evidence_trace_ids || []).map(String);
      const match = trace.events?.[0] || events.find(event => ids.includes(String(event?.trace?.trace_id)));
      if (match) {
        setForensicTrace(trace);
        setForensicEvent(match);
        setActive("Forensics");
        return;
      }
      throw new Error("No linked evidence returned by the backend");
    } catch (err) {
      const ids = (alert.evidence_trace_ids || alert.trace_ids || [alert.trace_id]).filter(Boolean).map(String);
      let match = events.find(event => ids.includes(String(event?.trace?.trace_id)));
      if (!match) {
        const sourceIp = alert.source_ip || alert.src_ip || alert.source?.ip;
        if (sourceIp) match = events.find(event => String(getField(event, ["source.ip", "src_ip", "srcip"]) || "") === String(sourceIp));
      }
      if (!match) {
        setMessage("Alert exists, but no matching loaded event is available for trace.");
        return;
      }
      setForensicTrace({
        alert,
        count: 1,
        trace_ids: [match?.trace?.trace_id].filter(Boolean),
        events: [match],
        offline_fallback: true
      });
      setForensicEvent(match);
      setActive("Forensics");
    }
  }

  function openCorrelationTrace(item) {
    const ids = correlationTraceIds(item);
    const match = events.find(event => ids.includes(String(event?.trace?.trace_id))) || events.find(event =>
      String(getField(event, ["source.ip", "src_ip", "srcip"]) || "") === String(item?.source_ip || "")
    );
    if (!match) {
      setMessage("No loaded evidence event is available for this correlation.");
      return;
    }
    setForensicTrace({
      alert: {
        title: item.title || "Correlated activity",
        reason: item.description || "Related normalized events sharing security fields.",
        rule: item.rule_id || item.rule || "field-correlation",
        risk_score: item.risk_score,
        severity: item.severity
      },
      count: ids.length || 1,
      trace_ids: ids,
      events: ids.map(id => events.find(event => String(event?.trace?.trace_id) === id)).filter(Boolean),
      offline_fallback: true
    });
    setForensicEvent(match);
    setActive("Forensics");
  }

  async function acknowledgeAlert(alert) {
    try {
      const ids = alert.alert_ids || [alert.alert_id];
      for (const id of ids) {
        await api("/api/alerts/ack", {
          method: "POST",
          body: JSON.stringify({ alert_id: id })
        });
      }
      await refresh();
    } catch (e) {
      setMessage(e.message);
    }
  }

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter(e => !q || JSON.stringify(e).toLowerCase().includes(q));
  }, [events, search]);

  const latest = visible[0] || events[0];
  const chart = useMemo(() => {
    const base = Math.max(3, events.length);
    return Array.from({ length: 16 }, (_, i) => ({
      t: i,
      events: Math.max(1, Math.round(base * (0.55 + Math.sin(i / 2.2) * 0.12 + i / 24)))
    }));
  }, [events]);

  const unackAlertCount = realAlerts.filter(a => !a.acknowledged).length;

  function navTo(label) {
    setActive(label);
    setMobileNav(false);
  }

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="top-nav">
        <div className="brand-lockup">
          <div className="brand-symbol"><span>U</span><i /></div>
          <div>
            <b>ULPF</b>
            <small>Universal Log Pre-processing Framework</small>
          </div>
        </div>

        <nav className={`main-nav ${mobileNav ? "open" : ""}`}>
          {NAV_ITEMS.map(label => (
            <button
              key={label}
              className={active === label ? "nav-link active" : "nav-link"}
              onClick={() => navTo(label)}
            >
              {label === "Live Ingest" && <span className="live-mini-dot" />}
              {label === "Correlations" && correlationCases.length > 0 && (
                <span className="nav-count-badge">{correlationCases.length}</span>
              )}
              {label}
            </button>
          ))}
        </nav>

        <div className="top-actions">
          <div className="global-search">
            <Search size={15} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events" />
            <kbd>⌘ K</kbd>
          </div>
          <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            <span>{theme === "dark" ? "Light" : "Dark"}</span>
          </button>
          <button className="mobile-menu" onClick={() => setMobileNav(v => !v)}><Menu size={19} /></button>
          <div className="secure-pill"><LockKeyhole size={13} /> AIR-GAP</div>
        </div>
      </header>

      <main>
        <section className="hero-section">
          <div className="hero-copy">
            <div className="eyebrow"><span className="pulse" /> SECURITY TELEMETRY FABRIC <span className="eyebrow-sep">/</span> ULPF-1.0</div>
            <h1>Every signal.<br /><em>One traceable language.</em></h1>
            <p>
              Ingest heterogeneous network and system telemetry, preserve the original evidence,
              normalize it into a universal event model, and keep the entire transformation explainable.
            </p>
            <div className="hero-badges">
              <span><CheckCircle2 size={14} /> Lossless evidence</span>
              <span><Fingerprint size={14} /> Field-level lineage</span>
              <span><PlugZap size={14} /> Plugin-native</span>
            </div>
          </div>

          <div className="hero-status">
            <div className="status-orbit">
              <div className="orbit orbit-a" />
              <div className="orbit orbit-b" />
              <div className="orbit-core"><ShieldCheck size={28} /><span>ULPF</span></div>
              <span className="orbit-label label-top">RAW</span>
              <span className="orbit-label label-right">UES</span>
              <span className="orbit-label label-bottom">TRACE</span>
              <span className="orbit-label label-left">SIEM</span>
            </div>
            <div className="system-status"><span /><b>Core online</b><small>Deterministic processing · offline ready</small></div>
          </div>
        </section>

        <section className="metric-row">
          <Metric label="Events processed" value={stats.received ?? events.length} icon={Activity} meta="live counter" />
          <Metric label="Validation pass" value={stats.parsed ?? 0} icon={CheckCircle2} meta="schema + type" />
          <Metric label="Threat matches" value={stats.threat_hits ?? 0} icon={ShieldCheck} meta="local intelligence" />
          <Metric label="Plugins online" value={runtimePlugins.length} icon={PlugZap} meta="runtime plugin packages" />
        </section>

        

        <AnimatePresence mode="wait">
          {active === "Overview" && (
            <motion.div key="overview" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              <AirGapProof airgap={airgap} />
              {unackAlertCount > 0 && (
                <section className="alerts-panel">
                  <div className="alerts-head">
                    <div>
                      <span className="eyebrow">LIVE ALERTS</span>
                      <h2>Suspicious activity <span>{unackAlertCount}</span></h2>
                    </div>
                    <small>Deterministic ULPF rules · local notification</small>
                  </div>
                  <div className="alerts-list">
                    {realAlerts.slice(0, 6).map(alert => (
                      <AlertCard
                        key={alert.alert_id}
                        alert={alert}
                        expanded={expandedAlertId === alert.alert_id}
                        onToggleExpand={() => setExpandedAlertId(expandedAlertId === alert.alert_id ? null : alert.alert_id)}
                        onTrace={() => openAlertTrace(alert)}
                        onAck={() => acknowledgeAlert(alert)}
                      />
                    ))}
                  </div>
                </section>
              )}

              

              <section className="section-heading">
                <div><span>CONTROL CENTER</span><h2>Normalization at a glance</h2></div>
                <div className="heading-actions">
                  <button className="soft-btn" onClick={refresh}><RefreshCw size={14} /> Refresh</button>
                  <button className="primary-btn" onClick={() => navTo("Live Ingest")}><Radio size={14} /> Open live ingest</button>
                </div>
              </section>

              <div className="overview-grid">
                <div className="card ingest-card">
                  <CardHeading icon={Upload} kicker="INGEST" title="Bring in raw telemetry" />
                  <div className="source-strip">
                    {SOURCES.map(({ label, format, icon: Icon }) => (
                      <div className="source-chip" key={label}><Icon size={13} /><span>{label}</span><small>{format}</small></div>
                    ))}
                  </div>
                  <div className="raw-preview">
                    <div className="raw-preview-head"><span><span className="record-dot" /> RAW EVENT</span><small>SHA-256 preserved</small></div>
                    <pre>{latest?.raw || raw}</pre>
                  </div>
                  <div className="ingest-actions">
                    <select value={sample} onChange={e => { setSample(e.target.value); setRaw(SAMPLES[e.target.value] || ""); }}>
                      <option value="forti">FortiGate traffic</option>
                      <option value="cisco">Cisco ASA</option>
                      <option value="cef">CEF firewall</option>
                      <option value="json">JSON application</option>
                      <option value="syslog">SSH / system syslog</option>
                    </select>
                    <button className="primary-btn" onClick={normalize} disabled={busy}><Play size={14} /> {busy ? "Processing" : "Normalize sample"}</button>
                  </div>
                </div>

                <div className="card live-card">
                  <div className="live-card-top">
                    <CardHeading icon={Radio} kicker="LIVE SOURCES" title="Telemetry is arriving" />
                    <span className={live ? "live-state on" : "live-state"}><span /> {live ? "STREAMING" : "IDLE"}</span>
                  </div>
                  <div className="live-visual">
                    <div className="signal-grid">
                      {Array.from({ length: 36 }, (_, i) => <i key={i} className={i % 5 === 0 ? "signal-hot" : ""} />)}
                    </div>
                    <div className="live-center"><Radio size={20} /><b>{live ? "LIVE" : "READY"}</b><small>{live ? "demo sources feeding ULPF" : "start a local demo stream"}</small></div>
                  </div>
                  <div className="live-source-list">
                    <SourceRow name="FortiGate FW-01" format="KV / Syslog" status={live ? "receiving" : "ready"} />
                    <SourceRow name="Cisco ASA edge" format="Syslog" status={live ? "receiving" : "ready"} />
                    <SourceRow name="Host system logs" format="Syslog" status="local files" />
                  </div>
                  <button className={live ? "stop-live-btn" : "live-btn"} onClick={() => setLive(v => !v)}>
                    {live ? <><span className="stop-square" /> Stop live stream</> : <><Radio size={14} /> Start live demo stream</>}
                  </button>
                  <small className="disclaimer">Demo stream uses bundled representative events. Host logs can be read from mounted local log files.</small>
                </div>
              </div>

              <section className="card activity-card">
                <CardHeading icon={Zap} kicker="INGESTION ACTIVITY" title="Events through the normalization fabric" />
                <div className="chart-area">
                  <ResponsiveContainer width="100%" height={200}>
                    <AreaChart data={chart}>
                      <defs>
                        <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent)" stopOpacity=".32" />
                          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="t" hide /><YAxis hide />
                      <Tooltip contentStyle={{ background: "var(--card)", border: "1px solid var(--line)", borderRadius: 12, color: "var(--text)" }} />
                      <Area type="monotone" dataKey="events" stroke="var(--accent)" fill="url(#activityFill)" strokeWidth={2.5} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </section>

              <section className="usp-strip">
                <USP icon={Fingerprint} title="Forensic by construction" text="Raw evidence, hash and field lineage survive normalization." />
                <USP icon={PlugZap} title="Formal plugin contract" text="Parser + mappings + tests can be versioned and certified." />
                <USP icon={LockKeyhole} title="Air-gap ready" text="Deterministic core does not depend on internet APIs." />
                <USP icon={Layers3} title="Don't replace — augment" text="Feed universal events into existing SIEM and data platforms." />
              </section>
            </motion.div>
          )}

          {active === "Live Ingest" && (
            <motion.div key="live" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <section className="section-heading">
                <div><span>INGESTION CONTROL</span><h2>Make telemetry feel alive</h2></div>
                <div className={live ? "stream-badge active" : "stream-badge"}><span /> {live ? "Receiving events" : "Stream stopped"}</div>
              </section>

              <div className="live-layout">
                <div className="card live-console">
                  <div className="console-head"><div><span className="eyebrow">SOURCE SIMULATOR</span><h3>Incoming security events</h3></div><Radio size={18} /></div>
                  <div className="source-buttons">
                    {Object.entries(SAMPLES).map(([key, value]) => (
                      <button key={key} className={sample === key ? "source-select active" : "source-select"} onClick={() => { setSample(key); setRaw(value); }}>
                        <span>{key === "forti" ? "FG" : key === "cisco" ? "CA" : key === "cef" ? "CF" : key === "json" ? "{}" : "OS"}</span>
                        <b>{key === "forti" ? "FortiGate" : key === "cisco" ? "Cisco ASA" : key === "cef" ? "CEF Firewall" : key === "json" ? "JSON App" : "System / SSH"}</b>
                        <small>ready</small>
                      </button>
                    ))}
                  </div>
                  <textarea value={raw} onChange={e => setRaw(e.target.value)} spellCheck="false" />
                  <div className="console-footer">
                    <span><Terminal size={13} /> {raw.split(/\r?\n/).filter(Boolean).length} event line</span>
                    <div className="console-actions">
                      <input ref={fileInputRef} className="file-input" type="file" accept=".log,.txt,.json,.jsonl,.csv,.cef,.ndjson,.syslog" onChange={uploadLog} />
                      <button className="soft-btn upload-btn" onClick={() => fileInputRef.current?.click()} disabled={busy}><Upload size={14} /> Upload log</button>
                      <button className="primary-btn" onClick={normalize} disabled={busy}><Zap size={14} /> Normalize now</button>
                    </div>
                  </div>
                </div>

                <div className="card live-control">
                  <div className="control-orb"><div><Radio size={25} /><span>{live ? "ON" : "OFF"}</span></div></div>
                  <h3>{live ? "Live demo stream is running" : "Start the telemetry stream"}</h3>
                  <p>ULPF will receive a representative event every few seconds and process it through the same deterministic pipeline.</p>
                  <button className={live ? "stop-live-btn large" : "live-btn large"} onClick={() => setLive(v => !v)}>
                    {live ? <><span className="stop-square" /> Stop stream</> : <><Radio size={15} /> Start live stream</>}
                  </button>
                  <button className="system-btn" onClick={normalizeSystem} disabled={busy}><Server size={14} /> Normalize local system logs</button>
                  {message && <div className="inline-message"><CircleDot size={13} /> {message}</div>}
                  <div className="source-foot"><LockKeyhole size={13} /> No cloud connection required for deterministic processing.</div>
                </div>
              </div>

              <section className="card source-guide">
                <CardHeading icon={Server} kicker="WHERE LOGS COME FROM" title="Your real deployment sources" />
                <div className="source-guide-grid">
                  <Guide title="Network devices" desc="Firewalls, routers, VPNs, IDS/IPS and proxies can send Syslog over UDP/TCP or events through REST." tag="UDP · TCP · REST" />
                  <Guide title="Linux / Unix hosts" desc="Mount or forward /var/log files into the container. ULPF reads text log lines and normalizes them." tag="/var/log" />
                  <Guide title="Windows hosts" desc="Export Windows Event Log to a file or Syslog/collector first, then forward it into ULPF." tag="EVTX → collector" />
                  <Guide title="Applications" desc="Post JSON, CEF, LEEF or custom events to the ingestion API." tag="POST /api/normalize" />
                </div>
              </section>
            </motion.div>
          )}

          {active === "Events" && (
            <motion.div key="events" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <section className="section-heading">
                <div><span>NORMALIZED EVENT STREAM</span><h2>Universal events <small>{visible.length}</small></h2></div>
                <div className="heading-actions">
                  <button className="soft-btn" onClick={refresh}><RefreshCw size={14} /> Refresh</button>
                  <button className="primary-btn" onClick={() => navTo("Live Ingest")}><Upload size={14} /> Ingest</button>
                </div>
              </section>
              {visible.length === 0 ? <Empty /> : (
                <div className="events-feed">
                  {visible.slice(0, 40).map((event, i) => (
                    <EventCard key={event.trace?.trace_id || i} event={event} onField={openLineage} />
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {active === "Forensics" && (
            <motion.div key="forensics" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <section className="section-heading">
                <div><span>FORENSIC WORKSPACE</span><h2>Trace the evidence</h2></div>
                <span className="forensic-badge"><Fingerprint size={13} /> RAW ↔ NORMALIZED</span>
              </section>
              {!forensicEvent && !latest ? (
                <Empty text="Normalize an event first, then open any field to inspect its trace." />
              ) : (
                <ForensicWorkspace
                  event={forensicEvent || latest}
                  onField={openLineage}
                  alertTrace={forensicTrace}
                />
              )}
            </motion.div>
          )}

          {active === "Correlations" && (
            <motion.div key="correlations" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <CorrelationView
                cases={correlationCases}
                events={events}
                loading={correlationLoading}
                onTrace={openCorrelationTrace}
              />
            </motion.div>
          )}

          {active === "Agents" && (
            <motion.div key="agents" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <section className="section-heading">
                <div><span>COLLECTOR MANAGEMENT</span><h2>ULPF agents <small>{agents.length}</small></h2></div>
                <div className="heading-actions">
                  <button className="soft-btn" onClick={refresh}><RefreshCw size={14} /> Refresh</button>
                  <button className="primary-btn" onClick={downloadAgentPlugin}><Download size={14} /> Download agent</button>
                </div>
              </section>
              <section className="card agent-setup-banner">
                <div className="agent-setup-copy">
                  <span className="eyebrow">WINDOWS / LINUX PLUGIN</span>
                  <h3>Install once, then configure the collector</h3>
                  <p>Download the offline ULPF Agent Plugin first. After download, the setup window guides gateway, authentication and approved log-source configuration.</p>
                </div>
                <button className="primary-btn" onClick={downloadAgentPlugin}><Download size={14} /> Download & setup</button>
              </section>
              <section className="card agent-management">
                <div className="agent-head">
                  <div>
                    <b>Local endpoint collectors</b>
                    <p>Agents collect host telemetry locally, persist a spool during outages, and forward only to this ULPF gateway.</p>
                  </div>
                  <span className="forensic-badge"><LockKeyhole size={13}/> AIR-GAP</span>
                </div>
                {agents.length === 0 ? (
                  <Empty text="No collectors registered yet. Install the ULPF agent on a host and point it at this gateway." />
                ) : (
                  <div className="agent-list">
                    {agents.map(a => (
                      <div className="agent-row" key={a.agent_id}>
                        <div className="agent-avatar"><Server size={16}/></div>
                        <div className="agent-main">
                          <b>{a.name || a.agent_id}</b>
                          <small>{a.hostname || "unknown host"} · {a.os || "unknown OS"}</small>
                        </div>
                        <span className={`agent-status ${a.status || ""}`}><i/>{a.status || "unknown"}</span>
                        <div className="agent-meta">
                          <span>v{a.agent_version || "?"}</span>
                          <span>queue {a.queue_size ?? 0}</span>
                          <span>{a.last_seen ? new Date(a.last_seen).toLocaleString() : "never"}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </motion.div>
          )}

          {active === "Plugins" && (
            <motion.div key="plugins" className="view" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
              <section className="section-heading">
                <div><span>EXTENSIBILITY</span><h2>ULPF plugin registry</h2></div>
                <span className="contract-badge"><PlugZap size={13} /> ULPF-Plugin-v1</span>
              </section>

              <div className="plugin-registry-summary">
                <div className="summary-tile">
                  <div className="summary-icon"><PlugZap size={18} /></div>
                  <div className="summary-text">
                    <span>Runtime plugins</span>
                    <b>{runtimePlugins.length}</b>
                  </div>
                </div>
                <div className="summary-tile">
                  <div className="summary-icon"><Terminal size={18} /></div>
                  <div className="summary-text">
                    <span>Parser integrations</span>
                    <b>{parserIntegrations.length}</b>
                  </div>
                </div>
                <div className="summary-tile">
                  <div className="summary-icon"><ShieldCheck size={18} /></div>
                  <div className="summary-text">
                    <span>Contract</span>
                    <b>v1</b>
                  </div>
                </div>
                <div className="summary-tile">
                  <div className="summary-icon"><CheckCircle2 size={18} /></div>
                  <div className="summary-text">
                    <span>Status</span>
                    <b>Healthy</b>
                  </div>
                </div>
              </div>

              {runtimePlugins.length > 0 && (
                <div className="plugin-section">
                  <div className="registry-group-heading">
                    <div>
                      <span>RUNTIME PACKAGES</span>
                      <h3>Installed plugin packages</h3>
                    </div>
                    <small>manifest-validated</small>
                  </div>
                  <div className="plugin-grid">
                    {runtimePlugins.map(p => <PluginCard key={`${p.id}-${p.version}`} plugin={p} runtime />)}
                  </div>
                </div>
              )}

              {parserIntegrations.length > 0 && (
                <div className="plugin-section">
                  <div className="registry-group-heading">
                    <div>
                      <span>PARSER INTEGRATIONS</span>
                      <h3>Built-in parser specifications</h3>
                    </div>
                    <small>configuration-backed</small>
                  </div>
                  <div className="plugin-grid">
                    {parserIntegrations.map(p => <PluginCard key={`${p.id}-${p.version}`} plugin={p} runtime={false} />)}
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {!chatOpen && <button className="agent-setup-fab" onClick={downloadAgentPlugin}><Download size={14} /> AGENT SETUP</button>}
        <Chatbot events={events} latest={latest} open={chatOpen} setOpen={setChatOpen} />
        <AgentSetupModal open={agentSetupOpen} downloaded={agentDownloaded} onClose={() => setAgentSetupOpen(false)} />

        <footer className="footer">
          <span>ULPF · Universal Log Pre-processing Framework</span>
          <span><LockKeyhole size={12} /> Core designed for offline / air-gapped deployment</span>
          <span>UES 1.0 · Plugin Contract v1</span>
        </footer>
      </main>

      <AnimatePresence>
        {drawer && <ForensicDrawer drawer={drawer} close={() => setDrawer(null)} />}
      </AnimatePresence>
      <AnimatePresence>
        {alertPopup && (
          <motion.div className="alert-popup" initial={{ opacity: 0, y: -18 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -18 }}>
            <AlertTriangle size={18} />
            <div>
              <b>Suspicious activity detected</b>
              <span>{alertPopup.title}</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ============ COMPONENTS ============

function AlertCard({ alert, expanded, onToggleExpand, onTrace, onAck }) {
  const sev = String(alert.severity || "high").toLowerCase();
  const isGroup = alert.group && alert.group_size > 1;
  const isCorr = alert.is_correlation;
  const riskScore = alert.risk_score ?? (sev === "critical" ? 90 : sev === "high" ? 75 : 50);
  const evidenceCount = (alert.evidence_trace_ids || alert.trace_ids || []).length || 1;

  const firstTime = alert.first_seen ? new Date(alert.first_seen).toLocaleTimeString() : "—";
  const lastTime = alert.last_seen ? new Date(alert.last_seen).toLocaleTimeString() : "—";
  const duration = alert.duration_seconds || 0;

  return (
    <div className={`alert-card severity-${sev} ${isGroup ? "grouped" : ""} ${isCorr ? "correlation" : ""}`}>
      <div className="alert-card-main">
        <div className="alert-icon-wrap">
          <AlertTriangle size={16} />
        </div>

        <div className="alert-content">
          <div className="alert-top">
            <div className="alert-title-row">
              <b className="alert-title">{alert.title}</b>
              {isGroup && <span className="group-badge">{alert.group_size} grouped</span>}
              {isCorr && <span className="corr-badge">correlated</span>}
              <span className={`sev-pill sev-${sev}`}>{sev}</span>
            </div>
            <button className="alert-toggle" onClick={onToggleExpand}>
              {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </button>
          </div>

          <div className="alert-reason-row">
            <span className="alert-reason">{alert.reason}</span>
          </div>

          <div className="alert-meta-row">
            <span><Server size={11} /> {alert.source_ip || "—"}</span>
            <span><Workflow size={11} /> {alert.rule}</span>
            <span><Clock3 size={11} /> {firstTime} → {lastTime}</span>
            {duration > 0 && <span>⏱ {duration}s</span>}
            {evidenceCount > 1 && <span><Layers3 size={11} /> {evidenceCount} events</span>}
          </div>

          {expanded && (
            <div className="alert-expanded">
              <div className="alert-stat">
                <span>Risk</span>
                <b>{riskScore}/100</b>
              </div>
              <div className="alert-stat">
                <span>Evidence</span>
                <b>{evidenceCount} event{evidenceCount === 1 ? "" : "s"}</b>
              </div>
              <div className="alert-stat">
                <span>Trigger</span>
                <b>{alert.rule}</b>
              </div>
              {alert.actions && alert.actions.length > 0 && (
                <div className="alert-stat">
                  <span>Actions</span>
                  <b>{alert.actions.join(", ")}</b>
                </div>
              )}
              {alert.parser && (
                <div className="alert-stat">
                  <span>Parser</span>
                  <b>{alert.parser}</b>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="alert-actions">
          <button className="trace-alert-btn" onClick={onTrace}>
            <Eye size={12} /> Trace
          </button>
          {!alert.acknowledged && (
            <button className="ack-alert-btn" onClick={onAck}>
              <CheckCircle2 size={12} /> Ack
            </button>
          )}
          {alert.acknowledged && (
            <span className="acked-pill"><CheckCircle2 size={11} /> Acked</span>
          )}
        </div>
      </div>
    </div>
  );
}
function AirGapProof({ airgap }) {
  const pass = airgap?.status === "PASS";

  return (
    <section className={`card airgap-proof ${pass ? "airgap-pass" : "airgap-warn"}`}>
      <div className="airgap-head">
        <div>
          <span className="eyebrow">SECURITY VERIFICATION</span>
          <h3>Air-Gapped Runtime</h3>
          <p>
            Runtime connectivity is continuously verified by the local ULPF security monitor.
          </p>
        </div>

        <div className={`airgap-status ${pass ? "pass" : "warn"}`}>
          <span className="airgap-dot" />
          {pass ? "VERIFIED · PASS" : "VERIFYING"}
        </div>
      </div>

      <div className="airgap-grid">

        <div className="airgap-stat">
          <LockKeyhole size={17} />
          <div>
            <span>External endpoints</span>
            <strong>{airgap?.external_endpoints ?? "—"}</strong>
          </div>
        </div>

        <div className="airgap-stat">
          <Globe2 size={17} />
          <div>
            <span>Cloud API calls</span>
            <strong>{airgap?.cloud_api_calls ?? "—"}</strong>
          </div>
        </div>

        <div className="airgap-stat">
          <Network size={17} />
          <div>
            <span>External requests</span>
            <strong>{airgap?.external_requests ?? "—"}</strong>
          </div>
        </div>

        <div className="airgap-stat">
          <Database size={17} />
          <div>
            <span>External DNS requests</span>
            <strong>{airgap?.external_dns_requests ?? "—"}</strong>
          </div>
        </div>

      </div>

      <div className="airgap-proof-row">
        <div>
          <span>NETWORK ACCESS REQUIRED</span>
          <b>{airgap?.network_access_required ? "YES" : "NO"}</b>
        </div>

        <div>
          <span>MODE</span>
          <b>{airgap?.mode || "air-gapped"}</b>
        </div>

        <div>
          <span>AUDIT</span>
          <b>{airgap?.audit?.performed_offline ? "PERFORMED OFFLINE" : "PENDING"}</b>
        </div>
      </div>

      <div className="airgap-architecture">
        <div className="airgap-node">
          <Server size={18} />
          <b>ULPF Runtime</b>
          <small>Local processing</small>
        </div>

        <div className="airgap-arrow">
          <ArrowRight size={18} />
          <span>PRIVATE NETWORK</span>
        </div>

        <div className="airgap-node">
          <ShieldCheck size={18} />
          <b>ULPF Gateway</b>
          <small>127.0.0.1:5173</small>
        </div>

        <div className="airgap-blocked">
          <Globe2 size={17} />
          <div>
            <b>Internet / Cloud</b>
            <small>NO EXTERNAL CONNECTION</small>
          </div>
        </div>
      </div>

      <div className="airgap-footer">
        <CheckCircle2 size={15} />
        <span>
          No cloud API · No external DNS · No SaaS telemetry · Offline-capable runtime
        </span>
      </div>
    </section>
  );
}

function Metric({ icon: Icon, label, value, meta }) {
  return (
    <motion.div className="metric-card" whileHover={{ y: -3 }}>
      <div className="metric-icon"><Icon size={16} /></div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{meta}</small>
      </div>
    </motion.div>
  );
}

function CardHeading({ icon: Icon, kicker, title }) {
  return (
    <div className="card-heading">
      <div className="heading-icon"><Icon size={16} /></div>
      <div>
        <span>{kicker}</span>
        <h3>{title}</h3>
      </div>
    </div>
  );
}

function SourceRow({ name, format, status }) {
  return (
    <div className="source-row">
      <div className="source-avatar"><Radio size={13} /></div>
      <div><b>{name}</b><small>{format}</small></div>
      <span className={status === "receiving" ? "receiving" : ""}><i />{status}</span>
    </div>
  );
}

function USP({ icon: Icon, title, text }) {
  return (
    <div className="usp-card">
      <div className="usp-icon"><Icon size={16} /></div>
      <div><b>{title}</b><span>{text}</span></div>
    </div>
  );
}

function Guide({ title, desc, tag }) {
  return (
    <div className="guide">
      <div className="guide-top"><b>{title}</b><span>{tag}</span></div>
      <p>{desc}</p>
    </div>
  );
}

function EventCard({ event, onField }) {
  const normalized = event.ues || event.normalized || event.fields || {};
  const flatten = (obj, prefix = "") => Object.entries(obj || {}).reduce((acc, [k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) return acc.concat(flatten(v, key));
    return acc.concat([[key, v]]);
  }, []);
  const fields = flatten(normalized).filter(([k]) =>
    !["schema_version", "event_id", "ingest_time", "event_time_epoch_ms"].includes(k)
  ).slice(0, 18);
  const trace = event.trace || {};
  const vendor = event.ues?.device?.vendor || "Unknown source";

  return (
    <motion.article className="event-card" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
      <div className="event-card-head">
        <div className="event-ident">
          <span className="pass-badge"><CheckCircle2 size={12} /> NORMALIZED</span>
          <b>{vendor}</b>
          <span className="event-id">{String(trace.trace_id || "").slice(0, 18)}</span>
        </div>
        <div className="event-card-meta">
          <span><Fingerprint size={12} /> {String(trace.raw_hash || "").slice(0, 12) || "hash"}</span>
          <span>{event.meta?.format || "unknown"}</span>
          <span>parser {event.meta?.parser || "v1"}</span>
        </div>
      </div>
      <div className="event-body">
        <div className="event-source-line">
          <span><Clock3 size={12} /> {event.ues?.event_time || event.meta?.received_time || "event time unavailable"}</span>
          <span><Server size={12} /> {event.meta?.source_type || "web"}</span>
        </div>
        <div className="field-grid">
          {fields.map(([key, value]) => (
            <button className="field-chip" key={key} onClick={() => onField(event, key)} title="Open forensic lineage">
              <span>{key}</span>
              <b>{typeof value === "object" ? JSON.stringify(value) : String(value)}</b>
              <ChevronRight size={13} />
            </button>
          ))}
        </div>
      </div>
    </motion.article>
  );
}

// ============ CORRELATION VIEW (MATCHES SCREENSHOT) ============
function CorrelationView({ cases, events, loading, onTrace }) {
  const eventByTrace = useMemo(() => {
    const map = new Map();
    events.forEach(item => {
      const id = item?.trace?.trace_id;
      if (id) map.set(String(id), item);
    });
    return map;
  }, [events]);

  const fallback = useMemo(() => {
    const groups = new Map();
    events.forEach(e => {
      const ip = getField(e, ["source.ip", "src_ip", "srcip"]);
      if (ip) {
        const key = String(ip);
        const row = groups.get(key) || { count: 0, traces: [] };
        row.count += 1;
        if (e?.trace?.trace_id) row.traces.push(String(e.trace.trace_id));
        groups.set(key, row);
      }
    });
    return [...groups.entries()].filter(([, row]) => row.count > 1).slice(0, 6).map(([ip, row]) => ({
      correlation_id: `local-${ip}`,
      title: "Shared source activity",
      rule_id: "field-correlation",
      source_ip: ip,
      attempts: row.count,
      trace_ids: row.traces,
      risk_score: Math.min(40 + row.count * 6, 92),
      severity: row.count >= 6 ? "high" : "medium",
      description: `${row.count} events share source IP ${ip}.`,
    }));
  }, [events]);

  const items = cases.length ? cases : fallback;

  if (loading && !items.length) {
    return (
      <div className="card correlation-main-card">
        <div className="correlation-empty">
          <RefreshCw size={20} className="spin-icon" />
          <span>Loading correlation cases from backend…</span>
        </div>
      </div>
    );
  }

  if (!items.length) {
    return (
      <div className="card correlation-main-card">
        <div className="correlation-empty">
          <Workflow size={22} />
          <b>No correlated activity detected yet</b>
          <span>Correlations appear when the engine observes multi-event patterns like brute-force, privilege escalation, or repeated failures from the same source.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="correlation-page">
      <div className="correlation-page-head">
        <div>
          <span className="correlation-page-eyebrow">CORRELATION ENGINE</span>
          <h2>Backend-linked attack activity</h2>
        </div>
        <span className="correlation-page-count">
          <Workflow size={14} />
          {items.length} CASE{items.length === 1 ? "" : "S"}
        </span>
      </div>

      <div className="correlation-cases">
        {items.map((c, i) => {
          const score = Number(c.risk_score ?? 0);
          const sev = String(c.severity || (score >= 80 ? "high" : score >= 60 ? "medium" : "low")).toLowerCase();
          const traceIds = correlationTraceIds(c);
          const evidence = Array.isArray(c.evidence) ? c.evidence : [];

          // Build event nodes for the chain
          const nodes = traceIds.slice(0, 8).map((id, idx) => {
            const ev = eventByTrace.get(String(id)) ||
              evidence.find(e => String(e.trace_id || e.trace?.trace_id) === String(id));
            const action = ev?.ues?.action || ev?.action || ev?.ues?.outcome || ev?.outcome || "event";
            const time = ev?.ues?.event_time || ev?.meta?.received_time || ev?.event_time || "";
            return {
              id: String(id),
              action: String(action),
              time: time ? String(time).slice(0, 24) : String(id).slice(0, 24),
            };
          });

          return (
            <article className={`correlation-case sev-${sev}`} key={c.correlation_id || c.alert_id || i}>
              {/* Case header */}
              <div className="case-head">
                <div className="case-head-left">
                  <span className="case-rule">{c.rule_id || c.rule || "correlation-rule"}</span>
                  <h3>{c.title || c.name || "Correlation case"}</h3>
                  <p>{c.description || c.explanation?.why || "Linked evidence returned by the correlation engine."}</p>
                </div>
                <div className={`case-risk sev-${sev}`}>
                  <b>{score || "—"}</b>
                  <span>{sev} risk</span>
                </div>
              </div>

              {/* Event chain row */}
              {nodes.length > 0 && (
                <div className="case-chain">
                  <div className="case-chain-track">
                    {nodes.map((node, idx) => (
                      <React.Fragment key={`${node.id}-${idx}`}>
                        <div className="case-event-card">
                          <div className="case-event-head">
                            <span className="case-event-num">EVENT {idx + 1}</span>
                          </div>
                          <b className="case-event-action">{node.action}</b>
                          <span className="case-event-meta">source unavailable · user unavailable</span>
                          <span className="case-event-time">{node.time}</span>
                          <code className="case-event-id">{node.id.slice(0, 20)}…</code>
                        </div>
                        {idx < nodes.length - 1 && (
                          <div className="case-chain-arrow">
                            <ArrowRight size={18} />
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              )}

              {/* Footer */}
              <div className="case-foot">
                <div className="case-foot-left">
                  <GitBranch size={14} />
                  <span>{traceIds.length} linked evidence event{traceIds.length === 1 ? "" : "s"}</span>
                </div>
                <button className="case-trace-btn" onClick={() => onTrace(c)}>
                  <Eye size={14} /> Trace evidence
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}

function ForensicWorkspace({ event, onField, alertTrace = null }) {
  const [lineage, setLineage] = useState([]);
  const [loading, setLoading] = useState(false);
  const trace = event?.trace || {};
  const normalized = event?.ues || event?.normalized || {};

  const flat = Object.entries(normalized).flatMap(([group, value]) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return [[group, value]];
    }
    return Object.entries(value).map(([k, v]) => [`${group}.${k}`, v]);
  }).filter(([k]) =>
    !["schema_version", "event_id", "ingest_time", "event_time_epoch_ms"].includes(k)
  ).slice(0, 24);

  useEffect(() => {
    let cancelled = false;
    async function loadLineage() {
      const id = trace.trace_id;
      if (!id) return;
      setLoading(true);
      try {
        const d = await api(`/api/events/${encodeURIComponent(id)}/lineage`);
        if (!cancelled) setLineage(d.lineage || []);
      } catch {
        if (!cancelled) setLineage([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    loadLineage();
    return () => { cancelled = true; };
  }, [trace.trace_id]);

  return (
    <div className="forensic-grid">
      {alertTrace && (
        <div className="card alert-trace-card">
          <div className="trace-map-head">
            <div>
              <span className="eyebrow">BACKEND SECURITY TRACE</span>
              <h3>{alertTrace.alert?.title || "Alert evidence chain"}</h3>
            </div>
            <span className="forensic-badge">
              {alertTrace.count || 0} linked event{alertTrace.count === 1 ? "" : "s"}
            </span>
          </div>
          <p className="alert-trace-desc">
            {alertTrace.alert?.reason || alertTrace.alert?.description || "Evidence returned by the backend trace service."}
          </p>
          <div className="inspector-list">
            {(alertTrace.events || []).map((item, index) => (
              <div className="trace-evidence-row" key={item.trace?.trace_id || index}>
                <span>{index + 1}. {item.trace?.trace_id || "trace unavailable"}</span>
                <b>{item.ues?.outcome || item.ues?.action || "security event"} · {item.ues?.event_time || item.meta?.received_time || "time unavailable"}</b>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card trace-map-card">
        <div className="trace-map-head">
          <div>
            <span className="eyebrow">EVIDENCE GRAPH</span>
            <h3>Raw → parse → map → normalized</h3>
          </div>
          <span className="hash-pill">
            <Fingerprint size={12} />
            {String(trace.raw_hash || "hash unavailable").slice(0, 18)}
            {trace.raw_hash ? "…" : ""}
          </span>
        </div>

        <TraceGraph event={event} lineage={lineage} loading={loading} />

        <div className="graph-caption">
          <span><i className="legend raw" /> Raw evidence</span>
          <span><i className="legend transform" /> Transformation</span>
          <span><i className="legend normalized" /> Universal field</span>
        </div>
      </div>

      <div className="card evidence-card">
        <div className="trace-map-head">
          <div>
            <span className="eyebrow">EVENT PAIR</span>
            <h3>Original vs normalized</h3>
          </div>
          <span className="pass-badge">
            <CheckCircle2 size={12} /> LOSSLESS
          </span>
        </div>

        <div className="evidence-columns">
          <div className="evidence-pane raw-pane">
            <div className="pane-title">
              <span>RAW EVENT</span>
              <small>exact input</small>
            </div>
            <pre>{event.raw || "Raw event unavailable"}</pre>
          </div>
          <div className="evidence-pane normalized-pane">
            <div className="pane-title">
              <span>UNIVERSAL EVENT</span>
              <small>UES 1.0</small>
            </div>
            <pre>{JSON.stringify(normalized, null, 2)}</pre>
          </div>
        </div>

        <div className="field-inspector">
          <div className="pane-title">
            <span>CLICK A FIELD TO TRACE IT</span>
            <small>{flat.length} fields</small>
          </div>
          <div className="inspector-list">
            {flat.map(([key, value]) => (
              <button key={key} onClick={() => onField(event, key)}>
                <span>{key}</span>
                <b>{typeof value === "object" ? JSON.stringify(value) : String(value)}</b>
                <ChevronRight size={13} />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function TraceGraph({ event, lineage, loading }) {
  const trace = event?.trace || {};
  const meta = event?.meta || {};
  const parser = meta.parser || lineage.find(x => x.parser)?.parser || "parser unavailable";
  const mappings = lineage.length
    ? `${lineage.length} field${lineage.length === 1 ? "" : "s"} mapped`
    : "lineage not returned";
  const validation = event?.validation?.status || event?.validation?.result || (event?.ues ? "PASS" : "pending");
  const confidenceValues = lineage.map(x => Number(x.confidence)).filter(Number.isFinite);
  const confidence = confidenceValues.length
    ? `${Math.round(confidenceValues.reduce((a, b) => a + b, 0) / confidenceValues.length * 100)}%`
    : (event?.confidence != null ? `${Math.round(Number(event.confidence) * 100)}%` : "—");

  return (
    <div className="trace-graph">
      <div className="trace-column">
        <TraceNode icon={FileSearch} label="RAW EVENT" sub={trace.raw_hash ? `SHA-256 ${String(trace.raw_hash).slice(0, 12)}…` : `${String(event?.raw || "").length} chars preserved`} tone="raw" />
        <div className="graph-arrow"><ArrowDown size={14} /></div>
        <TraceNode icon={Terminal} label="PARSER" sub={parser} tone="transform" />
        <div className="graph-arrow"><ArrowDown size={14} /></div>
        <TraceNode icon={GitBranch} label="MAPPING" sub={mappings} tone="transform" />
        <div className="graph-arrow"><ArrowDown size={14} /></div>
        <TraceNode icon={CheckCircle2} label="VALIDATION" sub={`${validation}${loading ? " • loading" : ""}`} tone="transform" />
        <div className="graph-arrow"><ArrowDown size={14} /></div>
        <TraceNode icon={Database} label="UNIVERSAL EVENT" sub={`${Object.keys(event?.ues || {}).length} top-level fields • UES`} tone="normalized" />
      </div>
      <div className="graph-side">
        <div className="side-stat"><Fingerprint size={14} /><span>Integrity</span><b>{trace.raw_hash ? "SHA-256" : "Unavailable"}</b></div>
        <div className="side-stat"><Sparkles size={14} /><span>Confidence</span><b>{confidence}</b></div>
        <div className="side-stat"><Eye size={14} /><span>Lineage</span><b>{lineage.length ? "Field-level" : "On field trace"}</b></div>
      </div>
    </div>
  );
}

function TraceNode({ icon: Icon, label, sub, tone }) {
  return (
    <div className={`trace-node ${tone}`}>
      <div className="trace-node-icon"><Icon size={15} /></div>
      <div><b>{label}</b><span>{sub}</span></div>
      <ChevronRight size={13} />
    </div>
  );
}

function PluginCard({ plugin, runtime = true }) {
  const vendor = plugin.vendor || "Vendor agnostic";
  const product = plugin.product || "";
  const format = plugin.format || "custom";
  const priority = plugin.priority ?? "—";

  return (
    <div className={`plugin-card-new ${runtime ? "runtime" : "parser"}`}>
      <div className="plugin-card-header">
        <div className="plugin-card-icon">
          <PlugZap size={20} />
        </div>
        <div className="plugin-card-badges">
          <span className={`plugin-status-badge ${runtime ? "runtime" : "parser"}`}>
            {runtime ? "CERTIFIED" : "PARSER"}
          </span>
          <span className="plugin-version-badge">v{plugin.version || "1.0"}</span>
        </div>
      </div>
      <h3 className="plugin-card-name">{plugin.name || plugin.id}</h3>
      <p className="plugin-card-vendor">
        {vendor}
        {product ? ` · ${product}` : ""}
      </p>
      <div className="plugin-card-meta-grid">
        <div className="plugin-meta-item">
          <span>Format</span>
          <b>{format}</b>
        </div>
        <div className="plugin-meta-item">
          <span>Priority</span>
          <b>{priority}</b>
        </div>
        <div className="plugin-meta-item">
          <span>Contract</span>
          <b>v1</b>
        </div>
      </div>
      <div className="plugin-card-footer">
        <div className="plugin-health">
          <span className="health-dot" />
          <span>Active</span>
        </div>
        <span className="plugin-contract-label">ULPF-Plugin-v1</span>
      </div>
    </div>
  );
}

function Empty({ text = "No normalized events yet. Start a live stream or ingest a sample." }) {
  return (
    <div className="empty-state">
      <Database size={28} />
      <b>{text}</b>
      <span>ULPF keeps the raw evidence while building the universal event.</span>
    </div>
  );
}

function ForensicDrawer({ drawer, close }) {
  const { data, item, field, event } = drawer;
  const confidence = Math.round((item?.confidence ?? 1) * 100);
  const rawHash = data?.raw_hash || event?.trace?.raw_hash || "";
  return (
    <motion.div className="drawer-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close}>
      <motion.aside className="forensic-drawer" initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }} onClick={e => e.stopPropagation()}>
        <div className="drawer-header">
          <div>
            <span className="eyebrow">FIELD FORENSICS</span>
            <h2>{field}</h2>
            <small>{String(event?.trace?.trace_id || "").slice(0, 28)}</small>
          </div>
          <button className="icon-close" onClick={close}><X size={18} /></button>
        </div>
        <div className="drawer-content">
          <div className="confidence-card">
            <div><span>Mapping confidence</span><strong>{confidence}%</strong></div>
            <div className="confidence-track"><i style={{ width: `${confidence}%` }} /></div>
          </div>
          <div className="mini-trace">
            <MiniTrace label="RAW" value={String(item?.original_field || "raw event")} icon={FileSearch} />
            <ArrowRight size={13} />
            <MiniTrace label="MAP" value={String(item?.mapping_rule || "deterministic mapping")} icon={GitBranch} />
            <ArrowRight size={13} />
            <MiniTrace label="UES" value={field} icon={Database} />
          </div>
          <DrawerRow icon={Database} label="Normalized field" value={item?.normalized_field || field} />
          <DrawerRow icon={Zap} label="Normalized value" value={item?.normalized_value ?? "—"} />
          <DrawerRow icon={FileSearch} label="Original field" value={item?.original_field || "—"} />
          <DrawerRow icon={Terminal} label="Original value" value={item?.original_value ?? "—"} />
          <DrawerRow icon={GitBranch} label="Mapping rule" value={item?.mapping_rule || "deterministic mapping"} />
          <DrawerRow icon={Workflow} label="Extraction method" value={item?.extraction_method || "parser-field mapping"} />
          <DrawerRow icon={PlugZap} label="Parser" value={item?.parser || event?.meta?.parser || "—"} />
          <DrawerRow icon={Fingerprint} label="SHA-256" value={rawHash || "—"} copy />
          <div className="raw-evidence-drawer">
            <div><span>EXACT RAW EVIDENCE</span><small>never modified</small></div>
            <pre>{data?.raw || event?.raw || "Raw event unavailable"}</pre>
          </div>
        </div>
      </motion.aside>
    </motion.div>
  );
}

function DrawerRow({ icon: Icon, label, value, copy }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="drawer-row">
      <div><Icon size={14} /><span>{label}</span></div>
      <code>{String(value)}</code>
      {copy && (
        <button onClick={() => {
          navigator.clipboard?.writeText(String(value));
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}>
          <Copy size={12} /> {copied ? "Copied" : "Copy"}
        </button>
      )}
    </div>
  );
}

function MiniTrace({ icon: Icon, label, value }) {
  return (
    <div className="mini-trace-node">
      <Icon size={12} />
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function AgentSetupModal({ open, downloaded, onClose }) {
  const [step, setStep] = useState(1);
  const [name, setName] = useState("Windows-Agent");
  const [gateway, setGateway] = useState("http://127.0.0.1:5173");
  const [token, setToken] = useState("Tnikita1800");
  const [sources, setSources] = useState({ windows: true, security: true, application: true, system: true });
  if (!open) return null;
  const next = () => setStep(v => Math.min(4, v + 1));
  const back = () => setStep(v => Math.max(1, v - 1));
  return (
    <div className="setup-backdrop" onClick={onClose}>
      <motion.div className="setup-modal" initial={{ opacity: 0, scale: .96, y: 12 }} animate={{ opacity: 1, scale: 1, y: 0 }} onClick={e => e.stopPropagation()}>
        <div className="setup-header">
          <div>
            <span className="eyebrow">ULPF AGENT INSTALLATION</span>
            <h2>Windows Agent Setup</h2>
            <p>Offline endpoint collector configuration</p>
          </div>
          <button className="icon-close" onClick={onClose}><X size={18}/></button>
        </div>
        <div className="setup-progress">
          {[1,2,3,4].map(n => <span key={n} className={step >= n ? "active" : ""}>{n}</span>)}
        </div>
        <div className="setup-body">
          {step === 1 && (
            <div className="setup-step">
              <div className="setup-icon"><Download size={24}/></div>
              <h3>{downloaded ? "Plugin downloaded" : "Download the offline plugin"}</h3>
              <p>Step 1 always comes first. The browser downloads <b>ULPF-Agent-Plugin.zip</b> from this air-gapped ULPF gateway.</p>
              <div className="setup-check">
                {downloaded ? <CheckCircle2 size={16}/> : <CircleDot size={16}/>}
                {downloaded ? "Download request completed" : "Waiting for download"}
              </div>
            </div>
          )}
          {step === 2 && (
            <div className="setup-step">
              <div className="setup-icon"><Terminal size={24}/></div>
              <h3>Run the Windows installer</h3>
              <p>Extract the ZIP and run <code>Install-ULPF-Agent.cmd</code>. Windows opens the installer window and creates the <code>ULPFAgent</code> service.</p>
              <div className="setup-check"><CheckCircle2 size={16}/> Install to Program Files + ProgramData</div>
            </div>
          )}
          {step === 3 && (
            <div className="setup-step setup-form">
              <div className="setup-icon"><Server size={24}/></div>
              <h3>Configure collector</h3>
              <label>Agent name<input value={name} onChange={e => setName(e.target.value)}/></label>
              <label>ULPF gateway<input value={gateway} onChange={e => setGateway(e.target.value)}/></label>
              <label>Agent token<input value={token} onChange={e => setToken(e.target.value)} type="password"/></label>
              <div className="source-checks">
                {Object.entries(sources).map(([key, value]) => (
                  <label key={key}>
                    <input type="checkbox" checked={value} onChange={e => setSources(s => ({...s, [key]: e.target.checked}))}/>
                    {key === "windows" ? "Windows Event Logs" : key[0].toUpperCase()+key.slice(1)+" logs"}
                  </label>
                ))}
              </div>
            </div>
          )}
          {step === 4 && (
            <div className="setup-step">
              <div className="setup-icon"><ShieldCheck size={24}/></div>
              <h3>Ready to register</h3>
              <p>The installer/service will use the configuration below and communicate only with the configured internal ULPF gateway.</p>
              <div className="setup-summary">
                <span><b>Agent</b>{name}</span>
                <span><b>Gateway</b>{gateway}</span>
                <span><b>Sources</b>{Object.values(sources).filter(Boolean).length} selected</span>
                <span><b>Mode</b>AIR-GAPPED</span>
              </div>
              <div className="setup-check"><CheckCircle2 size={16}/> No cloud API or internet connection required</div>
            </div>
          )}
        </div>
        <div className="setup-footer">
          {step > 1 ? <button className="soft-btn" onClick={back}>Back</button> : <span/>}
          <div>
            <span>Step {step} of 4</span>
            {step < 4 ? (
              <button className="primary-btn" onClick={next}>{step === 1 ? "Continue" : "Next"}<ChevronRight size={14}/></button>
            ) : (
              <button className="primary-btn" onClick={onClose}><CheckCircle2 size={14}/> Finish setup</button>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  );
}

function Chatbot({ events, latest, open, setOpen }) {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([
    { role: "bot", text: "ULPF Log Assistant ready. Ask me anything about the currently loaded logs — including field details and correlations." }
  ]);

  function send(text = input) {
    const q = text.trim();
    if (!q) return;
    const answer = analyzeLogQuestion(q, events, latest);
    setMessages(prev => [...prev, { role: "user", text: q }, { role: "bot", text: answer }]);
    setInput("");
  }

  return (
    <div className={`chatbot ${open ? "open" : ""}`}>
      {!open && (
        <button className="chat-fab" onClick={() => setOpen(true)} title="Open log assistant">
          <MessageCircle size={21} /><span>LOG AI</span>
        </button>
      )}
      {open && (
        <motion.div className="chat-panel" initial={{ opacity: 0, y: 12, scale: .98 }} animate={{ opacity: 1, y: 0, scale: 1 }}>
          <div className="chat-head">
            <div>
              <span><Cpu size={14} /> ULPF LOG ASSISTANT</span>
              <b>Evidence-grounded analysis</b>
            </div>
            <button onClick={() => setOpen(false)}><X size={16} /></button>
          </div>
          <div className="chat-messages">
            {messages.map((m, i) => (
              <div key={i} className={`chat-message ${m.role}`}>
                <span>{m.role === "bot" ? "AI" : "YOU"}</span>
                <p>{m.text}</p>
              </div>
            ))}
          </div>
          <div className="chat-suggestions">
            {["Analyze current log", "Correlate loaded events", "Show suspicious indicators"].map(s => (
              <button key={s} onClick={() => send(s)}>{s}</button>
            ))}
          </div>
          <div className="chat-input">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && send()}
              placeholder="Ask about any log…"
            />
            <button onClick={() => send()}><ArrowRight size={15} /></button>
          </div>
          <small className="chat-note">Answers are computed from loaded ULPF event data; heuristic matches are not definitive threat verdicts.</small>
        </motion.div>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
