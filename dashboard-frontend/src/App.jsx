import React, { useState, useMemo } from "react";

const SEV_CONFIG = {
  critical: { bg: "#dc2626", label: "CRITICAL" },
  high:     { bg: "#ea580c", label: "HIGH" },
  medium:   { bg: "#eab308", label: "MEDIUM" },
  low:      { bg: "#3b82f6", label: "LOW" },
};

const STATUS_STYLE = {
  new:         { bg: "#fef3c7", color: "#92400e" },
  triaging:    { bg: "#dbeafe", color: "#1e40af" },
  dispatched:  { bg: "#d1fae5", color: "#065f46" },
  resolved:    { bg: "#e5e7eb", color: "#374151" },
};

const SAMPLE_INCIDENTS = [
  { id: "INC-001", title: "Database connection pool exhausted", severity: "critical", status: "new", service: "auth-svc", count: 12, lastSeen: "2024-01-15T09:32:00Z", slackNotified: false, pdTriggered: true },
  { id: "INC-002", title: "High error rate on payment gateway", severity: "high", status: "triaging", service: "payment-svc", count: 8, lastSeen: "2024-01-15T09:28:00Z", slackNotified: true, pdTriggered: true },
  { id: "INC-003", title: "Elevated latency on user profile API", severity: "medium", status: "dispatched", service: "profile-svc", count: 5, lastSeen: "2024-01-15T09:20:00Z", slackNotified: true, pdTriggered: false },
  { id: "INC-004", title: "Disk usage above 80% on cache nodes", severity: "low", status: "new", service: "cache-svc", count: 3, lastSeen: "2024-01-15T08:55:00Z", slackNotified: false, pdTriggered: false },
  { id: "INC-005", title: "SSL certificate expiring in 7 days", severity: "high", status: "dispatched", service: "ingress", count: 1, lastSeen: "2024-01-15T07:00:00Z", slackNotified: true, pdTriggered: true },
  { id: "INC-006", title: "Memory leak in batch processor", severity: "medium", status: "resolved", service: "batch-svc", count: 15, lastSeen: "2024-01-14T22:10:00Z", slackNotified: true, pdTriggered: true },
];

function Badge({ children, style }) {
  return <span style={{ ...style, padding: "2px 8px", borderRadius: "4px", fontSize: "12px", fontWeight: 600, display: "inline-block" }}>{children}</span>;
}

function DetailPanel({ incident, onClose }) {
  if (!incident) return null;
  const sev = SEV_CONFIG[incident.severity];
  return (
    <div style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: "420px", background: "#fff", borderLeft: "1px solid #d1d5db", padding: "24px", overflowY: "auto", zIndex: 50, boxShadow: "-2px 0 8px rgba(0,0,0,0.1)" }}>
      <button onClick={onClose} style={{ float: "right", border: "none", background: "none", fontSize: "20px", cursor: "pointer" }}>✕</button>
      <h2 style={{ marginTop: 0 }}>{incident.id}</h2>
      <p style={{ fontWeight: 600 }}>{incident.title}</p>
      <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "8px", fontSize: "14px" }}>
        <span style={{ color: "#6b7280" }}>Severity</span><Badge style={{ background: sev.bg, color: "#fff" }}>{sev.label}</Badge>
        <span style={{ color: "#6b7280" }}>Status</span><Badge style={STATUS_STYLE[incident.status]}>{incident.status}</Badge>
        <span style={{ color: "#6b7280" }}>Service</span><span>{incident.service}</span>
        <span style={{ color: "#6b7280" }}>Alert Count</span><span>{incident.count}</span>
        <span style={{ color: "#6b7280" }}>Last Seen</span><span>{new Date(incident.lastSeen).toLocaleString()}</span>
        <span style={{ color: "#6b7280" }}>Slack</span><span>{incident.slackNotified ? "✅ Sent" : "—"} </span>
        <span style={{ color: "#6b7280" }}>PagerDuty</span><span>{incident.pdTriggered ? "✅ Triggered" : "—"}</span>
      </div>
    </div>
  );
}

export default function App() {
  const [incidents] = useState(SAMPLE_INCIDENTS);
  const [sevFilter, setSevFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => {
    if (sevFilter === "all") return incidents;
    return incidents.filter((i) => i.severity === sevFilter);
  }, [incidents, sevFilter]);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", margin: 0, padding: "24px", background: "#f9fafb", minHeight: "100vh" }}>
      <h1 style={{ margin: "0 0 20px" }}>Incident Triage Dashboard</h1>
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        {["all", "critical", "high", "medium", "low"].map((s) => (
          <button key={s} onClick={() => setSevFilter(s)} style={{
            padding: "6px 16px", border: "1px solid #d1d5db", borderRadius: "6px", cursor: "pointer",
            background: sevFilter === s ? (s === "all" ? "#111827" : SEV_CONFIG[s]?.bg) : "#fff",
            color: sevFilter === s ? "#fff" : "#111827", fontWeight: 600, fontSize: "13px",
          }}>{s === "all" ? "All" : SEV_CONFIG[s].label}</button>
        ))}
        <span style={{ alignSelf: "center", marginLeft: "auto", color: "#6b7280", fontSize: "14px" }}>{filtered.length} incident{filtered.length !== 1 && "s"}</span>
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse", background: "#fff", borderRadius: "8px", overflow: "hidden", boxShadow: "0 1px 3px rgba(0,0,0,0.1)" }}>
        <thead>
          <tr style={{ background: "#f3f4f6", textAlign: "left", fontSize: "13px" }}>
            <th style={{ padding: "10px 12px" }}>ID</th><th style={{ padding: "10px 12px" }}>Title</th>
            <th style={{ padding: "10px 12px" }}>Severity</th><th style={{ padding: "10px 12px" }}>Status</th>
            <th style={{ padding: "10px 12px" }}>Service</th><th style={{ padding: "10px 12px" }}>Count</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((inc) => {
            const sev = SEV_CONFIG[inc.severity];
            return (
              <tr key={inc.id} onClick={() => setSelected(inc)} style={{ cursor: "pointer", borderBottom: "1px solid #e5e7eb" }}>
                <td style={{ padding: "10px 12px", fontWeight: 600, fontSize: "13px" }}>{inc.id}</td>
                <td style={{ padding: "10px 12px", fontSize: "14px" }}>{inc.title}</td>
                <td style={{ padding: "10px 12px" }}><Badge style={{ background: sev.bg, color: "#fff" }}>{sev.label}</Badge></td>
                <td style={{ padding: "10px 12px" }}><Badge style={STATUS_STYLE[inc.status]}>{inc.status}</Badge></td>
                <td style={{ padding: "10px 12px", fontSize: "13px", color: "#6b7280" }}>{inc.service}</td>
                <td style={{ padding: "10px 12px", textAlign: "center" }}>{inc.count}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {selected && <DetailPanel incident={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}