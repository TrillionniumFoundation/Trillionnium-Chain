export type Health = "healthy" | "degraded" | "risk";

export type Kpi = {
  label: string;
  value: string;
  delta: string;
  health: Health;
};

export type TaskItem = {
  id: string;
  title: string;
  owner: string;
  priority: "P0" | "P1" | "P2";
  status: "Todo" | "In Progress" | "Blocked" | "Done";
  updatedAt: string;
};

export type EventItem = {
  id: string;
  time: string;
  category: "Deploy" | "Incident" | "Governance" | "Security";
  summary: string;
  severity: "Info" | "Warning" | "Critical";
};

export type AuditItem = {
  id: string;
  control: string;
  result: "Pass" | "Warn" | "Fail";
  reviewer: string;
  reviewedAt: string;
};

export const kpis: Kpi[] = [
  { label: "Network Uptime", value: "99.982%", delta: "+0.02%", health: "healthy" },
  { label: "Pending Tasks", value: "17", delta: "-5", health: "healthy" },
  { label: "Open Incidents", value: "2", delta: "+1", health: "degraded" },
  { label: "Audit Coverage", value: "94.6%", delta: "+1.8%", health: "healthy" },
];

export const tasks: TaskItem[] = [
  { id: "TSK-341", title: "RPC quota read model cache", owner: "Core RPC", priority: "P1", status: "In Progress", updatedAt: "2026-03-03 10:18" },
  { id: "TSK-339", title: "Validator heartbeat drift panel", owner: "Ops", priority: "P1", status: "Todo", updatedAt: "2026-03-03 09:40" },
  { id: "TSK-336", title: "MEV dashboard null-safe rendering", owner: "Frontend", priority: "P2", status: "Done", updatedAt: "2026-03-03 08:30" },
  { id: "TSK-333", title: "Bridge watcher threshold tuning", owner: "Bridge", priority: "P0", status: "Blocked", updatedAt: "2026-03-03 07:56" },
];

export const events: EventItem[] = [
  { id: "EVT-928", time: "2026-03-03 10:30", category: "Deploy", summary: "Read-model indexer v0.9.4 deployed to canary", severity: "Info" },
  { id: "EVT-925", time: "2026-03-03 09:54", category: "Incident", summary: "Temporary RPC latency spike in ap-east-1", severity: "Warning" },
  { id: "EVT-919", time: "2026-03-03 07:42", category: "Governance", summary: "Parameter proposal #18 entered review window", severity: "Info" },
  { id: "EVT-917", time: "2026-03-03 06:18", category: "Security", summary: "Signer access audit found stale key rotation", severity: "Critical" },
];

export const audits: AuditItem[] = [
  { id: "AUD-114", control: "Readonly endpoint stability guardrails", result: "Pass", reviewer: "SRE", reviewedAt: "2026-03-03 10:02" },
  { id: "AUD-110", control: "Event retention > 90 days", result: "Pass", reviewer: "Data", reviewedAt: "2026-03-03 08:14" },
  { id: "AUD-108", control: "Ops escalation policy linked", result: "Warn", reviewer: "Governance", reviewedAt: "2026-03-02 22:45" },
  { id: "AUD-105", control: "Privileged write path disabled in dashboard", result: "Pass", reviewer: "Security", reviewedAt: "2026-03-02 21:19" },
];
