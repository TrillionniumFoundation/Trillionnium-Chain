import { adaptDashboardSnapshot, type DashboardSnapshot } from "./adapter";

const rawSnapshot: unknown = {
  kpis: [
    { label: "Network Uptime", value: "99.982%", delta: "+0.02%", health: "healthy" },
    { label: "Pending Tasks", value: "17", delta: "-5", health: "healthy" },
    { label: "Open Incidents", value: "2", delta: "+1", health: "degraded" },
    { label: "Audit Coverage", value: "94.6%", delta: "+1.8%", health: "healthy" },
  ],
  tasks: [
    {
      id: "TSK-341",
      title: "RPC quota read model cache",
      owner: "Core RPC",
      priority: "P1",
      status: "In Progress",
      updatedAt: "2026-03-03 10:18",
      description: "Backfill cache miss metrics for query-task endpoints and add fallback TTL policy.",
    },
    {
      id: "TSK-339",
      title: "Validator heartbeat drift panel",
      owner: "Ops",
      priority: "P1",
      status: "Todo",
      updatedAt: "2026-03-03 09:40",
      description: "Expose drift percentile and stale heartbeat thresholds in the overview.",
    },
    {
      id: "TSK-336",
      title: "MEV dashboard null-safe rendering",
      owner: "Frontend",
      priority: "P2",
      status: "Done",
      updatedAt: "2026-03-03 08:30",
      description: "Guard against missing block payload fields and keep skeleton view stable.",
    },
    {
      id: "TSK-333",
      title: "Bridge watcher threshold tuning",
      owner: "Bridge",
      priority: "P0",
      status: "Blocked",
      updatedAt: "2026-03-03 07:56",
      description: "Waiting for new anomaly baseline from production traffic replay.",
    },
  ],
  events: [
    {
      id: "EVT-928",
      time: "2026-03-03 10:30",
      category: "Deploy",
      summary: "Read-model indexer v0.9.4 deployed to canary",
      severity: "Info",
      details: "Canary in ap-east-1 enabled for 5% traffic. No rollback signal detected.",
    },
    {
      id: "EVT-925",
      time: "2026-03-03 09:54",
      category: "Incident",
      summary: "Temporary RPC latency spike in ap-east-1",
      severity: "Warning",
      details: "P95 latency rose to 1.2s for 6 minutes. Autoscaling policy patched and recovered.",
    },
    {
      id: "EVT-919",
      time: "2026-03-03 07:42",
      category: "Governance",
      summary: "Parameter proposal #18 entered review window",
      severity: "Info",
      details: "Community review open for 48 hours. Impacts reward epoch pacing.",
    },
    {
      id: "EVT-917",
      time: "2026-03-03 06:18",
      category: "Security",
      summary: "Signer access audit found stale key rotation",
      severity: "Critical",
      details: "One staging signer exceeded rotation SLA by 9 days. Rotation ticket escalated.",
    },
  ],
  audits: [
    {
      id: "AUD-114",
      control: "Readonly endpoint stability guardrails",
      result: "Pass",
      reviewer: "SRE",
      reviewedAt: "2026-03-03 10:02",
      notes: "SLO and alert routing verified for query endpoints.",
    },
    {
      id: "AUD-110",
      control: "Event retention > 90 days",
      result: "Pass",
      reviewer: "Data",
      reviewedAt: "2026-03-03 08:14",
      notes: "Cold storage archival policy sampled and confirmed.",
    },
    {
      id: "AUD-108",
      control: "Ops escalation policy linked",
      result: "Warn",
      reviewer: "Governance",
      reviewedAt: "2026-03-02 22:45",
      notes: "Two runbooks still reference deprecated incident channel.",
    },
    {
      id: "AUD-105",
      control: "Privileged write path disabled in dashboard",
      result: "Pass",
      reviewer: "Security",
      reviewedAt: "2026-03-02 21:19",
      notes: "No write endpoints exposed in frontend and gateway ACL.",
    },
  ],
};

export async function fetchDashboardSnapshot({
  mode = "ok",
}: {
  mode?: "ok" | "empty" | "error";
} = {}): Promise<DashboardSnapshot> {
  await new Promise((resolve) => setTimeout(resolve, 120));

  if (mode === "error") {
    throw new Error("Dashboard backend unavailable");
  }

  const normalized = adaptDashboardSnapshot(rawSnapshot);

  if (mode === "empty") {
    return { ...normalized, tasks: [], events: [], audits: [] };
  }

  return normalized;
}
