import { createFrontendApiClient } from "@/lib/api-contract/client";
import type {
  CapabilityAuditEntry,
  ChainEvent,
  ChainTask,
  NormalizedAuditEvent,
} from "@/lib/api-contract/types";
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

const resolveQueryApiBaseUrl = (): string => {
  const fromEnv = process.env.NEXT_PUBLIC_QUERY_API_BASE_URL?.trim();
  if (fromEnv) return fromEnv;

  if (typeof window !== "undefined") {
    return window.location.origin.replace(/\/+$/, "");
  }

  return "http://127.0.0.1:8080";
};

const resolveNonEmptyEnv = (value: string | undefined, fallback: string): string => {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};

const resolvePreferredTimestamp = (...candidates: Array<string | undefined>): string | undefined => {
  for (const candidate of candidates) {
    const normalized = candidate?.trim();
    if (normalized) return normalized;
  }

  return undefined;
};

const resolveDashboardTaskId = (): string =>
  resolveNonEmptyEnv(process.env.NEXT_PUBLIC_DASHBOARD_TASK_ID, "341");

const resolveDashboardAuditSubject = (): string =>
  resolveNonEmptyEnv(process.env.NEXT_PUBLIC_DASHBOARD_AUDIT_SUBJECT, "did:trnm:core-rpc");

const toDisplayTime = (isoLike?: string): string => {
  if (typeof isoLike !== "string" || isoLike.trim().length === 0) return "-";

  const date = new Date(isoLike);
  if (Number.isNaN(date.getTime())) return isoLike;

  const fmt = new Intl.DateTimeFormat("sv-SE", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

  return fmt.format(date);
};

const mapTaskStatus = (status: ChainTask["status"]): DashboardSnapshot["tasks"][number]["status"] => {
  if (status === "running") return "In Progress";
  if (status === "succeeded") return "Done";
  if (status === "failed" || status === "canceled") return "Blocked";
  return "Todo";
};

const mapEventSeverity = (
  level: ChainEvent["level"],
): DashboardSnapshot["events"][number]["severity"] => {
  if (level === "error") return "Critical";
  if (level === "warn") return "Warning";
  return "Info";
};

const mapEventCategory = (
  type: string,
): DashboardSnapshot["events"][number]["category"] => {
  if (/deploy/i.test(type)) return "Deploy";
  if (/security|auth|audit/i.test(type)) return "Security";
  if (/govern/i.test(type)) return "Governance";
  if (/vault/i.test(type) || /bridge.*relay/i.test(type) || /bridge_relay|settlement_vault|governance/i.test(type)) {
    return "Security";
  }
  return "Incident";
};

const normalizeDashboardEventToken = (value: string | undefined, fallback: string): string => {
  const normalized = value
    ?.replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};

const normalizeDashboardText = (value: string | undefined, fallback: string): string => {
  const normalized = value
    ?.replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};

const normalizeDashboardSignalTokens = (...values: Array<string | undefined>): string =>
  values
    .join(" ")
    .replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

const mapNormalizedAuditSeverity = (event: NormalizedAuditEvent): DashboardSnapshot["events"][number]["severity"] => {
  const normalizedEventType = normalizeDashboardEventToken(event.event_type, "unknown-event");
  const tokens = normalizeDashboardSignalTokens(event.reason, event.note, normalizedEventType);

  if (
    tokens.includes("critical") ||
    tokens.includes("error") ||
    tokens.includes("fail") ||
    tokens.includes("reject") ||
    tokens.includes("invalid") ||
    tokens.includes("revoke") ||
    tokens.includes("revocat") ||
    tokens.includes("expire") ||
    tokens.includes("expirat") ||
    tokens.includes("disable") ||
    tokens.includes("disabled") ||
    tokens.includes("suspend") ||
    tokens.includes("unauthor") ||
    tokens.includes("forbid") ||
    tokens.includes("denied")
  ) {
    return "Critical";
  }
  if (tokens.includes("warn") || tokens.includes("drift") || tokens.includes("mismatch")) {
    return "Warning";
  }
  return "Info";
};

const mapNormalizedAuditToDashboardEvent = (event: NormalizedAuditEvent, fallbackTime: string): DashboardSnapshot["events"][number] => {
  const source = normalizeDashboardEventToken(event.source, "unknown-source");
  const eventType = normalizeDashboardEventToken(event.event_type, "unknown-event");
  const actor = normalizeDashboardEventToken(event.actor, "system");
  const objectId = event.object_id
    ?.replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim();

  return {
    id: objectId && objectId.length > 0
      ? `${source}:${objectId}`
      : `${source}:${eventType}:${actor}`,
    time: toDisplayTime(event.timestamp ?? event.checkedAt ?? fallbackTime),
    category: mapEventCategory(eventType),
    summary: `${source} · ${eventType}`,
    severity: mapNormalizedAuditSeverity(event),
    details: stringifyDashboardField(
      {
        actor: event.actor,
        objectId: event.object_id,
        relatedId: event.related_id,
        amount: event.amount,
        reason: event.reason,
        note: event.note,
      },
      "{}",
    ),
  };
};

const toEventSortKey = (displayTime: string): number => {
  const parsed = Date.parse(displayTime);
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
};

const parsePositiveIntEnv = (value: string | undefined, fallback: number): number => {
  const normalized = value?.trim();
  if (!normalized) return fallback;
  if (!/^\d+$/.test(normalized)) return fallback;

  const parsed = Number.parseInt(normalized, 10);
  if (Number.isNaN(parsed) || parsed <= 0) return fallback;

  return parsed;
};

const normalizeOptionalCursor = (cursor: string | undefined): string | undefined => {
  if (cursor == null) return undefined;

  const normalized = cursor
    .replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim();

  return normalized.length > 0 ? normalized : undefined;
};

const resolveNormalizedAuditPageLimit = (): number =>
  parsePositiveIntEnv(process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_EVENT_LIMIT, 60);

const resolveNormalizedAuditMaxPages = (): number =>
  parsePositiveIntEnv(process.env.NEXT_PUBLIC_DASHBOARD_NORMALIZED_AUDIT_MAX_PAGES, 4);

const getNormalizedAuditEventKey = (event: NormalizedAuditEvent): string =>
  [
    normalizeDashboardEventToken(event.source, "unknown-source"),
    normalizeDashboardEventToken(event.event_type, "unknown-event"),
    normalizeDashboardText(event.object_id, ""),
    normalizeDashboardText(event.related_id, ""),
    normalizeDashboardText(event.actor, ""),
    normalizeDashboardText(event.subject, ""),
    normalizeDashboardText(event.timestamp, ""),
    normalizeDashboardText(event.checkedAt, ""),
    event.amount == null ? "" : String(event.amount),
    normalizeDashboardText(event.reason, ""),
    normalizeDashboardText(event.note, ""),
  ].join("\u001f");

const fetchNormalizedAuditEventsWithPagination = async (
  client: ReturnType<typeof createFrontendApiClient>,
): Promise<NormalizedAuditEvent[]> => {
  const allEvents: NormalizedAuditEvent[] = [];
  const normalizedAuditPageLimit = resolveNormalizedAuditPageLimit();
  const normalizedAuditMaxPages = resolveNormalizedAuditMaxPages();
  const seenCursors = new Set<string>();
  const seenEventKeys = new Set<string>();

  let cursor: string | undefined;
  let page = 0;
  let hasMore = true;

  while (hasMore && page < normalizedAuditMaxPages) {
    const query = cursor == null ? {} : { cursor };
    const pageResp = await client.queryNormalizedAuditEvents({ ...query, limit: normalizedAuditPageLimit });

    for (const event of pageResp.events) {
      const eventKey = getNormalizedAuditEventKey(event);
      if (seenEventKeys.has(eventKey)) continue;
      seenEventKeys.add(eventKey);
      allEvents.push(event);
    }

    const nextCursor = normalizeOptionalCursor(pageResp.nextCursor);
    if (pageResp.hasMore === true && nextCursor == null) {
      throw new Error("Normalized audit pagination declared more pages without a next cursor");
    }

    hasMore = pageResp.hasMore === true && nextCursor != null;

    if (!hasMore || !nextCursor) break;

    if (nextCursor === cursor || seenCursors.has(nextCursor)) {
      throw new Error(`Normalized audit pagination cursor stalled at ${nextCursor}`);
    }

    seenCursors.add(nextCursor);
    cursor = nextCursor;
    page += 1;
  }

  if (hasMore) {
    throw new Error(`Normalized audit pagination exceeded max pages (${normalizedAuditMaxPages})`);
  }

  return allEvents;
};

const mapAuditResult = (
  entry: CapabilityAuditEntry,
): DashboardSnapshot["audits"][number]["result"] => {
  if (entry.granted) return "Pass";
  return entry.reason ? "Warn" : "Fail";
};

const stringifyDashboardField = (value: unknown, fallback: string): string => {
  if (value == null) return fallback;
  if (typeof value === "string") {
    return value.trim().length > 0 ? value : fallback;
  }

  try {
    const serialized = JSON.stringify(value);
    return serialized ?? fallback;
  } catch {
    return fallback;
  }
};

const parseDashboardTime = (value: string): number => {
  const direct = Date.parse(value);
  if (!Number.isNaN(direct)) return direct;

  const normalized = value.trim().replace(" ", "T");
  const fallback = Date.parse(normalized);
  if (!Number.isNaN(fallback)) return fallback;

  return Number.MIN_SAFE_INTEGER;
};

async function fetchReadonlySnapshotFromApi(): Promise<DashboardSnapshot> {
  const client = createFrontendApiClient({ baseUrl: resolveQueryApiBaseUrl() });
  const dashboardTaskId = resolveDashboardTaskId();
  const dashboardAuditSubject = resolveDashboardAuditSubject();

  const [taskResp, eventsResp, auditsResp, normalizedAuditEvents] = await Promise.all([
    client.queryTask(dashboardTaskId),
    client.queryEvents(dashboardTaskId),
    client.queryCapabilityAudit(dashboardAuditSubject),
    fetchNormalizedAuditEventsWithPagination(client),
  ]);

  const mapped = {
    kpis: [
      {
        label: "Readonly API",
        value: "Connected",
        delta: `task ${taskResp.task.id}`,
        health: "healthy" as const,
      },
      {
        label: "Pending Tasks",
        value: mapTaskStatus(taskResp.task.status) === "Done" ? "0" : "1",
        delta: "live",
        health: mapTaskStatus(taskResp.task.status) === "Done" ? ("healthy" as const) : ("degraded" as const),
      },
      {
        label: "Open Incidents",
        value: String(
          eventsResp.events.filter((event) => event.level === "error").length
            + normalizedAuditEvents.filter((event) => mapNormalizedAuditSeverity(event) === "Critical").length,
        ),
        delta: "live",
        health:
          eventsResp.events.some((event) => event.level === "error") ||
          normalizedAuditEvents.some((event) => mapNormalizedAuditSeverity(event) === "Critical")
            ? ("risk" as const)
            : ("healthy" as const),
      },
      {
        label: "Audit Coverage",
        value: `${Math.round((auditsResp.audits.filter((item) => item.granted).length / Math.max(auditsResp.audits.length, 1)) * 100)}%`,
        delta: "live",
        health:
          auditsResp.audits.every((item) => item.granted)
            ? ("healthy" as const)
            : ("degraded" as const),
      },
    ],
    tasks: [
      {
        id: taskResp.task.id,
        title: normalizeDashboardText(taskResp.task.name, `task-${taskResp.task.id}`),
        owner: normalizeDashboardText(taskResp.task.owner, "Unassigned"),
        priority: "P1" as const,
        status: mapTaskStatus(taskResp.task.status),
        updatedAt: (() => {
          const timestamp = resolvePreferredTimestamp(taskResp.task.updatedAt, taskResp.task.createdAt);
          return timestamp ? toDisplayTime(timestamp) : "-";
        })(),
        description: stringifyDashboardField(taskResp.task.metadata, "{}"),
      },
    ],
    events: [
      ...eventsResp.events.map((event) => {
        const normalizedType = normalizeDashboardEventToken(event.type, "unknown-event");

        return {
          id: event.id,
          time: toDisplayTime(event.timestamp),
          category: mapEventCategory(normalizedType),
          summary: normalizedType,
          severity: mapEventSeverity(event.level),
          details: stringifyDashboardField(event.payload, "{}"),
        };
      }),
      ...normalizedAuditEvents.map((event) =>
        mapNormalizedAuditToDashboardEvent(
          event,
          eventsResp.events[0]?.timestamp ?? taskResp.task.createdAt,
        ),
      ),
    ].sort((left, right) => parseDashboardTime(right.time) - parseDashboardTime(left.time)),
    audits: auditsResp.audits.map((audit, index) => ({
      id: `AUD-${index + 1}`,
      control: audit.capability,
      result: mapAuditResult(audit),
      reviewer: "Capability",
      reviewedAt: toDisplayTime(audit.checkedAt),
      notes: normalizeDashboardText(
        audit.reason,
        audit.granted ? "Granted" : "No reason provided",
      ),
    })),
  };

  return adaptDashboardSnapshot(mapped);
}

export async function fetchDashboardSnapshot({
  mode = "ok",
}: {
  mode?: "ok" | "empty" | "error" | "mock";
} = {}): Promise<DashboardSnapshot> {
  await new Promise((resolve) => setTimeout(resolve, 120));

  if (mode === "error") {
    throw new Error("Dashboard backend unavailable");
  }

  if (mode === "mock") {
    if (process.env.NODE_ENV === "production") {
      throw new Error("Mock mode is disabled in production");
    }
    return adaptDashboardSnapshot(rawSnapshot);
  }

  const normalized = await fetchReadonlySnapshotFromApi().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Unknown API client failure";
    throw new Error(
      `Readonly API unavailable (fail-closed): ${message}. Add ?mode=mock to switch to readonly snapshot fallback.`,
    );
  });

  if (mode === "empty") {
    return { ...normalized, tasks: [], events: [], audits: [] };
  }

  return normalized;
}
