import { z } from "zod";
import {
  queryCapabilityAuditResponseSchema,
  queryEventsResponseSchema,
  queryNormalizedAuditEventsResponseSchema,
  queryTaskResponseSchema,
  checkedAtSchema,
} from "./schemas";
import type {
  QueryCapabilityAuditResult,
  QueryEventsResult,
  QueryTaskResult,
  QueryNormalizedAuditEventsResult,
  TaskStatus,
  NormalizedAuditEventsQuery,
  CheckedAt,
  IsoDatetimeString,
  HeightCheckedAt,
} from "./types";
import { FrontendApiError } from "./errors";

function normalizeSchemaError(error: unknown): FrontendApiError {
  return new FrontendApiError({
    code: "INVALID_PAYLOAD",
    message: "Backend response does not match frontend API contract",
    causeData: error,
    retryable: false,
  });
}

const rpcTaskSchema = z.object({
  task_id: z.number().int().nonnegative(),
  status: z.enum([
    "Open",
    "Assigned",
    "Committed",
    "Revealed",
    "Challenged",
    "Completed",
    "Slashed",
  ]),
  worker: z.string().min(1).nullable().optional(),
  bounty: z.union([z.number(), z.string()]).optional(),
  result_hash_hex: z.string().min(1).nullable().optional(),
  version: z.number().int().nonnegative().optional(),
});

const rpcEventSchema = z.object({
  event_type: z.string().min(1),
  task_id: z.number().int().nonnegative(),
  from_status: z.string().min(1),
  to_status: z.string().min(1),
  actor: z.string().min(1),
  tx_id: z.number().int().nonnegative(),
  block_height: z.number().int().nonnegative(),
  state_root: z.string().min(1),
  ts_unix_ms: z.union([z.number(), z.string()]),
  signer: z.string().min(1).optional(),
  challenger: z.string().min(1).nullable().optional(),
  tx_hash: z.string().min(1).nullable().optional(),
  resolution_code: z.string().min(1).nullable().optional(),
  treasury_delta: z.union([z.number(), z.string()]).nullable().optional(),
  challenger_delta: z.union([z.number(), z.string()]).nullable().optional(),
  bond_disposition: z.string().min(1).nullable().optional(),
});

const m2v2ErrorCodes = [
  "ERR_M2V2_PROOF_MISSING",
  "ERR_M2V2_PROOF_LATE",
  "ERR_M2V2_PROOF_INVALID",
  "ERR_M2V2_SETTLEMENT_DEGRADED",
] as const;

type M2V2ErrorCode = (typeof m2v2ErrorCodes)[number];

const m2v2ErrorCodeSet: ReadonlySet<string> = new Set(m2v2ErrorCodes);

function normalizeCanonicalEventForM2V2(
  event: QueryEventsResult["events"][number],
): QueryEventsResult["events"][number] {
  const rawResolutionCode =
    typeof event.payload?.resolutionCode === "string"
      ? event.payload.resolutionCode
      : typeof event.payload?.resolution_code === "string"
        ? event.payload.resolution_code
        : undefined;
  const resolutionCode = canonicalizeResolutionCode(rawResolutionCode);
  const isM2V2Error = isM2V2ErrorCode(resolutionCode);

  if (!isM2V2Error) return event;

  return {
    ...event,
    level: "error",
    payload: {
      ...event.payload,
      resolutionCode,
      m2v2ErrorCode: resolutionCode,
    },
  };
}

function canonicalizeResolutionCode(code: string | undefined): string | undefined {
  if (code == null) return undefined;
  const normalized = code
    .replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "")
    .trim()
    .toUpperCase()
    .replace(/[\s\-\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFF0D\uFE63\uFE58]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized.length > 0 ? normalized : undefined;
}

function isM2V2ErrorCode(code: string | undefined): code is M2V2ErrorCode {
  return code != null && m2v2ErrorCodeSet.has(code);
}

const rpcCapabilityAuditSchema = z.object({
  token: z.object({
    subject_did: z.string().min(1),
    scope: z.string().min(1),
    revoked_at: z.union([z.number(), z.string()]).nullable().optional(),
  }),
  owner_history: z.array(
    z.object({
      action: z.enum([
        "DID_REGISTERED",
        "DID_REVOKED",
        "CAPABILITY_ISSUED",
        "CAPABILITY_RENEWED",
        "CAPABILITY_REVOKED",
      ]),
      at_height: z.union([z.number(), z.string()]),
      note: z.string().optional().nullable(),
    }),
  ),
});

function mapRpcTaskStatus(status: z.infer<typeof rpcTaskSchema>["status"]): TaskStatus {
  switch (status) {
    case "Open":
      return "pending";
    case "Assigned":
      return "queued";
    case "Committed":
    case "Revealed":
    case "Challenged":
      return "running";
    case "Completed":
      return "succeeded";
    case "Slashed":
      return "failed";
  }
}

function toIsoFromUnixMs(ts: unknown): IsoDatetimeString {
  const num = typeof ts === "string" ? Number(ts) : ts;
  if (!Number.isFinite(num)) throw new Error("invalid timestamp");
  return new Date(Number(num)).toISOString() as IsoDatetimeString;
}

function toHeightMarker(height: unknown): HeightCheckedAt {
  const num = typeof height === "string" ? Number(height) : height;
  if (!Number.isFinite(num)) throw new Error("invalid height");
  return `height:${Math.trunc(Number(num))}` as HeightCheckedAt;
}

function toCheckedAt(value: z.infer<typeof checkedAtSchema>): CheckedAt {
  return value as CheckedAt;
}

function toOptionalHeightMarker(height: unknown): string | undefined {
  if (height == null) return undefined;
  if (typeof height === "string" && height.trim().length === 0) return undefined;
  return toHeightMarker(height);
}

function normalizeOptionalText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export const adaptQueryTask = (payload: unknown): QueryTaskResult => {
  const canonical = queryTaskResponseSchema.safeParse(payload);
  if (canonical.success) return canonical.data;

  const rpc = rpcTaskSchema.safeParse(payload);
  if (!rpc.success) throw normalizeSchemaError(rpc.error.flatten());

  const task = rpc.data;
  const derivedIso =
    task.version != null ? new Date(task.version * 1000).toISOString() : new Date(0).toISOString();

  return {
    task: {
      id: String(task.task_id),
      name: `rpc-task:${task.task_id}`,
      status: mapRpcTaskStatus(task.status),
      owner: "unmapped:rpc-owner-not-provided",
      createdAt: derivedIso,
      updatedAt: task.version != null ? derivedIso : undefined,
      metadata: {
        source: "trnm-rpc",
        bounty: task.bounty,
        resultHashHex: task.result_hash_hex ?? undefined,
        version: task.version,
        trace: {
          name: "derived-from-rpc-task-id",
          owner: "not-derived-from-worker-field",
          workerObserved: task.worker ?? null,
        },
      },
    },
  };
};

export const adaptQueryEvents = (
  payload: unknown,
  requestedTaskId?: string,
): QueryEventsResult => {
  const canonical = queryEventsResponseSchema.safeParse(payload);
  if (canonical.success) {
    return {
      ...canonical.data,
      events: canonical.data.events.map(normalizeCanonicalEventForM2V2),
    };
  }

  const rpc = z.array(rpcEventSchema).safeParse(payload);
  if (!rpc.success) throw normalizeSchemaError(rpc.error.flatten());

  const events = rpc.data;
  const normalizedTaskId =
    events[0] != null
      ? String(events[0].task_id)
      : requestedTaskId && requestedTaskId.trim().length > 0
        ? requestedTaskId
        : "";

  if (!normalizedTaskId) {
    throw normalizeSchemaError({
      message: "empty query-events payload requires requested task id context",
    });
  }

  const hasMixedTaskIds = events.some(
    (event) => String(event.task_id) !== normalizedTaskId,
  );
  if (hasMixedTaskIds) {
    throw normalizeSchemaError({
      message: "query-events payload contains mixed task ids",
      requestedTaskId,
      normalizedTaskId,
    });
  }

  return {
    taskId: normalizedTaskId,
    events: events.map((event) => {
      const resolutionCode = canonicalizeResolutionCode(event.resolution_code ?? undefined);
      const isM2V2Error = isM2V2ErrorCode(resolutionCode);

      return {
        id: `${event.task_id}:${event.tx_id}:${event.event_type}`,
        taskId: String(event.task_id),
        type: event.event_type,
        level:
          isM2V2Error || event.to_status === "Slashed"
            ? "error"
            : event.event_type === "challenge"
              ? "warn"
              : "info",
        timestamp: toIsoFromUnixMs(event.ts_unix_ms),
        payload: {
          fromStatus: event.from_status,
          toStatus: event.to_status,
          actor: event.actor,
          blockHeight: event.block_height,
          stateRoot: event.state_root,
          signer: event.signer,
          challenger: event.challenger,
          txHash: event.tx_hash,
          resolutionCode,
          m2v2ErrorCode: isM2V2Error ? resolutionCode : undefined,
          treasuryDelta: event.treasury_delta,
          challengerDelta: event.challenger_delta,
          bondDisposition: event.bond_disposition,
        },
      };
    }),
  };
};



export const adaptQueryNormalizedAuditEvents = (
  payload: unknown,
): QueryNormalizedAuditEventsResult => {
  const canonical = queryNormalizedAuditEventsResponseSchema.safeParse(payload);
  if (canonical.success) {
    return {
      events: canonical.data.events.map((event) => ({
        ...event,
        checkedAt: event.checkedAt == null ? undefined : toCheckedAt(event.checkedAt),
      })),
      nextCursor: "nextCursor" in canonical.data ? canonical.data.nextCursor : undefined,
      hasMore: "hasMore" in canonical.data ? canonical.data.hasMore : undefined,
      total: "total" in canonical.data ? canonical.data.total : undefined,
    };
  }

  const rpc = z.array(
    z.object({
      source: z.string().min(1),
      eventType: z.string().min(1),
      actor: z.string().min(1).optional(),
      objectId: z.string().min(1).optional(),
      relatedId: z.string().min(1).optional(),
      amount: z.union([z.string(), z.number().nonnegative()]).optional(),
      reason: z.string().optional(),
      note: z.string().optional(),
      checkedAt: checkedAtSchema.optional(),
      recordedAt: z.string().datetime().optional(),
      subject: z.string().optional(),
    }).strict(),
  ).safeParse(payload);

  if (!rpc.success) throw normalizeSchemaError(rpc.error.flatten());

  const events = rpc.data.map((event) => ({
    source: event.source,
    event_type: event.eventType,
    actor: event.actor,
    object_id: event.objectId,
    related_id: event.relatedId,
    amount: event.amount,
    reason: event.reason,
    note: event.note,
    checkedAt: event.checkedAt == null ? undefined : toCheckedAt(event.checkedAt),
    timestamp: event.recordedAt,
    subject: event.subject,
  }));

  return { events, hasMore: false };
};

export const adaptQueryCapabilityAudit = (
  payload: unknown,
): QueryCapabilityAuditResult => {
  const canonical = queryCapabilityAuditResponseSchema.safeParse(payload);
  if (canonical.success) {
    return {
      subject: canonical.data.subject,
      audits: canonical.data.audits.map((audit) => ({
        ...audit,
        checkedAt: toCheckedAt(audit.checkedAt),
      })),
    };
  }

  const rpc = rpcCapabilityAuditSchema.safeParse(payload);
  if (!rpc.success) throw normalizeSchemaError(rpc.error.flatten());

  try {
    const tokenRevokedAt = toOptionalHeightMarker(rpc.data.token.revoked_at);
    const tokenIsRevoked = tokenRevokedAt != null;

    return {
      subject: rpc.data.token.subject_did,
      audits: rpc.data.owner_history.map((entry) => {
        const actionGrantsCapability =
          entry.action === "CAPABILITY_ISSUED" || entry.action === "CAPABILITY_RENEWED";
        const actionTouchesCapability = actionGrantsCapability || entry.action === "CAPABILITY_REVOKED";

        const revocationMarker = tokenIsRevoked
          ? `TOKEN_REVOKED@${tokenRevokedAt}`
          : undefined;

        const normalizedNote = normalizeOptionalText(entry.note);

        return {
          subject: rpc.data.token.subject_did,
          capability: rpc.data.token.scope,
          granted: actionGrantsCapability,
          reason:
            tokenIsRevoked && actionTouchesCapability
              ? [revocationMarker, normalizedNote ?? entry.action]
                  .filter((value): value is string => typeof value === "string" && value.length > 0)
                  .join(": ")
              : normalizedNote ?? entry.action,
          checkedAt: toHeightMarker(entry.at_height),
        };
      }),
    };
  } catch (error) {
    throw normalizeSchemaError(error);
  }
};
