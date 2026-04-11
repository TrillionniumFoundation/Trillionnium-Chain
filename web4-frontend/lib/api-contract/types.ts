export type TaskStatus =
  | "pending"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "canceled";

export type ChainTask = Readonly<{
  id: string;
  name?: string;
  status: TaskStatus;
  owner: string;
  createdAt: string;
  updatedAt?: string;
  metadata: Readonly<Record<string, unknown>>;
}>;

export type ChainEvent = Readonly<{
  id: string;
  taskId: string;
  type: string;
  level: "info" | "warn" | "error";
  timestamp: string;
  payload: Readonly<Record<string, unknown>>;
}>;

export type HeightCheckedAt = `height:${number}`;
export type IsoDatetimeString = `${string}T${string}`;
export type CheckedAt = HeightCheckedAt | IsoDatetimeString;

export type CapabilityAuditEntry = Readonly<{
  subject: string;
  capability: string;
  granted: boolean;
  reason?: string;
  checkedAt: CheckedAt;
}>;

export type QueryTaskResult = Readonly<{
  task: ChainTask;
}>;

export type QueryEventsResult = Readonly<{
  taskId: string;
  events: ReadonlyArray<ChainEvent>;
}>;

export type QueryCapabilityAuditResult = Readonly<{
  subject: string;
  audits: ReadonlyArray<CapabilityAuditEntry>;
}>;


export type NormalizedAuditEvent = Readonly<{
  source: string;
  event_type: string;
  actor?: string;
  object_id?: string;
  related_id?: string;
  amount?: string | number;
  reason?: string;
  note?: string;
  checkedAt?: CheckedAt;
  timestamp?: string;
  subject?: string;
}>;

type QueryNormalizedAuditEventsBase = Readonly<{
  events: ReadonlyArray<NormalizedAuditEvent>;
  total?: number;
}>;

export type QueryNormalizedAuditEventsResult =
  | (QueryNormalizedAuditEventsBase & Readonly<{
      hasMore: true;
      nextCursor: string;
    }> )
  | (QueryNormalizedAuditEventsBase & Readonly<{
      hasMore?: false;
      nextCursor?: string;
    }>);

export type NormalizedAuditEventsQuery = Readonly<{
  source?: string;
  eventType?: string;
  limit?: number;
  cursor?: string;
}>;
