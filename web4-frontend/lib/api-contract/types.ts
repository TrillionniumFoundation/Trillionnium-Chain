export type TaskStatus =
  | "pending"
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "canceled";

export type ChainTask = {
  id: string;
  name?: string;
  status: TaskStatus;
  owner: string;
  createdAt: string;
  updatedAt?: string;
  metadata: Record<string, unknown>;
};

export type ChainEvent = {
  id: string;
  taskId: string;
  type: string;
  level: "info" | "warn" | "error";
  timestamp: string;
  payload: Record<string, unknown>;
};

export type CapabilityAuditEntry = {
  subject: string;
  capability: string;
  granted: boolean;
  reason?: string;
  checkedAt: string;
};

export type QueryTaskResult = {
  task: ChainTask;
};

export type QueryEventsResult = {
  taskId: string;
  events: ChainEvent[];
};

export type QueryCapabilityAuditResult = {
  subject: string;
  audits: CapabilityAuditEntry[];
};


export type NormalizedAuditEvent = {
  source: string;
  event_type: string;
  actor?: string;
  object_id?: string;
  related_id?: string;
  amount?: string | number;
  reason?: string;
  note?: string;
  checkedAt?: string;
  timestamp?: string;
  subject?: string;
};

export type QueryNormalizedAuditEventsResult = {
  events: NormalizedAuditEvent[];
  nextCursor?: string;
  hasMore?: boolean;
  total?: number;
};

export type NormalizedAuditEventsQuery = {
  source?: string;
  eventType?: string;
  limit?: number;
  cursor?: string;
};

