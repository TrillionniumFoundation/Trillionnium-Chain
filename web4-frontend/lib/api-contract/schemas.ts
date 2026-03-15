import { z } from "zod";

export const taskStatusSchema = z.enum([
  "pending",
  "queued",
  "running",
  "succeeded",
  "failed",
  "canceled",
]);

export const chainTaskSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1).optional(),
  status: taskStatusSchema,
  owner: z.string().min(1),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime().optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export const chainEventSchema = z.object({
  id: z.string().min(1),
  taskId: z.string().min(1),
  type: z.string().min(1),
  level: z.enum(["info", "warn", "error"]),
  timestamp: z.string().datetime(),
  payload: z.record(z.string(), z.unknown()).default({}),
});

export const checkedAtSchema = z.string().regex(/^height:\d+$/).or(z.string().datetime());

export const capabilityAuditEntrySchema = z.object({
  subject: z.string().min(1),
  capability: z.string().min(1),
  granted: z.boolean(),
  reason: z.string().optional(),
  checkedAt: checkedAtSchema,
});

export const queryTaskResponseSchema = z.object({
  task: chainTaskSchema,
});

export const queryEventsResponseSchema = z.object({
  taskId: z.string().min(1),
  events: z.array(chainEventSchema),
});

export const queryCapabilityAuditResponseSchema = z.object({
  subject: z.string().min(1),
  audits: z.array(capabilityAuditEntrySchema),
});


export const normalizedAuditEventSchema = z.object({
  source: z.string().min(1),
  event_type: z.string().min(1),
  actor: z.string().min(1).optional(),
  object_id: z.string().optional(),
  related_id: z.string().optional(),
  amount: z.union([z.string(), z.number().nonnegative()]).optional(),
  reason: z.string().optional(),
  note: z.string().optional(),
  checkedAt: checkedAtSchema.optional(),
  timestamp: z.string().datetime().optional(),
  subject: z.string().optional(),
});

export const queryNormalizedAuditEventsPageSchema = z.object({
  events: z.array(normalizedAuditEventSchema),
  nextCursor: z.string().min(1).optional(),
  hasMore: z.boolean().optional(),
  total: z.number().int().nonnegative().optional(),
});

export const queryNormalizedAuditEventsResponseSchema = z.union([
  queryNormalizedAuditEventsPageSchema,
  z.object({
    events: z.array(normalizedAuditEventSchema),
  }),
]);
