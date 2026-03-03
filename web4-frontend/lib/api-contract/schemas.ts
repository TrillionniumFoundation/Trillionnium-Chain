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
  createdAt: z.string().datetime().optional(),
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

export const capabilityAuditEntrySchema = z.object({
  subject: z.string().min(1),
  capability: z.string().min(1),
  granted: z.boolean(),
  reason: z.string().optional(),
  checkedAt: z.string().datetime(),
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
