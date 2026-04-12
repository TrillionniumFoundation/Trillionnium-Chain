import { z } from "zod";

const normalizeNonEmptyCursor = (value: string): string =>
  value.replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "").trim();

const paginationCursorSchema = z.string().transform(normalizeNonEmptyCursor).pipe(z.string().min(1));
const normalizedQueryFilterSchema = z.string().transform(normalizeNonEmptyCursor).pipe(z.string().min(1));

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
}).strict();

export const chainEventSchema = z.object({
  id: z.string().min(1),
  taskId: z.string().min(1),
  type: z.string().min(1),
  level: z.enum(["info", "warn", "error"]),
  timestamp: z.string().datetime(),
  payload: z.record(z.string(), z.unknown()).default({}),
}).strict();

export const checkedAtSchema = z.string().regex(/^height:\d+$/).or(z.string().datetime());

export const capabilityAuditEntrySchema = z.object({
  subject: z.string().min(1),
  capability: z.string().min(1),
  granted: z.boolean(),
  reason: z.string().optional(),
  checkedAt: checkedAtSchema,
}).strict();

export const queryTaskResponseSchema = z.object({
  task: chainTaskSchema,
}).strict();

export const queryEventsResponseSchema = z.object({
  taskId: z.string().min(1),
  events: z.array(chainEventSchema),
}).strict();

export const queryCapabilityAuditResponseSchema = z.object({
  subject: z.string().min(1),
  audits: z.array(capabilityAuditEntrySchema),
}).strict();


export const normalizedAuditEventSchema = z.object({
  source: z.string().trim().min(1),
  event_type: z.string().trim().min(1),
  actor: z.string().min(1).optional(),
  object_id: z.string().min(1).optional(),
  related_id: z.string().min(1).optional(),
  amount: z.union([z.string(), z.number().nonnegative()]).optional(),
  reason: z.string().optional(),
  note: z.string().optional(),
  checkedAt: checkedAtSchema.optional(),
  timestamp: z.string().datetime().optional(),
  subject: z.string().min(1).optional(),
}).strict();

export const queryNormalizedAuditEventsPageSchema = z.object({
  events: z.array(normalizedAuditEventSchema),
  nextCursor: paginationCursorSchema.optional(),
  hasMore: z.boolean().optional(),
  total: z.number().int().nonnegative().optional(),
}).strict().superRefine((payload, ctx) => {
  if (payload.hasMore === true && payload.nextCursor == null) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "normalized audit page with hasMore=true must include nextCursor",
      path: ["nextCursor"],
    });
  }
});

export const normalizedAuditEventsQuerySchema = z.object({
  source: normalizedQueryFilterSchema.optional(),
  eventType: normalizedQueryFilterSchema.optional(),
  limit: z.number().int().positive().optional(),
  cursor: paginationCursorSchema.optional(),
}).strict();

export const queryNormalizedAuditEventsResponseSchema = queryNormalizedAuditEventsPageSchema;
