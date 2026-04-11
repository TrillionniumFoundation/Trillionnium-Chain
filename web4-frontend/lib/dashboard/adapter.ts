import { z } from "zod";

const optionalDetailField = z.string().min(1).catch("");

const kpiSchema = z
  .object({
    label: z.string().min(1),
    value: z.string().min(1),
    delta: z.string().min(1),
    health: z.enum(["healthy", "degraded", "risk"]),
  })
  .strict();

const taskSchema = z
  .object({
    id: z.string().min(1),
    title: z.string().min(1),
    owner: z.string().min(1),
    priority: z.enum(["P0", "P1", "P2"]),
    status: z.enum(["Todo", "In Progress", "Blocked", "Done"]),
    updatedAt: z.string().min(1),
    description: optionalDetailField,
  })
  .strict()
  .or(
    z
      .object({
        id: z.string().min(1),
        title: z.string().min(1),
        owner: z.string().min(1),
        priority: z.enum(["P0", "P1", "P2"]),
        status: z.enum(["Todo", "In Progress", "Blocked", "Done"]),
        updated_at: z.string().min(1),
        description: optionalDetailField,
      })
      .strict()
      .transform(({ updated_at, ...rest }) => ({ ...rest, updatedAt: updated_at }))
  );

const eventSchema = z
  .object({
    id: z.string().min(1),
    time: z.string().min(1),
    category: z.enum(["Deploy", "Incident", "Governance", "Security"]),
    summary: z.string().min(1),
    severity: z.enum(["Info", "Warning", "Critical"]),
    details: optionalDetailField,
  })
  .strict()
  .or(
    z
      .object({
        id: z.string().min(1),
        event_time: z.string().min(1),
        category: z.enum(["Deploy", "Incident", "Governance", "Security"]),
        summary: z.string().min(1),
        severity: z.enum(["Info", "Warning", "Critical"]),
        details: optionalDetailField,
      })
      .strict()
      .transform(({ event_time, ...rest }) => ({ ...rest, time: event_time }))
  );

const auditSchema = z
  .object({
    id: z.string().min(1),
    control: z.string().min(1),
    result: z.enum(["Pass", "Warn", "Fail"]),
    reviewer: z.string().min(1),
    reviewedAt: z.string().min(1),
    notes: optionalDetailField,
  })
  .strict()
  .or(
    z
      .object({
        id: z.string().min(1),
        control: z.string().min(1),
        result: z.enum(["Pass", "Warn", "Fail"]),
        reviewer: z.string().min(1),
        reviewed_at: z.string().min(1),
        notes: optionalDetailField,
      })
      .strict()
      .transform(({ reviewed_at, ...rest }) => ({ ...rest, reviewedAt: reviewed_at }))
  );

const dashboardSnapshotSchema = z
  .object({
    kpis: z.array(kpiSchema),
    tasks: z.array(taskSchema),
    events: z.array(eventSchema),
    audits: z.array(auditSchema),
  })
  .strict();

export type DashboardSnapshot = z.infer<typeof dashboardSnapshotSchema>;

export class DashboardAdapterError extends Error {
  readonly code = "INVALID_DASHBOARD_PAYLOAD";

  constructor(message: string, readonly causeData?: unknown) {
    super(message);
    this.name = "DashboardAdapterError";
  }
}

export const adaptDashboardSnapshot = (payload: unknown): DashboardSnapshot => {
  const parsed = dashboardSnapshotSchema.safeParse(payload);
  if (!parsed.success) {
    throw new DashboardAdapterError("Dashboard payload schema mismatch", parsed.error.flatten());
  }
  return parsed.data;
};
