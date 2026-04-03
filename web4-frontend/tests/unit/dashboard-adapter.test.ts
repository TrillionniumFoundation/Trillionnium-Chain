import { describe, expect, it } from "vitest";
import { adaptDashboardSnapshot, DashboardAdapterError } from "@/lib/dashboard/adapter";

describe("adaptDashboardSnapshot", () => {
  it("accepts valid payload", () => {
    const payload = {
      kpis: [{ label: "K1", value: "1", delta: "+0", health: "healthy" }],
      tasks: [
        {
          id: "TSK-1",
          title: "task",
          owner: "ops",
          priority: "P1",
          status: "Todo",
          updatedAt: "2026-01-01",
          description: "desc",
        },
      ],
      events: [
        {
          id: "EVT-1",
          time: "2026-01-01",
          category: "Deploy",
          summary: "sum",
          severity: "Info",
          details: "detail",
        },
      ],
      audits: [
        {
          id: "AUD-1",
          control: "ctl",
          result: "Pass",
          reviewer: "sec",
          reviewedAt: "2026-01-01",
          notes: "ok",
        },
      ],
    };

    const result = adaptDashboardSnapshot(payload);
    expect(result.tasks[0].id).toBe("TSK-1");
  });

  it("accepts snake_case task/event/audit timestamps and normalizes them", () => {
    const payload = {
      kpis: [{ label: "K1", value: "1", delta: "+0", health: "healthy" }],
      tasks: [
        {
          id: "TSK-2",
          title: "task",
          owner: "ops",
          priority: "P1",
          status: "Todo",
          updated_at: "2026-01-02",
          description: "desc",
        },
      ],
      events: [
        {
          id: "EVT-2",
          event_time: "2026-01-02",
          category: "Deploy",
          summary: "sum",
          severity: "Info",
          details: "detail",
        },
      ],
      audits: [
        {
          id: "AUD-2",
          control: "ctl",
          result: "Pass",
          reviewer: "sec",
          reviewed_at: "2026-01-02",
          notes: "ok",
        },
      ],
    };

    const result = adaptDashboardSnapshot(payload);
    expect(result.tasks[0].updatedAt).toBe("2026-01-02");
    expect(result.events[0].time).toBe("2026-01-02");
    expect(result.audits[0].reviewedAt).toBe("2026-01-02");
  });

  it("accepts legacy slim snapshots and fills missing detail fields with empty strings", () => {
    const payload = {
      kpis: [{ label: "K1", value: "1", delta: "+0", health: "healthy" }],
      tasks: [
        {
          id: "TSK-3",
          title: "task",
          owner: "ops",
          priority: "P1",
          status: "Todo",
          updatedAt: "2026-01-03",
        },
      ],
      events: [
        {
          id: "EVT-3",
          time: "2026-01-03",
          category: "Deploy",
          summary: "sum",
          severity: "Info",
        },
      ],
      audits: [
        {
          id: "AUD-3",
          control: "ctl",
          result: "Pass",
          reviewer: "sec",
          reviewedAt: "2026-01-03",
        },
      ],
    };

    const result = adaptDashboardSnapshot(payload);
    expect(result.tasks[0].description).toBe("");
    expect(result.events[0].details).toBe("");
    expect(result.audits[0].notes).toBe("");
  });

  it("throws on invalid payload", () => {
    expect(() => adaptDashboardSnapshot({ tasks: [] })).toThrow(DashboardAdapterError);
  });
});
