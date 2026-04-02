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

  it("accepts snake_case task/audit timestamps and normalizes them", () => {
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
          time: "2026-01-02",
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
    expect(result.audits[0].reviewedAt).toBe("2026-01-02");
  });

  it("accepts mixed camelCase and snake_case timestamp aliases within the same readonly snapshot", () => {
    const payload = {
      kpis: [{ label: "K1", value: "1", delta: "+0", health: "healthy" }],
      tasks: [
        {
          id: "TSK-3",
          title: "camel-task",
          owner: "ops",
          priority: "P1",
          status: "Todo",
          updatedAt: "2026-01-03",
          description: "desc",
        },
        {
          id: "TSK-4",
          title: "snake-task",
          owner: "ops",
          priority: "P2",
          status: "Done",
          updated_at: "2026-01-04",
          description: "desc",
        },
      ],
      events: [
        {
          id: "EVT-3",
          time: "2026-01-03",
          category: "Governance",
          summary: "sum",
          severity: "Info",
          details: "detail",
        },
      ],
      audits: [
        {
          id: "AUD-3",
          control: "ctl-a",
          result: "Pass",
          reviewer: "sec",
          reviewedAt: "2026-01-03",
          notes: "ok",
        },
        {
          id: "AUD-4",
          control: "ctl-b",
          result: "Warn",
          reviewer: "sec",
          reviewed_at: "2026-01-04",
          notes: "watch",
        },
      ],
    };

    const result = adaptDashboardSnapshot(payload);
    expect(result.tasks.map((task) => task.updatedAt)).toEqual(["2026-01-03", "2026-01-04"]);
    expect(result.audits.map((audit) => audit.reviewedAt)).toEqual(["2026-01-03", "2026-01-04"]);
  });

  it("fails closed when any readonly snapshot row violates the schema", () => {
    const payload = {
      kpis: [{ label: "K1", value: "1", delta: "+0", health: "healthy" }],
      tasks: [
        {
          id: "TSK-5",
          title: "task",
          owner: "ops",
          priority: "P1",
          status: "Todo",
          updatedAt: "2026-01-05",
          description: "desc",
        },
      ],
      events: [
        {
          id: "EVT-5",
          time: "2026-01-05",
          category: "Deploy",
          summary: "sum",
          severity: "Info",
          details: "detail",
        },
      ],
      audits: [
        {
          id: "AUD-5",
          control: "ctl",
          result: "Pass",
          reviewer: "sec",
          reviewedAt: "2026-01-05",
          notes: "ok",
        },
        {
          id: "AUD-6",
          control: "ctl-bad",
          result: "Maybe",
          reviewer: "sec",
          reviewedAt: "2026-01-06",
          notes: "bad",
        },
      ],
    };

    expect(() => adaptDashboardSnapshot(payload)).toThrow(DashboardAdapterError);
  });

  it("throws on invalid payload", () => {
    expect(() => adaptDashboardSnapshot({ tasks: [] })).toThrow(DashboardAdapterError);
  });
});
