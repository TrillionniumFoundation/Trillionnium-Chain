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

  it("throws on invalid payload", () => {
    expect(() => adaptDashboardSnapshot({ tasks: [] })).toThrow(DashboardAdapterError);
  });
});
