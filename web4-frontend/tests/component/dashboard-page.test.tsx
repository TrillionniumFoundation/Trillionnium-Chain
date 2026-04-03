import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Home from "@/app/page";
import { fetchDashboardSnapshot } from "@/lib/dashboard/source";

vi.mock("@/lib/dashboard/source", () => ({
  fetchDashboardSnapshot: vi.fn(),
}));

const mockedFetch = vi.mocked(fetchDashboardSnapshot);

const snapshot = {
  kpis: [
    { label: "Network Uptime", value: "99.9%", delta: "+0.1%", health: "healthy" as const },
    { label: "Pending Tasks", value: "2", delta: "-1", health: "degraded" as const },
    { label: "Open Incidents", value: "1", delta: "+1", health: "risk" as const },
    { label: "Audit Coverage", value: "96%", delta: "+2%", health: "healthy" as const },
  ],
  tasks: [
    {
      id: "TSK-1",
      title: "Task one",
      owner: "Ops",
      priority: "P1" as const,
      status: "Todo" as const,
      updatedAt: "2026-03-03 10:00",
      description: "Task one detail",
    },
    {
      id: "TSK-2",
      title: "Task two",
      owner: "Core",
      priority: "P0" as const,
      status: "Done" as const,
      updatedAt: "2026-03-03 11:00",
      description: "Task two detail",
    },
  ],
  events: [
    {
      id: "EVT-1",
      time: "2026-03-03 09:00",
      category: "Security" as const,
      summary: "Critical event",
      severity: "Critical" as const,
      details: "Critical event details",
    },
    {
      id: "EVT-2",
      time: "2026-03-03 09:30",
      category: "Deploy" as const,
      summary: "Info event",
      severity: "Info" as const,
      details: "Info event details",
    },
  ],
  audits: [
    {
      id: "AUD-1",
      control: "Readonly controls",
      result: "Warn" as const,
      reviewer: "Security",
      reviewedAt: "2026-03-03 08:00",
      notes: "Warn details",
    },
    {
      id: "AUD-2",
      control: "Endpoint ACL",
      result: "Pass" as const,
      reviewer: "SRE",
      reviewedAt: "2026-03-03 09:00",
      notes: "Pass details",
    },
  ],
};

describe("dashboard page", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mockedFetch.mockReset();
    window.history.replaceState({}, "", "/");
  });

  it("supports overview/tasks/events/audit demo flow with filtering and details", async () => {
    mockedFetch.mockResolvedValue(snapshot);
    render(<Home />);

    expect(await screen.findByText("Task Digest")).toBeInTheDocument();
    expect(screen.getByText("Open execution items: 1")).toBeInTheDocument();
    expect(screen.getByText("Critical events in latest window: 1")).toBeInTheDocument();
    expect(screen.getByText("Non-pass controls to review: 1")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Tasks" }));
    expect(await screen.findByText("Task Detail · TSK-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Status filter"), { target: { value: "Done" } });
    expect(await screen.findByText("Task Detail · TSK-2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Events" }));
    expect(await screen.findByText("Event Detail · EVT-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Severity filter"), { target: { value: "Info" } });
    expect(await screen.findByText("Event Detail · EVT-2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Audit" }));
    expect(await screen.findByText("Audit Detail · AUD-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Result filter"), { target: { value: "Pass" } });
    expect(await screen.findByText("Audit Detail · AUD-2")).toBeInTheDocument();
  });

  it("shows empty states when source returns empty mode payload", async () => {
    mockedFetch.mockResolvedValue({ ...snapshot, tasks: [], events: [], audits: [] });
    window.history.replaceState({}, "", "/?mode=empty");

    render(<Home />);

    fireEvent.click(await screen.findByRole("button", { name: "Tasks" }));
    expect(await screen.findByText("No tasks match current filter")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Events" }));
    expect(await screen.findByText("No events found")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Audit" }));
    expect(await screen.findByText("No audit controls found")).toBeInTheDocument();

    expect(mockedFetch).toHaveBeenCalledWith({ mode: "empty" });
  });

  it("fails closed to ok mode when the query param is unknown", async () => {
    mockedFetch.mockResolvedValue(snapshot);
    window.history.replaceState({}, "", "/?mode=write-enabled");

    render(<Home />);

    expect(await screen.findByText("Task Digest")).toBeInTheDocument();
    expect(mockedFetch).toHaveBeenCalledWith({ mode: "ok" });
  });

  it("uses readonly mock fallback when explicitly requested via query param", async () => {
    mockedFetch.mockResolvedValue(snapshot);
    window.history.replaceState({}, "", "/?mode=mock");

    render(<Home />);

    expect(await screen.findByText("Task Digest")).toBeInTheDocument();
    expect(screen.getByText("Open execution items: 1")).toBeInTheDocument();
    expect(mockedFetch).toHaveBeenCalledWith({ mode: "mock" });
  });

  it("shows adapter error state", async () => {
    mockedFetch.mockRejectedValue(new Error("Dashboard backend unavailable"));
    window.history.replaceState({}, "", "/?mode=error");

    render(<Home />);

    await waitFor(() => {
      expect(screen.getByText("Failed to load dashboard")).toBeInTheDocument();
    });

    expect(screen.getByText(/Adapter source error: Dashboard backend unavailable/)).toBeInTheDocument();
    expect(mockedFetch).toHaveBeenCalledWith({ mode: "error" });
  });
});
