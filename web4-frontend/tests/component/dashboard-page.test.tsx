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

    fireEvent.click(screen.getByRole("tab", { name: "Tasks" }));
    expect(await screen.findByText("Task Detail · TSK-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Status filter"), { target: { value: "Done" } });
    expect(await screen.findByText("Task Detail · TSK-2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Events" }));
    expect(await screen.findByText("Event Detail · EVT-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Severity filter"), { target: { value: "Info" } });
    expect(await screen.findByText("Event Detail · EVT-2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: "Audit" }));
    expect(await screen.findByText("Audit Detail · AUD-1")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Result filter"), { target: { value: "Pass" } });
    expect(await screen.findByText("Audit Detail · AUD-2")).toBeInTheDocument();
  });

  it("shows empty states when source returns empty mode payload", async () => {
    mockedFetch.mockResolvedValue({ ...snapshot, tasks: [], events: [], audits: [] });
    window.history.replaceState({}, "", "/?mode=empty");

    render(<Home />);

    fireEvent.click(await screen.findByRole("tab", { name: "Tasks" }));
    const tasksEmptyState = await screen.findByRole("status");
    expect(tasksEmptyState).toHaveTextContent("No tasks match current filter");
    expect(tasksEmptyState).toHaveTextContent(
      "Readonly task snapshot has no entries for this filter. Try another status filter or switch to All.",
    );
    expect(tasksEmptyState).toHaveAttribute("aria-live", "polite");

    fireEvent.click(screen.getByRole("tab", { name: "Events" }));
    const eventsEmptyState = await screen.findByRole("status");
    expect(eventsEmptyState).toHaveTextContent("No events found");
    expect(eventsEmptyState).toHaveTextContent("Readonly event snapshot has no matching records for this filter.");
    expect(eventsEmptyState).toHaveAttribute("aria-live", "polite");

    fireEvent.click(screen.getByRole("tab", { name: "Audit" }));
    const auditsEmptyState = await screen.findByRole("status");
    expect(auditsEmptyState).toHaveTextContent("No audit controls found");
    expect(auditsEmptyState).toHaveTextContent("Readonly audit snapshot has no entries for this result filter.");
    expect(auditsEmptyState).toHaveAttribute("aria-live", "polite");

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

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Failed to load dashboard");
    expect(alert).toHaveTextContent("Adapter source error: Dashboard backend unavailable");
    expect(alert).toHaveAttribute("aria-live", "assertive");
    expect(mockedFetch).toHaveBeenCalledWith({ mode: "error" });
  });

  it("announces loading state politely before readonly data resolves", () => {
    mockedFetch.mockImplementation(
      () =>
        new Promise(() => {
          // keep pending to assert loading UX
        }),
    );

    render(<Home />);

    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("Loading dashboard snapshot");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-busy", "true");
  });

  it("supports keyboard selection for readonly task, event, and audit details", async () => {
    mockedFetch.mockResolvedValue(snapshot);

    render(<Home />);

    await screen.findByText("Task Digest");

    fireEvent.click(screen.getByRole("tab", { name: "Tasks" }));
    const taskRow = screen.getByRole("button", { name: /TSK-2 Task two Core P0 Done 2026-03-03 11:00/i });
    fireEvent.keyDown(taskRow, { key: "Enter" });
    expect(await screen.findByText("Task Detail · TSK-2")).toBeInTheDocument();
    expect(taskRow).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("tab", { name: "Events" }));
    const eventCard = screen.getByText("Info event").closest("article");
    expect(eventCard).not.toBeNull();
    fireEvent.keyDown(eventCard!, { key: " " });
    expect(await screen.findByText("Event Detail · EVT-2")).toBeInTheDocument();
    expect(eventCard).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("tab", { name: "Audit" }));
    const auditCard = screen.getByText("Endpoint ACL").closest("article");
    expect(auditCard).not.toBeNull();
    fireEvent.keyDown(auditCard!, { key: "Enter" });
    expect(await screen.findByText("Audit Detail · AUD-2")).toBeInTheDocument();
    expect(auditCard).toHaveAttribute("aria-pressed", "true");
  });

  it("fail-closes stale readonly selection to the first visible task after filtering", async () => {
    mockedFetch.mockResolvedValue(snapshot);

    render(<Home />);

    await screen.findByText("Task Digest");

    fireEvent.click(screen.getByRole("tab", { name: "Tasks" }));
    fireEvent.click(screen.getByRole("button", { name: /TSK-2 Task two Core P0 Done 2026-03-03 11:00/i }));
    expect(await screen.findByText("Task Detail · TSK-2")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Status filter"), { target: { value: "Todo" } });
    expect(await screen.findByText("Task Detail · TSK-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /TSK-1 Task one Ops P1 Todo 2026-03-03 10:00/i })).toHaveAttribute(
      "aria-pressed",
      "true",
    );

    fireEvent.change(screen.getByLabelText("Status filter"), { target: { value: "All" } });
    expect(await screen.findByText("Task Detail · TSK-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /TSK-1 Task one Ops P1 Todo 2026-03-03 10:00/i })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("fail-closes stale readonly event and audit selections to the first visible record after filtering", async () => {
    mockedFetch.mockResolvedValue(snapshot);

    render(<Home />);

    await screen.findByText("Task Digest");

    fireEvent.click(screen.getByRole("tab", { name: "Events" }));
    fireEvent.click(screen.getByRole("button", { name: /Info event/i }));
    expect(await screen.findByText("Event Detail · EVT-2")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Severity filter"), { target: { value: "Critical" } });
    expect(await screen.findByText("Event Detail · EVT-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Critical event/i })).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(screen.getByRole("tab", { name: "Audit" }));
    fireEvent.click(screen.getByRole("button", { name: /Endpoint ACL/i }));
    expect(await screen.findByText("Audit Detail · AUD-2")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Result filter"), { target: { value: "Warn" } });
    expect(await screen.findByText("Audit Detail · AUD-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Readonly controls/i })).toHaveAttribute("aria-pressed", "true");
  });

  it("supports arrow/home/end keyboard navigation across readonly dashboard tabs", async () => {
    mockedFetch.mockResolvedValue(snapshot);

    render(<Home />);

    await screen.findByText("Task Digest");

    const overviewTab = screen.getByRole("tab", { name: "Overview" });
    fireEvent.keyDown(overviewTab, { key: "ArrowRight" });
    await waitFor(() => expect(screen.getByRole("tab", { name: "Tasks" })).toHaveAttribute("aria-selected", "true"));

    const tasksTab = screen.getByRole("tab", { name: "Tasks" });
    fireEvent.keyDown(tasksTab, { key: "End" });
    await waitFor(() => expect(screen.getByRole("tab", { name: "Audit" })).toHaveAttribute("aria-selected", "true"));

    const auditTab = screen.getByRole("tab", { name: "Audit" });
    fireEvent.keyDown(auditTab, { key: "Home" });
    await waitFor(() => expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true"));
  });

  it("clears tabpanel busy state after readonly snapshot loads", async () => {
    mockedFetch.mockResolvedValue(snapshot);

    render(<Home />);

    await screen.findByText("Task Digest");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-busy", "false");
  });
});
