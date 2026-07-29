"use client";

import { type KeyboardEvent, useEffect, useMemo, useState } from "react";
import { fetchDashboardSnapshot } from "@/lib/dashboard/source";
import type { DashboardSnapshot } from "@/lib/dashboard/adapter";

type Tab = "Overview" | "Tasks" | "Events" | "Audit";
const tabs: Tab[] = ["Overview", "Tasks", "Events", "Audit"];

type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; data: DashboardSnapshot };

type DashboardMode = "ok" | "empty" | "error" | "mock";

function normalizeHealth(health: unknown): DashboardSnapshot["kpis"][number]["health"] {
  return health === "healthy" || health === "degraded" || health === "risk" ? health : "risk";
}

function failClosedText(value: string | null | undefined, fallback: string) {
  if (typeof value !== "string") {
    return fallback;
  }

  const normalized = value.trim();
  return normalized === "" ? fallback : normalized;
}

function normalizeSnapshot(snapshot: DashboardSnapshot): DashboardSnapshot {
  return {
    ...snapshot,
    kpis: Array.isArray(snapshot.kpis)
      ? snapshot.kpis.map((kpi, index) => ({
          ...kpi,
          label: failClosedText(kpi.label, `Metric ${index + 1}`),
          value: failClosedText(kpi.value, "Unavailable"),
          delta: failClosedText(kpi.delta, "Unavailable"),
          health: normalizeHealth(kpi.health),
        }))
      : [],
    tasks: Array.isArray(snapshot.tasks) ? snapshot.tasks : [],
    events: Array.isArray(snapshot.events) ? snapshot.events : [],
    audits: Array.isArray(snapshot.audits) ? snapshot.audits : [],
  };
}

function normalizeDashboardMode(value: string | null): DashboardMode {
  const normalized = value?.replace(/[\u200B\u200C\u200D\u2060\u2063\uFEFF]/g, "").trim();
  return normalized === "empty" || normalized === "error" || normalized === "mock" ? normalized : "ok";
}

const healthClassMap: Record<DashboardSnapshot["kpis"][number]["health"], string> = {
  healthy: "bg-emerald-100 text-emerald-700",
  degraded: "bg-amber-100 text-amber-700",
  risk: "bg-rose-100 text-rose-700",
};

function StatusChip({ text, tone }: { text: string; tone: string }) {
  return <span className={`rounded-full px-2 py-1 text-xs font-medium ${tone}`}>{text}</span>;
}

function EmptyState({
  title,
  detail,
  tone = "neutral",
  live = "off",
}: {
  title: string;
  detail: string;
  tone?: "neutral" | "error";
  live?: "off" | "polite" | "assertive";
}) {
  return (
    <article
      role={tone === "error" ? "alert" : live === "off" ? undefined : "status"}
      aria-live={live}
      className={`rounded-xl border border-dashed p-8 text-center text-slate-600 ${
        tone === "error" ? "border-rose-300 bg-rose-50" : "border-slate-300 bg-slate-50"
      }`}
    >
      <p className="text-base font-semibold text-slate-700">{title}</p>
      <p className="mt-2 text-sm">{detail}</p>
    </article>
  );
}

function onSelectableKeyDown(event: KeyboardEvent<HTMLElement>, onSelect: () => void) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    onSelect();
  }
}

function onTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, activeTab: Tab, setActiveTab: (tab: Tab) => void) {
  const currentIndex = tabs.indexOf(activeTab);

  if (currentIndex === -1) {
    return;
  }

  let nextTab: Tab | null = null;

  if (event.key === "ArrowRight") {
    nextTab = tabs[(currentIndex + 1) % tabs.length];
  } else if (event.key === "ArrowLeft") {
    nextTab = tabs[(currentIndex - 1 + tabs.length) % tabs.length];
  } else if (event.key === "Home") {
    nextTab = tabs[0];
  } else if (event.key === "End") {
    nextTab = tabs[tabs.length - 1];
  }

  if (!nextTab) {
    return;
  }

  event.preventDefault();
  setActiveTab(nextTab);
  requestAnimationFrame(() => {
    document.getElementById(`dashboard-tab-${nextTab.toLowerCase()}`)?.focus();
  });
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>("Overview");
  const [taskStatusFilter, setTaskStatusFilter] = useState<"All" | DashboardSnapshot["tasks"][number]["status"]>("All");
  const [eventSeverityFilter, setEventSeverityFilter] = useState<"All" | DashboardSnapshot["events"][number]["severity"]>("All");
  const [auditResultFilter, setAuditResultFilter] = useState<"All" | DashboardSnapshot["audits"][number]["result"]>("All");
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedAuditId, setSelectedAuditId] = useState<string | null>(null);
  const [loadState, setLoadState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const normalizedMode = normalizeDashboardMode(params.get("mode"));

    fetchDashboardSnapshot({
      mode: normalizedMode,
    })
      .then((data) => {
        const normalizedData = normalizeSnapshot(data);
        setLoadState({ status: "ready", data: normalizedData });
        setSelectedTaskId(normalizedData.tasks[0]?.id ?? null);
        setSelectedEventId(normalizedData.events[0]?.id ?? null);
        setSelectedAuditId(normalizedData.audits[0]?.id ?? null);
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : "Unknown dashboard loading failure";
        setLoadState({ status: "error", message });
      });
  }, []);

  const overviewDigest = useMemo(() => {
    if (loadState.status !== "ready") {
      return { todoTasks: 0, criticalEvents: 0, auditWarnings: 0 };
    }

    return {
      todoTasks: loadState.data.tasks.filter((task) => task.status !== "Done").length,
      criticalEvents: loadState.data.events.filter((event) => event.severity === "Critical").length,
      auditWarnings: loadState.data.audits.filter((audit) => audit.result !== "Pass").length,
    };
  }, [loadState]);

  const filteredTasks = useMemo(() => {
    if (loadState.status !== "ready") return [];
    return loadState.data.tasks.filter((task) => taskStatusFilter === "All" || task.status === taskStatusFilter);
  }, [loadState, taskStatusFilter]);

  const filteredEvents = useMemo(() => {
    if (loadState.status !== "ready") return [];
    return loadState.data.events.filter((event) => eventSeverityFilter === "All" || event.severity === eventSeverityFilter);
  }, [loadState, eventSeverityFilter]);

  const filteredAudits = useMemo(() => {
    if (loadState.status !== "ready") return [];
    return loadState.data.audits.filter((audit) => auditResultFilter === "All" || audit.result === auditResultFilter);
  }, [loadState, auditResultFilter]);

  const selectedTask = filteredTasks.find((task) => task.id === selectedTaskId) ?? filteredTasks[0];
  const selectedEvent = filteredEvents.find((event) => event.id === selectedEventId) ?? filteredEvents[0];
  const selectedAudit = filteredAudits.find((audit) => audit.id === selectedAuditId) ?? filteredAudits[0];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <main className="mx-auto w-full max-w-6xl px-4 py-10 md:px-8">
        <header className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-sm text-slate-500">Trillionnium Chain · Readonly Business Board</p>
            <h1 className="text-3xl font-semibold tracking-tight">Operations Dashboard</h1>
          </div>
          <p className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-600">
            Data mode: readonly API client (use ?mode=mock for readonly fallback) · No write-paths enabled
          </p>
        </header>

        <nav role="tablist" aria-label="Dashboard sections" className="mb-8 flex flex-wrap gap-2">
          {tabs.map((tab) => {
            const isActive = activeTab === tab;
            const tabId = `dashboard-tab-${tab.toLowerCase()}`;
            const panelId = `dashboard-panel-${tab.toLowerCase()}`;

            return (
              <button
                key={tab}
                id={tabId}
                role="tab"
                type="button"
                aria-selected={isActive}
                aria-controls={panelId}
                tabIndex={isActive ? 0 : -1}
                onClick={() => setActiveTab(tab)}
                onKeyDown={(event) => onTabKeyDown(event, activeTab, setActiveTab)}
                className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                  isActive
                    ? "bg-slate-900 text-white"
                    : "bg-white text-slate-700 ring-1 ring-slate-200 hover:bg-slate-100"
                }`}
              >
                {tab}
              </button>
            );
          })}
        </nav>

        <div
          id={`dashboard-panel-${activeTab.toLowerCase()}`}
          role="tabpanel"
          aria-labelledby={`dashboard-tab-${activeTab.toLowerCase()}`}
          aria-busy={loadState.status === "loading"}
        >

        {loadState.status === "loading" && (
          <EmptyState
            title="Loading dashboard snapshot"
            detail="Fetching readonly adapter data and normalizing schema..."
            live="polite"
          />
        )}

        {loadState.status === "error" && (
          <EmptyState
            title="Failed to load dashboard"
            detail={`Adapter source error: ${loadState.message}`}
            tone="error"
            live="assertive"
          />
        )}

        {loadState.status === "ready" && (
          <>
            {activeTab === "Overview" && (
              <section className="space-y-6">
                {loadState.data.kpis.length === 0 ? (
                  <EmptyState
                    title="No overview KPIs available"
                    detail="Readonly dashboard metrics are unavailable for this snapshot. Verify the adapter payload before trusting the overview."
                  />
                ) : (
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    {loadState.data.kpis.map((kpi) => (
                      <article key={kpi.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                        <p className="text-sm text-slate-500">{kpi.label}</p>
                        <div className="mt-2 flex items-center justify-between gap-2">
                          <p className="text-2xl font-semibold">{kpi.value}</p>
                          <StatusChip text={kpi.health} tone={healthClassMap[kpi.health]} />
                        </div>
                        <p className="mt-2 text-sm text-slate-500">Δ {kpi.delta} / 24h</p>
                      </article>
                    ))}
                  </div>
                )}

                <div className="grid gap-4 lg:grid-cols-3">
                  <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <h2 className="text-lg font-semibold">Task Digest</h2>
                    <p className="mt-2 text-sm text-slate-600">Open execution items: {overviewDigest.todoTasks}</p>
                  </article>
                  <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <h2 className="text-lg font-semibold">Event Digest</h2>
                    <p className="mt-2 text-sm text-slate-600">Critical events in latest window: {overviewDigest.criticalEvents}</p>
                  </article>
                  <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <h2 className="text-lg font-semibold">Audit Digest</h2>
                    <p className="mt-2 text-sm text-slate-600">Non-pass controls to review: {overviewDigest.auditWarnings}</p>
                  </article>
                </div>
              </section>
            )}

            {activeTab === "Tasks" && (
              <section className="space-y-4">
                <div className="flex items-center justify-between gap-2">
                  <label className="text-sm text-slate-600">
                    Status filter
                    <select
                      value={taskStatusFilter}
                      onChange={(event) => {
                        setTaskStatusFilter(event.target.value as typeof taskStatusFilter);
                        setSelectedTaskId(null);
                      }}
                      className="ml-2 rounded-md border border-slate-300 px-2 py-1 text-sm"
                    >
                      <option>All</option>
                      <option>Todo</option>
                      <option>In Progress</option>
                      <option>Blocked</option>
                      <option>Done</option>
                    </select>
                  </label>
                </div>

                {filteredTasks.length === 0 ? (
                  <EmptyState
                    title="No tasks match current filter"
                    detail="Readonly task snapshot has no entries for this filter. Try another status filter or switch to All."
                    live="polite"
                  />
                ) : (
                  <>
                    <section className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
                      <table className="w-full min-w-[680px] text-left text-sm">
                        <thead className="bg-slate-100 text-slate-600">
                          <tr>
                            <th className="px-4 py-3 font-medium">ID</th>
                            <th className="px-4 py-3 font-medium">Title</th>
                            <th className="px-4 py-3 font-medium">Owner</th>
                            <th className="px-4 py-3 font-medium">Priority</th>
                            <th className="px-4 py-3 font-medium">Status</th>
                            <th className="px-4 py-3 font-medium">Updated</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredTasks.map((task) => (
                            <tr
                              key={task.id}
                              role="button"
                              tabIndex={0}
                              aria-pressed={selectedTask?.id === task.id}
                              onClick={() => setSelectedTaskId(task.id)}
                              onKeyDown={(event) => onSelectableKeyDown(event, () => setSelectedTaskId(task.id))}
                              className={`cursor-pointer border-t border-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 ${selectedTask?.id === task.id ? "bg-slate-50" : ""}`}
                            >
                              <td className="px-4 py-3 font-medium">{task.id}</td>
                              <td className="px-4 py-3">{task.title}</td>
                              <td className="px-4 py-3">{task.owner}</td>
                              <td className="px-4 py-3">{task.priority}</td>
                              <td className="px-4 py-3">{task.status}</td>
                              <td className="px-4 py-3 text-slate-500">{task.updatedAt}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </section>

                    {selectedTask && (
                      <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                        <h3 className="text-base font-semibold">Task Detail · {selectedTask.id}</h3>
                        <p className="mt-2 text-sm text-slate-700">
                          {failClosedText(selectedTask.description, "Readonly task detail is unavailable for this snapshot.")}
                        </p>
                      </article>
                    )}
                  </>
                )}
              </section>
            )}

            {activeTab === "Events" && (
              <section className="space-y-4">
                <label className="text-sm text-slate-600">
                  Severity filter
                  <select
                    value={eventSeverityFilter}
                    onChange={(event) => {
                      setEventSeverityFilter(event.target.value as typeof eventSeverityFilter);
                      setSelectedEventId(null);
                    }}
                    className="ml-2 rounded-md border border-slate-300 px-2 py-1 text-sm"
                  >
                    <option>All</option>
                    <option>Info</option>
                    <option>Warning</option>
                    <option>Critical</option>
                  </select>
                </label>

                {filteredEvents.length === 0 ? (
                  <EmptyState
                    title="No events found"
                    detail="Readonly event snapshot has no matching records for this filter."
                    live="polite"
                  />
                ) : (
                  <>
                    {filteredEvents.map((event) => (
                      <article
                        key={event.id}
                        role="button"
                        tabIndex={0}
                        aria-pressed={selectedEvent?.id === event.id}
                        onClick={() => setSelectedEventId(event.id)}
                        onKeyDown={(eventKey) => onSelectableKeyDown(eventKey, () => setSelectedEventId(event.id))}
                        className={`cursor-pointer rounded-xl border border-slate-200 bg-white p-4 shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 ${
                          selectedEvent?.id === event.id ? "ring-2 ring-slate-300" : ""
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="text-sm text-slate-500">{event.time}</p>
                          <StatusChip
                            text={event.severity}
                            tone={
                              event.severity === "Critical"
                                ? "bg-rose-100 text-rose-700"
                                : event.severity === "Warning"
                                  ? "bg-amber-100 text-amber-700"
                                  : "bg-sky-100 text-sky-700"
                            }
                          />
                        </div>
                        <p className="mt-2 text-sm font-semibold text-slate-700">
                          {event.id} · {event.category}
                        </p>
                        <p className="mt-1 text-slate-700">{event.summary}</p>
                      </article>
                    ))}

                    {selectedEvent && (
                      <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                        <h3 className="text-base font-semibold">Event Detail · {selectedEvent.id}</h3>
                        <p className="mt-2 text-sm text-slate-700">
                          {failClosedText(selectedEvent.details, "Readonly event detail is unavailable for this snapshot.")}
                        </p>
                      </article>
                    )}
                  </>
                )}
              </section>
            )}

            {activeTab === "Audit" && (
              <section className="space-y-4">
                <label className="text-sm text-slate-600">
                  Result filter
                  <select
                    value={auditResultFilter}
                    onChange={(event) => {
                      setAuditResultFilter(event.target.value as typeof auditResultFilter);
                      setSelectedAuditId(null);
                    }}
                    className="ml-2 rounded-md border border-slate-300 px-2 py-1 text-sm"
                  >
                    <option>All</option>
                    <option>Pass</option>
                    <option>Warn</option>
                    <option>Fail</option>
                  </select>
                </label>

                {filteredAudits.length === 0 ? (
                  <EmptyState
                    title="No audit controls found"
                    detail="Readonly audit snapshot has no entries for this result filter."
                    live="polite"
                  />
                ) : (
                  <>
                    <section className="grid gap-3">
                      {filteredAudits.map((audit) => (
                        <article
                          key={audit.id}
                          role="button"
                          tabIndex={0}
                          aria-pressed={selectedAudit?.id === audit.id}
                          onClick={() => setSelectedAuditId(audit.id)}
                          onKeyDown={(eventKey) => onSelectableKeyDown(eventKey, () => setSelectedAuditId(audit.id))}
                          className={`cursor-pointer rounded-xl border border-slate-200 bg-white p-4 shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 ${
                            selectedAudit?.id === audit.id ? "ring-2 ring-slate-300" : ""
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="font-semibold text-slate-700">{audit.id}</p>
                            <StatusChip
                              text={audit.result}
                              tone={
                                audit.result === "Pass"
                                  ? "bg-emerald-100 text-emerald-700"
                                  : audit.result === "Warn"
                                    ? "bg-amber-100 text-amber-700"
                                    : "bg-rose-100 text-rose-700"
                              }
                            />
                          </div>
                          <p className="mt-2">{audit.control}</p>
                          <p className="mt-1 text-sm text-slate-500">
                            Reviewer: {audit.reviewer} · {audit.reviewedAt}
                          </p>
                        </article>
                      ))}
                    </section>

                    {selectedAudit && (
                      <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                        <h3 className="text-base font-semibold">Audit Detail · {selectedAudit.id}</h3>
                        <p className="mt-2 text-sm text-slate-700">
                          {failClosedText(selectedAudit.notes, "Readonly audit detail is unavailable for this snapshot.")}
                        </p>
                      </article>
                    )}
                  </>
                )}
              </section>
            )}
          </>
        )}
        </div>
      </main>
    </div>
  );
}
