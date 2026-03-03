"use client";

import { useMemo, useState } from "react";
import { audits, events, kpis, tasks, type Health } from "./dashboard-data";

type Tab = "Overview" | "Tasks" | "Events" | "Audit";

const tabs: Tab[] = ["Overview", "Tasks", "Events", "Audit"];

const healthClassMap: Record<Health, string> = {
  healthy: "bg-emerald-100 text-emerald-700",
  degraded: "bg-amber-100 text-amber-700",
  risk: "bg-rose-100 text-rose-700",
};

function StatusChip({ text, tone }: { text: string; tone: string }) {
  return <span className={`rounded-full px-2 py-1 text-xs font-medium ${tone}`}>{text}</span>;
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<Tab>("Overview");

  const overviewDigest = useMemo(
    () => ({
      todoTasks: tasks.filter((task) => task.status !== "Done").length,
      criticalEvents: events.filter((event) => event.severity === "Critical").length,
      auditWarnings: audits.filter((audit) => audit.result !== "Pass").length,
    }),
    [],
  );

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <main className="mx-auto w-full max-w-6xl px-4 py-10 md:px-8">
        <header className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-sm text-slate-500">Trillionnium Chain · Readonly Business Board</p>
            <h1 className="text-3xl font-semibold tracking-tight">Operations Dashboard</h1>
          </div>
          <p className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-600">
            Data mode: readonly snapshots · No write-paths enabled
          </p>
        </header>

        <nav className="mb-8 flex flex-wrap gap-2">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
                activeTab === tab
                  ? "bg-slate-900 text-white"
                  : "bg-white text-slate-700 ring-1 ring-slate-200 hover:bg-slate-100"
              }`}
            >
              {tab}
            </button>
          ))}
        </nav>

        {activeTab === "Overview" && (
          <section className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {kpis.map((kpi) => (
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
                {tasks.map((task) => (
                  <tr key={task.id} className="border-t border-slate-100">
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
        )}

        {activeTab === "Events" && (
          <section className="space-y-3">
            {events.map((event) => (
              <article key={event.id} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
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
                <p className="mt-2 text-sm font-semibold text-slate-700">{event.id} · {event.category}</p>
                <p className="mt-1 text-slate-700">{event.summary}</p>
              </article>
            ))}
          </section>
        )}

        {activeTab === "Audit" && (
          <section className="grid gap-3">
            {audits.map((audit) => (
              <article key={audit.id} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
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
                <p className="mt-1 text-sm text-slate-500">Reviewer: {audit.reviewer} · {audit.reviewedAt}</p>
              </article>
            ))}
          </section>
        )}
      </main>
    </div>
  );
}
