import type { ChainStatus } from "@/lib/chain-status";

function failClosedValue(value: string | number | null | undefined, fallback = "Unavailable") {
  if (value === null || value === undefined) {
    return fallback;
  }

  if (typeof value === "string") {
    const normalized = value.trim();
    return normalized === "" ? fallback : normalized;
  }

  return String(value);
}

export function ChainStatusCard({ status }: { status: ChainStatus }) {
  return (
    <section aria-label="chain-status" className="w-full rounded-xl border border-zinc-200 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Chain Status (Read-only)</h2>
          <p className="mt-1 text-sm text-zinc-600">
            Snapshot-only telemetry. Controls stay disabled until a trusted write path is enabled.
          </p>
        </div>
        <span className="rounded-full bg-zinc-100 px-2 py-1 text-xs font-medium text-zinc-700">
          Fail closed
        </span>
      </div>
      <ul className="mt-3 space-y-1 text-sm">
        <li>Network: {failClosedValue(status.network)}</li>
        <li>Latest block: {failClosedValue(status.latestBlock)}</li>
        <li>Finality: {failClosedValue(status.finality)}</li>
        <li>Health: {failClosedValue(status.health)}</li>
      </ul>
    </section>
  );
}
