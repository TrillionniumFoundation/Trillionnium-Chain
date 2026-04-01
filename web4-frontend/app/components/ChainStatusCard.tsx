import type { ChainStatus } from "@/lib/chain-status";

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
        <li>Network: {status.network}</li>
        <li>Latest block: {status.latestBlock}</li>
        <li>Finality: {status.finality}</li>
        <li>Health: {status.health}</li>
      </ul>
    </section>
  );
}
