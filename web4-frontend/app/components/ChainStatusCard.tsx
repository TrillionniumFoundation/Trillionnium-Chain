import type { ChainStatus } from "@/lib/chain-status";

export function ChainStatusCard({ status }: { status: ChainStatus }) {
  return (
    <section aria-label="chain-status" className="w-full rounded-xl border border-zinc-200 p-4">
      <h2 className="text-lg font-semibold">Chain Status (Read-only)</h2>
      <ul className="mt-2 space-y-1 text-sm">
        <li>Network: {status.network}</li>
        <li>Latest block: {status.latestBlock}</li>
        <li>Finality: {status.finality}</li>
        <li>Health: {status.health}</li>
      </ul>
    </section>
  );
}
