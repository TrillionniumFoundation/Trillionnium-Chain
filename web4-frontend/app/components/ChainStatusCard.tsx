import type { ChainStatus } from "@/lib/chain-status";

const knownHealthStates = new Set<ChainStatus["health"]>(["healthy", "degraded", "offline"]);

function failClosedValue(value: string | number | null | undefined, fallback = "Unavailable") {
  if (value === null || value === undefined) {
    return fallback;
  }

  if (typeof value === "string") {
    const normalized = value.trim();
    return normalized === "" ? fallback : normalized;
  }

  if (!Number.isFinite(value)) {
    return fallback;
  }

  return String(value);
}

function failClosedBlockHeight(value: number | null | undefined, fallback = "Unavailable") {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    return fallback;
  }

  return String(value);
}

function failClosedHealth(value: ChainStatus["health"] | string | null | undefined) {
  const normalized = failClosedValue(value);
  const canonical = typeof normalized === "string" ? normalized.toLowerCase() : normalized;
  return knownHealthStates.has(canonical as ChainStatus["health"]) ? canonical : "Unavailable";
}

export function ChainStatusCard({ status }: { status: ChainStatus }) {
  const network = failClosedValue(status.network);
  const latestBlock = failClosedBlockHeight(status.latestBlock);
  const finality = failClosedValue(status.finality);
  const health = failClosedHealth(status.health);
  const normalizedValues = [network, latestBlock, finality, health];
  const unavailableCount = normalizedValues.filter((value) => value === "Unavailable").length;
  const isSnapshotUnavailable = unavailableCount === normalizedValues.length;
  const isSnapshotPartial = unavailableCount > 0 && !isSnapshotUnavailable;
  const alertId = isSnapshotUnavailable
    ? "chain-status-unavailable"
    : isSnapshotPartial
      ? "chain-status-partial"
      : undefined;

  return (
    <section
      aria-label="chain-status"
      aria-describedby={alertId}
      className="w-full rounded-xl border border-zinc-200 p-4"
    >
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
      {isSnapshotUnavailable && (
        <p
          id="chain-status-unavailable"
          role="alert"
          aria-live="assertive"
          className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800"
        >
          Readonly chain snapshot is unavailable. Verify the adapter payload before trusting this card.
        </p>
      )}
      {isSnapshotPartial && (
        <p
          id="chain-status-partial"
          role="status"
          aria-live="polite"
          className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800"
        >
          Readonly chain snapshot is partial. Unavailable fields stay fail-closed until the adapter provides them.
        </p>
      )}
      <ul className="mt-3 space-y-1 text-sm">
        <li>Network: {network}</li>
        <li>Latest block: {latestBlock}</li>
        <li>Finality: {finality}</li>
        <li>Health: {health}</li>
      </ul>
    </section>
  );
}
