import { describe, expect, it } from "vitest";
import { getMockChainStatus } from "@/lib/chain-status";

describe("getMockChainStatus", () => {
  it("returns deterministic readonly fixture data", () => {
    const status = getMockChainStatus();
    expect(status.network).toBe("Trillionnium Localnet");
    expect(status.latestBlock).toBeGreaterThan(0);
    expect(status.health).toBe("healthy");
  });
});
