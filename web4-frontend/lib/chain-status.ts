import chainStatusFixture from "./fixtures/chain-status.json";

export type ChainStatus = {
  network: string;
  latestBlock: number;
  finality: string;
  health: "healthy" | "degraded" | "offline";
};

export function getMockChainStatus(): ChainStatus {
  return chainStatusFixture as ChainStatus;
}
