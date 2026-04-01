import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChainStatusCard } from "@/app/components/ChainStatusCard";

describe("ChainStatusCard", () => {
  it("renders readonly chain fields with fail-closed copy", () => {
    render(
      <ChainStatusCard
        status={{
          network: "Trillionnium Localnet",
          latestBlock: 256,
          finality: "2s",
          health: "healthy",
        }}
      />,
    );

    expect(screen.getByRole("heading", { name: /chain status/i })).toBeInTheDocument();
    expect(screen.getByText(/snapshot-only telemetry/i)).toBeInTheDocument();
    expect(screen.getByText("Fail closed")).toBeInTheDocument();
    expect(screen.getByText("Network: Trillionnium Localnet")).toBeInTheDocument();
    expect(screen.getByText("Latest block: 256")).toBeInTheDocument();
  });
});
