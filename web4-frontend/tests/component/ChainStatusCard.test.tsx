import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ChainStatusCard } from "@/app/components/ChainStatusCard";

afterEach(() => {
  cleanup();
});

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

  it("fail-closes missing readonly fields to unavailable copy", () => {
    render(
      <ChainStatusCard
        status={{
          network: "",
          latestBlock: undefined,
          finality: "",
          health: undefined,
        } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
      />,
    );

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(
      "Readonly chain snapshot is unavailable. Verify the adapter payload before trusting this card.",
    );
    expect(alert).toHaveAttribute("aria-live", "assertive");
    expect(screen.getByText("Network: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Latest block: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Finality: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Health: Unavailable")).toBeInTheDocument();
  });

  it("trims whitespace-only readonly fields before fail-closing", () => {
    render(
      <ChainStatusCard
        status={{
          network: "   ",
          latestBlock: 512,
          finality: "  finalizing ",
          health: "\n\t",
        } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
      />,
    );

    expect(screen.getByText("Network: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Latest block: 512")).toBeInTheDocument();
    expect(screen.getByText("Finality: finalizing")).toBeInTheDocument();
    expect(screen.getByText("Health: Unavailable")).toBeInTheDocument();
  });

  it("fail-closes unknown readonly health values to unavailable", () => {
    render(
      <ChainStatusCard
        status={{
          network: "Trillionnium Localnet",
          latestBlock: 1024,
          finality: "2s",
          health: "recovering",
        } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
      />,
    );

    expect(screen.getByText("Network: Trillionnium Localnet")).toBeInTheDocument();
    expect(screen.getByText("Latest block: 1024")).toBeInTheDocument();
    expect(screen.getByText("Finality: 2s")).toBeInTheDocument();
    expect(screen.getByText("Health: Unavailable")).toBeInTheDocument();
  });
});
