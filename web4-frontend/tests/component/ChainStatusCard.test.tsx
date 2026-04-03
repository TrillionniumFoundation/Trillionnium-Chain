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
    expect(alert).toHaveAttribute("id", "chain-status-unavailable");
    expect(screen.getByLabelText("chain-status")).toHaveAttribute("aria-describedby", "chain-status-unavailable");
    expect(screen.getByText("Network: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Latest block: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Finality: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Health: Unavailable")).toBeInTheDocument();
  });

  it("trims whitespace-only readonly fields before fail-closing and flags partial snapshots", () => {
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

    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(
      "Readonly chain snapshot is partial. Unavailable fields stay fail-closed until the adapter provides them.",
    );
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveAttribute("id", "chain-status-partial");
    expect(screen.getByLabelText("chain-status")).toHaveAttribute("aria-describedby", "chain-status-partial");
    expect(screen.getByText("Network: Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Latest block: 512")).toBeInTheDocument();
    expect(screen.getByText("Finality: finalizing")).toBeInTheDocument();
    expect(screen.getByText("Health: Unavailable")).toBeInTheDocument();
  });

  it("normalizes mixed-case readonly health values before validating fail-closed status", () => {
    render(
      <ChainStatusCard
        status={{
          network: "Trillionnium Localnet",
          latestBlock: 1024,
          finality: "2s",
          health: " Healthy ",
        } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
      />,
    );

    expect(screen.getByText("Network: Trillionnium Localnet")).toBeInTheDocument();
    expect(screen.getByText("Latest block: 1024")).toBeInTheDocument();
    expect(screen.getByText("Finality: 2s")).toBeInTheDocument();
    expect(screen.getByText("Health: healthy")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
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

  it("fail-closes non-finite or invalid readonly numeric fields to unavailable", () => {
    render(
      <>
        <ChainStatusCard
          status={{
            network: "Trillionnium Localnet",
            latestBlock: Number.NaN,
            finality: Number.POSITIVE_INFINITY as unknown as string,
            health: "healthy",
          } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
        />
        <ChainStatusCard
          status={{
            network: "Trillionnium Localnet",
            latestBlock: -1,
            finality: "2s",
            health: "healthy",
          } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
        />
        <ChainStatusCard
          status={{
            network: "Trillionnium Localnet",
            latestBlock: 12.5,
            finality: "2s",
            health: "healthy",
          } as unknown as Parameters<typeof ChainStatusCard>[0]["status"]}
        />
      </>,
    );

    const partialWarnings = screen.getAllByRole("status");
    expect(partialWarnings).toHaveLength(3);
    expect(partialWarnings[0]).toHaveTextContent(
      "Readonly chain snapshot is partial. Unavailable fields stay fail-closed until the adapter provides them.",
    );
    expect(screen.getAllByText("Latest block: Unavailable")).toHaveLength(3);
    expect(screen.getByText("Finality: Unavailable")).toBeInTheDocument();
    expect(screen.getAllByText("Health: healthy")).toHaveLength(3);
  });
});
