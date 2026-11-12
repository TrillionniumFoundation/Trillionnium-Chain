#!/usr/bin/env python3
"""Plot the exact retained original pair; never modify or reconstruct raw data.

All displayed times use each phase's original traffic-epoch nanoseconds. Native
observer-local subspans and wall-clock timestamps are not mixed into this axis.
Every output is create-only. The input digest is pinned before JSON parsing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch, Rectangle

EXPECTED_REPORT_SHA256 = "4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d"
STEM = "original_pair_timing"
WINDOW_NS = 4_000_000_000
ACCEPTED = "#0072B2"
REFUSED = "#D55E00"
CONFIRMED = "#007A4D"


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value):
    return type(value) is int and value >= 0


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def write_new(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)


def extract(path):
    raw = path.read_bytes()
    require(sha(raw) == EXPECTED_REPORT_SHA256, "ORIGINAL_REPORT_SHA256_MISMATCH")
    report = json.loads(raw)
    require(report.get("schema") == "public-v3-signed-confirmation-pressure-v1", "PAIR_SCHEMA")
    require(type(report.get("phases")) is list and len(report["phases"]) == 2, "PAIR_PHASES")
    phases = []
    for index, phase in enumerate(report["phases"]):
        require(phase.get("mode") == ("attack-free-baseline", "from-zero-pressure")[index], "FIXED_PHASE_ORDER")
        require(type(phase.get("workers")) is int and phase["workers"] == (0, 16)[index], "WORKERS")
        require(type(phase.get("requested_window_ns")) is int and phase["requested_window_ns"] == WINDOW_NS,
                "ORIGINAL_FOUR_SECOND_WINDOW")
        release = phase.get("business_started_ns")
        require(integer(release) and release < WINDOW_NS, "BUSINESS_RELEASE")
        calls = phase.get("honest_submissions")
        require(type(calls) is list, "HONEST_SUBMISSIONS")
        accepted = [call for call in calls if call.get("status") == "ok"]
        require(all(integer(call.get("ended_ns")) for call in accepted), "ACK_ENDPOINT")
        intervals = []
        for replay_index, row in enumerate(phase["independent_history_page_replay"]):
            require(integer(row.get("replay_started_ns")) and integer(row.get("replay_ended_ns"))
                    and row["replay_started_ns"] <= row["replay_ended_ns"], "REPLAY_INTERVAL")
            require(type(row.get("replay_accepted")) is bool, "REPLAY_RESULT")
            require((row["replay_accepted"] and row.get("replay_error") is None)
                    or (not row["replay_accepted"] and type(row.get("replay_error")) is str),
                    "REPLAY_ERROR")
            intervals.append({"page_number_in_recorded_order": replay_index + 1,
                "history_call_index": row.get("history_call_index"),
                "replay_started_ns": row["replay_started_ns"], "replay_ended_ns": row["replay_ended_ns"],
                "replay_accepted": row["replay_accepted"], "replay_error": row["replay_error"],
                "pointer": f"/phases/{index}/independent_history_page_replay/{replay_index}"})
        gate, end, count = (phase.get(key) for key in (
            "client_confirmed_before_original_window_end", "confirmation_ended_ns", "client_confirmed_transactions"))
        require(type(gate) is bool and type(count) is int and count == int(gate), "NATIVE_GATE_COUNT")
        require(end is None or integer(end), "CONFIRMATION_ENDPOINT")
        observation = phase.get("independent_client_confirmation")
        if gate:
            require(integer(end) and end < WINDOW_NS and type(observation) is dict
                    and observation.get("confirmed") is True, "POSITIVE_NATIVE_ENDPOINT")
        else:
            # This exact original pair has no pressure confirmation endpoint.
            # A future pair with a late observation must use a separate version.
            require(end is None and observation is None, "UNEXPECTED_NONCONFIRMATION_OBSERVATION")
        phases.append({"phase_index": index, "mode": phase["mode"], "workers": phase["workers"],
            "requested_window_ns": WINDOW_NS, "business_started_ns": release,
            "successful_ack_count": len(accepted), "recorded_submission_count": len(calls),
            "last_successful_ack_ns": max((call["ended_ns"] for call in accepted), default=None),
            "successful_ack_endpoints_ns": [call["ended_ns"] for call in accepted],
            "independent_history_replays": intervals, "confirmation_ended_ns": end,
            "client_confirmed_before_original_window_end": gate, "client_confirmed_transactions": count,
            "phase_clock_origin": "original phase traffic epoch; separate epoch for each panel",
            "pointer": f"/phases/{index}"})
    return {"schema": "sp27-original-pair-timing-figure-data-v1",
            "source_report_sha256": sha(raw), "source_report_bytes": len(raw),
            "source_report_schema": report["schema"], "phases": phases,
            "raw_record_rewritten": False, "missing_confirmation_endpoint_imputed": False,
            "clock_domains_combined": False, "fixed_order_pair_repetitions": 1,
            "mechanism_status": "UNKNOWN", "causal_claim": False}


def make_figure(data):
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
        "axes.titlesize": 12, "axes.labelsize": 11, "svg.fonttype": "none",
        "svg.hashsalt": EXPECTED_REPORT_SHA256, "axes.spines.top": False,
        "axes.spines.right": False, "axes.spines.left": False})
    fig, axes = plt.subplots(2, 1, sharex=True, figsize=(10.5, 7.0))
    fig.subplots_adjust(left=0.165, right=0.97, top=0.86, bottom=0.17, hspace=0.43)
    fig.suptitle("Original fixed-order pair: independent business confirmation", x=0.165,
                 ha="left", y=0.975, fontsize=14, fontweight="bold")
    fig.text(0.165, 0.928, "One baseline followed by one pressure phase; descriptive timing evidence only.",
             fontsize=10, ha="left", color="#444444")
    for index, (ax, phase) in enumerate(zip(axes, data["phases"])):
        title = ("(a) No-pressure baseline — first; 1/1 confirmed" if index == 0 else
                 "(b) 16-worker pressure — second; 0/1 confirmed")
        ax.set_title(title, loc="left", pad=12, fontweight="bold")
        ax.set_ylim(-0.44, 3.58)
        ax.set_xlim(-0.05, 4.36)
        ax.set_yticks([3, 2, 1, 0], ["Business release", "Last successful ACK", "History page replay", "Independent\nconfirmation"])
        ax.tick_params(axis="y", length=0, pad=9, labelsize=9)
        ax.set_xticks([0, 1, 2, 3, 4])
        ax.tick_params(axis="x", labelbottom=True)
        ax.grid(axis="x", color="#E6E6E6", linewidth=0.7, zorder=0)
        ax.axvspan(4.0, 4.36, facecolor="#EEEEEE", zorder=0)
        ax.axvline(4.0, color="#303030", linestyle=(0, (4, 3)), linewidth=1.15, zorder=6)
        ax.text(4.025, 3.45, "T = 4 s", fontsize=9, ha="left", va="center", color="#303030")
        for y in (0, 1, 2, 3):
            ax.hlines(y, 0, 4.26, color="#DDDDDD", linewidth=0.65, zorder=0)
        release = phase["business_started_ns"] / 1e9
        ax.plot(release, 3, marker="v", markersize=7, color="#222222", zorder=7)
        ax.text(release + 0.10, 3.13, f"{release:.6f} s", fontsize=9, va="center")
        last_ack = phase["last_successful_ack_ns"]
        if last_ack is not None:
            at = last_ack / 1e9
            ax.plot(at, 2, marker="s", markersize=6, color="#222222", zorder=7)
            ax.text(at + 0.10, 2.13, f"{at:.6f} s  ({phase['successful_ack_count']} packet ACKs)",
                    fontsize=9, va="center")
        for interval in phase["independent_history_replays"]:
            start, end = interval["replay_started_ns"] / 1e9, interval["replay_ended_ns"] / 1e9
            accepted = interval["replay_accepted"]
            color = ACCEPTED if accepted else REFUSED
            rect = Rectangle((start, 0.80), end - start, 0.40, facecolor=color,
                             edgecolor="#222222", linewidth=0.55,
                             hatch=None if accepted else "///", zorder=4)
            ax.add_patch(rect)
            ax.text((start + end) / 2, 1, str(interval["page_number_in_recorded_order"]),
                    color="white", fontsize=9, fontweight="bold", ha="center", va="center", zorder=5)
            if not accepted:
                ax.annotate(f"Page {interval['page_number_in_recorded_order']} refused: {interval['replay_error']}\n"
                            f"{start:.6f}–{end:.6f} s (endpoint after T)",
                            xy=(end, 0.80), xycoords="data", xytext=(2.40, 0.19), textcoords="data",
                            ha="left", va="center", fontsize=8.4, color="#8A3600",
                            arrowprops={"arrowstyle": "-", "color": "#8A3600", "linewidth": 0.8}, zorder=8)
        confirmation = phase["confirmation_ended_ns"]
        if confirmation is not None:
            at = confirmation / 1e9
            ax.plot(at, 0, marker="D", markersize=7, color=CONFIRMED, zorder=7)
            ax.text(at + 0.10, 0.15, f"{at:.6f} s\nnative final gate = true", fontsize=9,
                    color=CONFIRMED, va="center")
        else:
            ax.text(0.10, -0.05, "No confirmation recorded (0/1)\nendpoint missing; native final gate = false",
                    fontsize=9, color="#555555", va="center")
    axes[-1].set_xlabel("Seconds from each phase's original traffic epoch", labelpad=10)
    legend = [Patch(facecolor=ACCEPTED, edgecolor="#222222", label="Replay accepted"),
              Patch(facecolor=REFUSED, edgecolor="#222222", hatch="///", label="Replay refused"),
              Line2D([], [], color=CONFIRMED, marker="D", linestyle="none", label="Recorded native confirmation")]
    fig.legend(handles=legend, loc="lower center", bbox_to_anchor=(0.56, 0.055), ncol=3,
               frameon=False, fontsize=9, handlelength=1.6, columnspacing=2.0)
    fig.text(0.165, 0.025, "Separate phase clocks; ACKs are not confirmation. Replay labels give recorded page order.",
             fontsize=8.5, color="#444444", ha="left")
    return fig


CAPTION = """# Original pair: observed timing and deadline failure

**Figure.** Each panel shows the original phase-relative business release,
last successful packet ACK, every retained independent History page-replay
interval, and the original four-second deadline. Blue intervals were accepted;
the hatched orange interval was refused. The no-pressure phase recorded an
independent confirmation endpoint at 2.704367684 s and its original final gate
was true (1/1). The 16-worker pressure phase recorded no independent confirmation
endpoint and its original final gate was false (0/1); no latency is assigned to
that missing endpoint. All seven packet submissions returned successful ACKs
in each phase, which are not business confirmations.

The pressure phase's fourth independent replay started at 3.877903180 s and
returned `PUBLIC_REQUEST_DEADLINE` at 4.066591277 s. Its complete retained
interval is drawn across the original deadline. This is an independent replay
deadline refusal, not a substituted Host-rejection result. The baseline retained
seven accepted replay intervals; pressure retained three accepted intervals and
this fourth refused interval.

Earlier timing already differs: the baseline business release was 0.000118889 s,
versus 0.078123550 s under pressure; the last successful ACKs were 0.201950838 s
and 1.270197394 s, respectively. The fourth replay's deadline refusal is not
identified as the first causal divergence or as a unique cause.

The panels have separate original traffic epochs; they are not one shared
wall-clock timeline. Native observer-local nested spans are not mixed into
these axes. Display labels round to six decimal places; the companion data JSON
retains the exact integer nanoseconds and raw JSON pointers.

This is one fixed-order baseline-then-pressure pair, not a randomized or
repeated causal experiment. The figure describes the recorded timing and failed
gate; it does not establish the attack mechanism, a causal resource bottleneck,
or a statistical effect. The mechanism remains **UNKNOWN**.

Source: unchanged `from-zero-native/confirmation/report.json`, SHA-256
`4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d`.
The plotting code verifies this digest before parsing and creates every output
exclusively. The receipt identifies the exact script, source, runtime and output
bytes.
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    outputs = {extension: args.out_dir / (STEM + extension) for extension in
               (".svg", ".png", ".data.json", ".caption.md", ".receipt.json")}
    require(not any(path.exists() for path in outputs.values()), "CREATE_ONLY_OUTPUT_ALREADY_EXISTS")
    data = extract(args.input)
    figure = make_figure(data)
    with outputs[".svg"].open("xb") as handle:
        figure.savefig(handle, format="svg", metadata={"Date": None,
            "Creator": "SP27-02 original-pair plotting script", "Description": "Descriptive fixed-order pair; no causal claim"})
    with outputs[".png"].open("xb") as handle:
        figure.savefig(handle, format="png", dpi=240, metadata={"Software": "SP27-02 original-pair plotting script"})
    plt.close(figure)
    write_new(outputs[".data.json"], json_bytes(data))
    write_new(outputs[".caption.md"], CAPTION.encode())
    receipt = {"schema": "sp27-original-pair-timing-figure-receipt-v1",
        "source_report": {"path": str(args.input.resolve()), "sha256": data["source_report_sha256"],
                          "bytes": data["source_report_bytes"]},
        "script_sha256": sha(Path(__file__).read_bytes()), "command_arguments": sys.argv,
        "python": sys.version, "matplotlib": matplotlib.__version__, "clock_domains_combined": False,
        "raw_record_rewritten": False, "new_native_experiments": 0, "causal_claim": False,
        "outputs": [{"file": path.name, "bytes": path.stat().st_size, "sha256": sha(path.read_bytes())}
                    for extension, path in outputs.items() if extension != ".receipt.json"]}
    write_new(outputs[".receipt.json"], json_bytes(receipt))
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
