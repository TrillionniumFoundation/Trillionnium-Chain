#!/usr/bin/env python3
"""Collect and hard-assert CometBFT safety evidence across local nodes.

CometBFT's block H header commits the application hash returned after block
H-1.  Consequently, the post-state hash for a non-terminal height H is read
from the header at H+1.  At the common terminal height there is no H+1 block,
so the post-state hash is read from ABCI Info, whose last_block_app_hash is
persisted by Commit for last_block_height.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any
from urllib.parse import urlencode
from urllib.request import urlopen


SCHEMA = "trnm_cometbft_safety_evidence_v1"
HEX_HASH = re.compile(r"^[0-9a-fA-F]{64}$")
NODE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class EvidenceError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Assert one block ID per common height and terminal ABCI/local "
            "application-state convergence."
        )
    )
    parser.add_argument(
        "--node",
        action="append",
        nargs=3,
        metavar=("NAME", "RPC_URL", "STATE_PATH"),
        required=True,
        help="node name, local CometBFT RPC base URL, and application state path",
    )
    parser.add_argument(
        "--history-node",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "node expected to retain every block from --start-height; repeat "
            "for each archival validator (defaults to every --node)"
        ),
    )
    parser.add_argument("--expected-chain-id", required=True)
    parser.add_argument("--start-height", type=int, default=1)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--tsv-out", type=Path, required=True)
    parser.add_argument("--rpc-timeout-seconds", type=float, default=3.0)
    parser.add_argument("--rpc-attempts", type=int, default=5)
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def normalize_hash(value: Any, context: str, *, allow_empty: bool = False) -> str:
    require(isinstance(value, str), f"{context}: hash is not a string")
    encoded = value.strip()
    if not encoded:
        require(allow_empty, f"{context}: hash is empty")
        return ""
    if HEX_HASH.fullmatch(encoded):
        return encoded.lower()
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceError(f"{context}: hash is neither SHA-256 hex nor base64") from exc
    require(len(decoded) == 32, f"{context}: decoded hash is not 32 bytes")
    return decoded.hex()


def parse_height(value: Any, context: str) -> int:
    try:
        height = int(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"{context}: invalid height {value!r}") from exc
    require(height >= 0, f"{context}: negative height {height}")
    return height


def rpc_get(
    rpc_url: str,
    endpoint: str,
    params: dict[str, Any],
    *,
    timeout_seconds: float,
    attempts: int,
) -> dict[str, Any]:
    url = f"{rpc_url.rstrip('/')}/{endpoint.lstrip('/')}"
    if params:
        url = f"{url}?{urlencode(params)}"
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urlopen(url, timeout=timeout_seconds) as response:
                payload = json.load(response)
            require(isinstance(payload, dict), f"{url}: response is not an object")
            require("error" not in payload, f"{url}: RPC error {payload.get('error')!r}")
            result = payload.get("result")
            require(isinstance(result, dict), f"{url}: missing result object")
            return result
        except Exception as exc:  # The final exception is reported with its RPC URL.
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.1)
    raise EvidenceError(f"{url}: RPC failed after {attempts} attempts: {last_error}")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def emit_evidence(
    args: argparse.Namespace,
    evidence: dict[str, Any],
    height_records: list[dict[str, Any]],
) -> None:
    atomic_write(
        args.json_out,
        json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
    )
    rows = [
        "\t".join(
            (
                "height",
                "chain_id",
                "block_id_hash",
                "prior_state_app_hash",
                "post_state_app_hash",
                "post_state_source",
                "history_nodes",
            )
        )
    ]
    for record in height_records:
        rows.append(
            "\t".join(
                (
                    str(record["height"]),
                    record["chain_id"],
                    record["block_id_hash"],
                    record["prior_state_app_hash"],
                    record["post_state_app_hash"],
                    record["post_state_source"],
                    ",".join(record["history_nodes"]),
                )
            )
        )
    atomic_write(args.tsv_out, "\n".join(rows) + "\n")


def main() -> int:
    args = parse_args()
    evidence: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "FAIL",
        "expected_chain_id": args.expected_chain_id,
        "start_height": args.start_height,
        "history_nodes": [],
        "nodes": [],
        "heights": [],
        "errors": [],
    }
    height_records: list[dict[str, Any]] = evidence["heights"]

    try:
        require(args.start_height >= 1, "--start-height must be at least 1")
        require(args.rpc_attempts >= 1, "--rpc-attempts must be at least 1")
        require(args.rpc_timeout_seconds > 0, "--rpc-timeout-seconds must be positive")

        node_specs: dict[str, tuple[str, Path]] = {}
        for name, rpc_url, state_path in args.node:
            require(NODE_NAME.fullmatch(name) is not None, f"invalid node name {name!r}")
            require(name not in node_specs, f"duplicate node name {name!r}")
            node_specs[name] = (rpc_url.rstrip("/"), Path(state_path))
        require(len(node_specs) >= 2, "at least two nodes are required")

        history_names = args.history_node or sorted(node_specs)
        require(
            len(history_names) == len(set(history_names)),
            "duplicate --history-node value",
        )
        for name in history_names:
            require(name in node_specs, f"unknown history node {name!r}")
        require(len(history_names) >= 2, "at least two history nodes are required")
        evidence["history_nodes"] = history_names

        terminal: dict[str, dict[str, Any]] = {}
        for name in sorted(node_specs):
            rpc_url, state_path = node_specs[name]
            status = rpc_get(
                rpc_url,
                "status",
                {},
                timeout_seconds=args.rpc_timeout_seconds,
                attempts=args.rpc_attempts,
            )
            sync_info = status.get("sync_info")
            node_info = status.get("node_info")
            require(isinstance(sync_info, dict), f"{name}: missing status.sync_info")
            require(isinstance(node_info, dict), f"{name}: missing status.node_info")
            latest_height = parse_height(
                sync_info.get("latest_block_height"),
                f"{name}: status latest_block_height",
            )
            status_chain_id = node_info.get("network")
            require(
                status_chain_id == args.expected_chain_id,
                f"{name}: status chain ID {status_chain_id!r} != "
                f"{args.expected_chain_id!r}",
            )

            info = rpc_get(
                rpc_url,
                "abci_info",
                {},
                timeout_seconds=args.rpc_timeout_seconds,
                attempts=args.rpc_attempts,
            )
            response = info.get("response")
            require(isinstance(response, dict), f"{name}: missing abci_info.response")
            abci_height = parse_height(
                response.get("last_block_height"),
                f"{name}: ABCI last_block_height",
            )
            abci_hash = normalize_hash(
                response.get("last_block_app_hash"),
                f"{name}: ABCI last_block_app_hash",
            )

            require(state_path.is_file(), f"{name}: missing local state {state_path}")
            try:
                local_state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise EvidenceError(f"{name}: cannot read local state {state_path}: {exc}") from exc
            require(isinstance(local_state, dict), f"{name}: local state is not an object")
            local_height = parse_height(
                local_state.get("height"),
                f"{name}: local state height",
            )
            local_hash = normalize_hash(
                local_state.get("app_hash_hex"),
                f"{name}: local app_hash_hex",
            )

            require(
                latest_height == abci_height == local_height,
                f"{name}: terminal height mismatch "
                f"comet={latest_height} abci={abci_height} local={local_height}",
            )
            require(
                abci_hash == local_hash,
                f"{name}: terminal app hash mismatch abci={abci_hash} local={local_hash}",
            )

            observation = {
                "name": name,
                "rpc_url": rpc_url,
                "state_path": str(state_path),
                "latest_block_height": latest_height,
                "abci_last_block_height": abci_height,
                "local_state_height": local_height,
                "abci_last_block_app_hash": abci_hash,
                "local_app_hash": local_hash,
            }
            evidence["nodes"].append(observation)
            terminal[name] = observation

        tip_heights = {item["latest_block_height"] for item in terminal.values()}
        require(
            len(tip_heights) == 1,
            "terminal Comet heights differ: "
            + ", ".join(
                f"{name}={item['latest_block_height']}"
                for name, item in sorted(terminal.items())
            ),
        )
        terminal_hashes = {item["abci_last_block_app_hash"] for item in terminal.values()}
        require(
            len(terminal_hashes) == 1,
            "terminal application hashes conflict: "
            + ", ".join(
                f"{name}={item['abci_last_block_app_hash']}"
                for name, item in sorted(terminal.items())
            ),
        )
        common_tip = next(iter(tip_heights))
        require(
            common_tip >= args.start_height,
            f"common tip {common_tip} is below start height {args.start_height}",
        )
        evidence["common_tip_height"] = common_tip

        for height in range(args.start_height, common_tip + 1):
            observations: list[dict[str, str]] = []
            for name in history_names:
                rpc_url, _ = node_specs[name]
                result = rpc_get(
                    rpc_url,
                    "block",
                    {"height": height},
                    timeout_seconds=args.rpc_timeout_seconds,
                    attempts=args.rpc_attempts,
                )
                block_id = result.get("block_id")
                block = result.get("block")
                require(isinstance(block_id, dict), f"{name}@{height}: missing block_id")
                require(isinstance(block, dict), f"{name}@{height}: missing block")
                header = block.get("header")
                require(isinstance(header, dict), f"{name}@{height}: missing block header")
                observed_height = parse_height(
                    header.get("height"),
                    f"{name}@{height}: header height",
                )
                require(
                    observed_height == height,
                    f"{name}@{height}: RPC returned height {observed_height}",
                )
                chain_id = header.get("chain_id")
                require(
                    chain_id == args.expected_chain_id,
                    f"{name}@{height}: chain ID {chain_id!r} != "
                    f"{args.expected_chain_id!r}",
                )
                block_hash = normalize_hash(
                    block_id.get("hash"),
                    f"{name}@{height}: block ID",
                )
                prior_app_hash = normalize_hash(
                    header.get("app_hash"),
                    f"{name}@{height}: header app hash",
                    allow_empty=height == 1,
                )
                observation = {
                    "node": name,
                    "block_id_hash": block_hash,
                    "prior_state_app_hash": prior_app_hash,
                }
                observations.append(observation)
            block_hashes = {item["block_id_hash"] for item in observations}
            require(
                len(block_hashes) == 1,
                f"height {height}: conflicting block IDs: "
                + ", ".join(
                    f"{item['node']}={item['block_id_hash']}" for item in observations
                ),
            )
            prior_hashes = {item["prior_state_app_hash"] for item in observations}
            require(
                len(prior_hashes) == 1,
                f"height {height}: conflicting header app hashes: "
                + ", ".join(
                    f"{item['node']}={item['prior_state_app_hash']}"
                    for item in observations
                ),
            )

            if height < common_tip:
                next_hashes: list[tuple[str, str]] = []
                for name in history_names:
                    rpc_url, _ = node_specs[name]
                    next_result = rpc_get(
                        rpc_url,
                        "block",
                        {"height": height + 1},
                        timeout_seconds=args.rpc_timeout_seconds,
                        attempts=args.rpc_attempts,
                    )
                    next_block = next_result.get("block")
                    require(
                        isinstance(next_block, dict),
                        f"{name}@{height + 1}: missing next block",
                    )
                    next_header = next_block.get("header")
                    require(
                        isinstance(next_header, dict),
                        f"{name}@{height + 1}: missing next header",
                    )
                    post_hash = normalize_hash(
                        next_header.get("app_hash"),
                        f"{name}@{height}: post-state hash from header {height + 1}",
                    )
                    next_hashes.append((name, post_hash))
                unique_post_hashes = {value for _, value in next_hashes}
                require(
                    len(unique_post_hashes) == 1,
                    f"height {height}: conflicting post-state app hashes: "
                    + ", ".join(f"{name}={value}" for name, value in next_hashes),
                )
                post_state_hash = next(iter(unique_post_hashes))
                post_state_source = f"header_at_height_{height + 1}"
            else:
                post_state_hash = next(iter(terminal_hashes))
                post_state_source = "terminal_abci_info"

            height_records.append(
                {
                    "height": height,
                    "chain_id": args.expected_chain_id,
                    "block_id_hash": next(iter(block_hashes)),
                    "prior_state_app_hash": next(iter(prior_hashes)),
                    "post_state_app_hash": post_state_hash,
                    "post_state_source": post_state_source,
                    "history_nodes": history_names,
                    "observations": observations,
                }
            )

        evidence["status"] = "PASS"
    except Exception as exc:
        evidence["errors"].append(str(exc))

    emit_evidence(args, evidence, height_records)
    if evidence["status"] != "PASS":
        print(
            "TRNM_COMETBFT_SAFETY_FAILED "
            f"json={args.json_out} tsv={args.tsv_out} "
            f"reason={evidence['errors'][0]}",
            file=sys.stderr,
        )
        return 1

    print(
        "TRNM_COMETBFT_SAFETY_OK "
        f"height={evidence['common_tip_height']} "
        f"nodes={len(evidence['nodes'])} "
        f"history_nodes={len(evidence['history_nodes'])} "
        "block_id_unique=verified terminal_app_hash=verified "
        f"json={args.json_out} tsv={args.tsv_out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
