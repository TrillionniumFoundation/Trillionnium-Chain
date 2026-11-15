#!/usr/bin/env python3
"""Observe experimental envelope serialization and paced TCP loopback transfer.

The envelope is explicitly not a Node wire format. A successful local byte
roundtrip measures neither WAN propagation nor block admission/confirmation.
This program never verifies a cryptographic proof or awards work tickets.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time

sys.dont_write_bytecode = True
from w1_stage_measure import write_new

MAGIC = b"TRNM-W1-LOCAL-PAYLOAD1\0"
HEADER_BYTES = 318
INPUT_BYTES = 49506
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = MAX_RECEIPT_BYTES + 1024


def bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"oversized local input: {path}")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def serialize(input_path, receipt_path, artifacts_path, statement_version, out):
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    full_input = bounded(input_path, INPUT_BYTES)
    receipt = bounded(receipt_path, MAX_RECEIPT_BYTES)
    artifacts = bounded(artifacts_path, 64) if artifacts_path else b""
    if len(full_input) != INPUT_BYTES or not receipt:
        raise ValueError("exact original full input and nonempty saved receipt required")
    if statement_version not in (1, 2) or len(artifacts) != (64 if statement_version == 2 else 0):
        raise ValueError("statement version and external artifact length differ")
    statement = full_input[:HEADER_BYTES] + artifacts
    rows = {}
    for kind, code, body in (("native", 1, full_input[HEADER_BYTES:]), ("transparent", 2, receipt)):
        begin = time.monotonic_ns()
        payload = MAGIC + struct.pack("<BBII", statement_version, code, len(statement), len(body)) + statement + body
        encoded_ns = time.monotonic_ns() - begin
        path = out / f"{kind}.payload.bin"
        begin = time.monotonic_ns()
        write_bytes(path, payload)
        write_ns = time.monotonic_ns() - begin
        rows[kind] = {"payload_file": path.name, "payload_bytes": len(payload),
                      "payload_sha256": digest(payload), "body_bytes": len(body),
                      "body_sha256": digest(body), "envelope_encode_ns": encoded_ns,
                      "durable_local_file_write_ns": write_ns}
    result = {
        "schema": "TRNM-W1-LOCAL-PAYLOAD1", "statement_version": statement_version,
        "scope": "experimental local envelope; not Node wire format or publication",
        "input_sha256": digest(full_input), "header_sha256": digest(full_input[:HEADER_BYTES]),
        "external_artifacts_sha256": digest(artifacts) if artifacts else None,
        "statement_bytes": len(statement), "statement_sha256": digest(statement),
        "serialization_and_file_write_wall_ns": time.monotonic_ns() - started,
        "payloads": rows, "proof_randomness_tickets": 0,
        "real_network_propagation_seconds": None, "node_admission_seconds": None,
        "confirmation_seconds": None, "stale_block_rate": None,
    }
    write_new(out / "result.json", result)
    return result


def transfer(payload_path, expected_sha256, bytes_per_second, out):
    if type(bytes_per_second) is not int or not 1000 <= bytes_per_second <= 1_000_000_000:
        raise ValueError("explicit pacing rate must be in [1000,1000000000] bytes/s")
    out.mkdir(parents=True, exist_ok=False)
    payload = bounded(payload_path, MAX_PAYLOAD_BYTES)
    if not payload or digest(payload) != expected_sha256:
        raise ValueError("local payload differs from its serialized digest")
    receiver = {"received_bytes": 0, "received_sha256": None, "error": None}
    setup_started = time.monotonic_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        with socket.create_connection(listener.getsockname(), timeout=10) as sender:
            accepted, peer = listener.accept()
            with accepted:
                accepted.settimeout(10)
                setup_ns = time.monotonic_ns() - setup_started

                def receive():
                    value = hashlib.sha256()
                    try:
                        with (out / "received.bin").open("xb") as stream:
                            while True:
                                block = accepted.recv(65536)
                                if not block:
                                    break
                                receiver["received_bytes"] += len(block)
                                if receiver["received_bytes"] > len(payload):
                                    raise ValueError("local receiver exceeded declared payload length")
                                value.update(block)
                                stream.write(block)
                            stream.flush()
                            os.fsync(stream.fileno())
                        receiver["received_sha256"] = value.hexdigest()
                    except Exception as error:
                        receiver["error"] = f"{type(error).__name__}: {error}"

                worker = threading.Thread(target=receive, daemon=True)
                started = time.monotonic()
                worker.start()
                chunk_size = min(4096, max(1, bytes_per_second // 10))
                sent = 0
                for offset in range(0, len(payload), chunk_size):
                    block = payload[offset:offset + chunk_size]
                    # Pace before each chunk: a local host scheduler may delay the
                    # send further, but cannot make the offered rate unlimited.
                    due = started + (sent + len(block)) / bytes_per_second
                    while time.monotonic() < due:
                        time.sleep(min(.05, max(0, due - time.monotonic())))
                    sender.sendall(block)
                    sent += len(block)
                sender.shutdown(socket.SHUT_WR)
                worker.join(timeout=10)
                elapsed = time.monotonic() - started
                complete = (not worker.is_alive() and receiver["error"] is None
                            and receiver["received_bytes"] == len(payload)
                            and receiver["received_sha256"] == expected_sha256)
    result = {
        "schema": "TRNM-W1-LOCAL-TCP-TRANSFER1",
        "scope": "actual single-host TCP loopback bytes; user-space sender pacing; no WAN, peer or Node admission evidence",
        "address_family": "AF_INET", "receiver_address": "127.0.0.1", "peer_address": peer[0],
        "offered_bytes_per_second": bytes_per_second, "chunk_bytes": chunk_size,
        "payload_bytes": len(payload), "payload_sha256": expected_sha256,
        "connection_setup_ns": setup_ns,
        "send_receive_and_durable_write_seconds": elapsed,
        "receiver": receiver, "byte_roundtrip_complete": complete,
        "real_network_propagation_seconds": None, "node_admission_seconds": None,
        "confirmation_seconds": None, "stale_block_rate": None,
    }
    write_new(out / "result.json", result)
    if not complete:
        raise RuntimeError("local byte roundtrip failed; retained result is not acceptance")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    encode = sub.add_parser("serialize")
    encode.add_argument("--input", type=Path, required=True)
    encode.add_argument("--receipt", type=Path, required=True)
    encode.add_argument("--expected-artifacts", type=Path)
    encode.add_argument("--statement-version", type=int, choices=(1, 2), required=True)
    encode.add_argument("--out", type=Path, required=True)
    send = sub.add_parser("transfer")
    send.add_argument("--payload", type=Path, required=True)
    send.add_argument("--expected-sha256", required=True)
    send.add_argument("--bytes-per-second", type=int, required=True)
    send.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "serialize":
        result = serialize(args.input, args.receipt, args.expected_artifacts, args.statement_version, args.out)
    else:
        result = transfer(args.payload, args.expected_sha256, args.bytes_per_second, args.out)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
