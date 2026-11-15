#!/usr/bin/env python3
"""Build a pinned private Kaggle worker after an actual native W1 winner.

This command writes source only. The NativeTask/M12 owner must durably bind the
resulting source and provider intent before its one authorized dispatch. The
worker's clock never interprets the owner's Linux monotonic deadline.
"""
from __future__ import annotations

import argparse
import ast
import base64
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
STATIC_SCHEMA = "TRNM-W1-KAGGLE-SOURCE-BUILDER1"
WORKER_SCHEMA = "TRNM-W1-KAGGLE-WORKER-CONFIG1"
BUILD_SCHEMA = "TRNM-W1-KAGGLE-SOURCE-BUILD1"
REPO_URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
BUNDLE_URL = ("https://github.com/risc0/risc0/releases/download/v3.0.3/"
              "cargo-risczero-x86_64-unknown-linux-gnu.tgz")
BUNDLE_SHA256 = "71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee"
GUEST_SHA256 = "25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f"
IMAGE_ID = [1958252411, 3287394615, 1805488136, 1516578702,
            78549041, 790278610, 301018785, 4279049364]
STATIC_KEYS = {"schema", "source_commit", "source_tree", "template_sha256",
               "r0vm_sha256", "segment_workers", "compression_mode",
               "compression_workers", "rayon_threads", "worker_wall_seconds"}
MAX_SOURCE_BYTES = 2 << 20


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key: " + key)
        value[key] = item
    return value


def read_object(path, limit=32768):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("bounded JSON file exceeded")
    value = json.loads(raw, object_pairs_hook=strict_object)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value, raw


def validate_static(value, template):
    if set(value) != STATIC_KEYS or value.get("schema") != STATIC_SCHEMA:
        raise ValueError("exact source-builder configuration schema required")
    for name, length in (("source_commit", 40), ("source_tree", 40),
                         ("template_sha256", 64), ("r0vm_sha256", 64)):
        if (type(value[name]) is not str
                or re.fullmatch("[0-9a-f]{" + str(length) + "}", value[name]) is None):
            raise ValueError("exact hexadecimal identity required: " + name)
    if digest(template) != value["template_sha256"]:
        raise ValueError("fixed worker template digest mismatch")
    for name in ("segment_workers", "compression_workers", "rayon_threads"):
        if type(value[name]) is not int or not 1 <= value[name] <= 4:
            raise ValueError("bounded integer worker plan required")
    if (value["segment_workers"] * value["rayon_threads"] > 4
            or value["compression_workers"] * value["rayon_threads"] > 4):
        raise ValueError("worker plan exceeds observed Kaggle four-CPU envelope")
    if value["compression_mode"] not in ("sequential", "balanced"):
        raise ValueError("explicit full compression mode required")
    if value["compression_mode"] == "sequential" and value["compression_workers"] != 1:
        raise ValueError("sequential compression requires exactly one worker")
    if (type(value["worker_wall_seconds"]) is not int
            or not 60 <= value["worker_wall_seconds"] <= 7200):
        raise ValueError("bounded research worker wall budget required")
    return dict(value)


def render_source(template, config):
    text = template.decode("utf-8", errors="strict")
    if text.startswith("\ufeff") or "\r" in text:
        raise ValueError("canonical UTF-8 LF template required")
    tree = ast.parse(text)
    mains = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    if len(mains) != 1 or len(mains[0].args.args) != 1:
        raise ValueError("worker template must define one main(config) function")
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), allow_nan=False)
    literal = json.dumps(canonical, ensure_ascii=True)
    suffix = ("\n\nif __name__ == '__main__':\n"
              "    import json as _w1_source_json\n"
              "    raise SystemExit(main(_w1_source_json.loads(" + literal + ")))\n")
    source = (text.rstrip("\n") + suffix).encode("utf-8")
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("provider source byte budget exceeded")
    ast.parse(source)
    return source


def write_new_bytes(path, raw):
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("absolute canonical existing output parent required")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError("saved source readback mismatch")
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


@lru_cache(maxsize=1)
def postwin_module():
    spec = importlib.util.spec_from_file_location("w1_builder_postwin", ROOT / "scripts/run_w1_postwin_proof.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frozen_checkout(config, deadline_ns):
    commands = [(["git", "rev-parse", "HEAD"], config["source_commit"]),
                (["git", "rev-parse", "HEAD^{tree}"], config["source_tree"]),
                (["git", "status", "--porcelain=v1", "--untracked-files=no"], "")]
    for argv, expected in commands:
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("original owner deadline exhausted during source binding")
        observed = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  check=True, timeout=min(30, remaining))
        if observed.stdout.decode("utf-8", errors="strict").strip() != expected:
            raise ValueError("worker source must name the exact clean owner checkout")


def build(args):
    if re.fullmatch("[a-z][a-z0-9-]{0,95}", args.request_id) is None:
        raise ValueError("bounded stable original provider request ID required")
    module = postwin_module()
    measure = module.measure
    winner_dir = args.winner_dir.resolve(strict=True)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    winner = module.winner_identity(winner_dir, time.monotonic_ns(), boot)
    deadline_ns = winner["original_deadline_monotonic_ns"]
    template_path = ROOT / "scripts/w1_kaggle_worker_template.py"
    template = template_path.read_bytes()
    static, static_raw = read_object(args.config.resolve(strict=True))
    static = validate_static(static, template)
    frozen_checkout(static, deadline_ns)
    # The actual parent process is responsible for authenticating this event and
    # funding it. JSON flags alone are not an attestation of native execution.
    intent, intent_raw = read_object(winner_dir / "intent.json")
    event_raw = (winner_dir / "result.json").read_bytes()
    config = {key: value for key, value in static.items() if key != "schema"}
    config.update(schema=WORKER_SCHEMA, request_id=args.request_id, repo_url=REPO_URL,
                  prover_profile="cpu-fixed-v3.0.3", cuda_required=False,
                  r0vm_bundle_url=BUNDLE_URL, r0vm_bundle_sha256=BUNDLE_SHA256,
                  guest_sha256=GUEST_SHA256, image_id=IMAGE_ID,
                  owner_deadline_provenance={key: winner[key] for key in (
                      "original_deadline_monotonic_ns", "original_deadline_boot_id",
                      "native_winner_monotonic_ns", "winner_saved_monotonic_ns")})
    for name, field, limit in (("input.bin", "input", 49506), ("header.bin", "header", 318),
                               ("expected-artifacts.bin", "expected_artifacts", 64)):
        raw = (winner_dir / name).read_bytes()
        if len(raw) != limit or digest(raw) != winner[field + "_sha256"]:
            raise ValueError("exact native input changed during worker source binding")
        config[field + "_b64"] = base64.b64encode(raw).decode("ascii")
        config[field + "_sha256"] = digest(raw)
    remaining_seconds = (deadline_ns - time.monotonic_ns()) // 1_000_000_000
    if remaining_seconds < 60:
        raise TimeoutError("original owner budget cannot accommodate worker preparation")
    config["worker_wall_seconds"] = min(static["worker_wall_seconds"], remaining_seconds)
    source = render_source(template, config)
    output = args.output
    record_path = output.with_name(output.name + ".build.json")
    cancellation_path = output.with_name(output.name + ".cancellation.json")
    if any(p.exists() or p.is_symlink() for p in (output, record_path, cancellation_path)):
        raise FileExistsError("source attempt output already exists; no overwrite or redispatch")
    try:
        with measure.cancel_on_signals():
            write_new_bytes(output, source)
            if template_path.read_bytes() != template or args.config.read_bytes() != static_raw:
                raise ValueError("fixed source-builder inputs changed before publication")
            module.winner_identity(winner_dir, time.monotonic_ns(), boot)
            if (winner_dir / "result.json").read_bytes() != event_raw:
                raise ValueError("native event changed before source publication")
            if (winner_dir / "intent.json").read_bytes() != intent_raw:
                raise ValueError("pre-search intent changed before source publication")
            report = {"schema": BUILD_SCHEMA, "request_id": args.request_id,
                      "source_sha256": digest(source), "source_bytes": len(source),
                      "static_config_sha256": digest(static_raw),
                      "template_sha256": digest(template),
                      "native_event_sha256": digest(event_raw),
                      "native_intent_sha256": digest(intent_raw),
                      "native_process_id_reported": intent.get("pid"),
                      "native_process_authenticated_by_builder": False,
                      "source_commit": static["source_commit"], "source_tree": static["source_tree"],
                      "original_deadline_monotonic_ns": deadline_ns,
                      "original_deadline_boot_id": boot, "provider_dispatched": False,
                      "fresh_proof_generations": 0, "production_qualified": False}
            with measure.DeferredCancellation(None, phase="worker-source-publication",
                                              live_deadline=(deadline_ns / 1e9, boot)) as handoff:
                measure.write_new(record_path, report)
                handoff.published_snapshot("worker-source", record_path)
    except (measure.Canceled, KeyboardInterrupt) as canceled:
        measure.publish_cancellation(cancellation_path, canceled, "worker-source-builder")
    if time.monotonic_ns() >= deadline_ns:
        raise TimeoutError("original owner deadline exhausted at source handoff")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("winner_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("request_id")
    args = parser.parse_args(argv)
    with postwin_module().measure.cancel_on_signals():
        print(json.dumps(build(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(postwin_module().measure.run_cli(main))
