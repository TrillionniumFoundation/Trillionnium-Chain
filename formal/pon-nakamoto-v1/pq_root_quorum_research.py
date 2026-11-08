#!/usr/bin/env python3
"""Research-only root proposal observations with a pinned OpenSSL 3.5.9 CLI.

The sole complete verifier requires ML-DSA-87 2-of-3 AND
SLH-DSA-SHA2-256s 2-of-3.  The ML-only baseline is a separately named
component observation and can never satisfy that policy. Both sign the same
complete proposal, including the AND policy and both rosters.

All keys are PUBLIC, deterministic test fixtures. Never provision identities
from them. This is command-cold latency (process startup, key import, temporary
file IO and receipt flushing included), not hot EVP latency. No production
registry, owner, root update, durable state, network or activation is exercised.

Example (output must be a new, absolute directory):
  python3 pq_root_quorum_research.py --openssl /absolute/bin/openssl \
    --openssl-sha256 <trusted-executable-sha256> --output /absolute/new-run

The executable version and hash are checked, but are not host attestation.
The caller must separately bind source, build, libraries and resource context.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time


SCHEMA = "trnm.root-quorum-research.v1"
MAX_MESSAGE = 4096
MAX_WIRE = 131072
SAMPLES = 64
QUORUM = 2
DOMAIN = b"TRNM/RootApprovalResearch/v1\0"
FULL_MAGIC = b"RQR1"
COMPONENT_MAGIC = b"RMC1"
CONTEXT = b""
NO_EFFECT = {"root_effect_executed": False, "activation_performed": False,
             "production_qualified": False, "host_attested": False}


@dataclass(frozen=True)
class Suite:
    code: int
    name: str
    signature_bytes: int
    spki_bytes: int
    seed_bytes: int


ML = Suite(1, "ML-DSA-87", 4627, 2614, 32)
SLH = Suite(2, "SLH-DSA-SHA2-256s", 29792, 82, 96)
SUITES = (ML, SLH)


def digest(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sized(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class Rejected(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Rejected(code)


@dataclass(frozen=True)
class PublicKey:
    suite: Suite
    spki: bytes

    @property
    def key_id(self) -> bytes:
        return digest(b"TRNM/RootResearch/Key/v1\0" + bytes([self.suite.code]) + sized(self.spki))


@dataclass(frozen=True)
class ResearchConfig:
    """Caller-owned fixture configuration; never constructed from a wire frame."""
    ml_roster: tuple[PublicKey, ...]
    slh_roster: tuple[PublicKey, ...]
    network: bytes = b"\x11" * 32
    genesis: bytes = b"\x22" * 32
    protocol: int = 1

    def roster(self, suite: Suite) -> tuple[PublicKey, ...]:
        return self.ml_roster if suite == ML else self.slh_roster

    def validate(self) -> None:
        require(len(self.network) == len(self.genesis) == 32, "trusted-config")
        require(type(self.protocol) is int and self.protocol == 1, "trusted-config")
        for suite in SUITES:
            keys = self.roster(suite)
            require(len(keys) == 3 and all(k.suite == suite and len(k.spki) == suite.spki_bytes
                                          for k in keys), "trusted-roster")
            require([k.key_id for k in keys] == sorted({k.key_id for k in keys}), "trusted-roster")

    def canonical(self) -> bytes:
        self.validate()
        raw = b"TRNM/RootResearch/Configuration/v1\0" + self.network + self.genesis
        raw += struct.pack(">III", self.protocol, MAX_MESSAGE, MAX_WIRE)
        raw += sized(b"Pure;empty-context;AND;root-rotation-research;root-role;no-effects")
        for suite in SUITES:
            raw += bytes([suite.code, 3, QUORUM]) + sized(suite.name.encode("ascii"))
            for key in self.roster(suite):
                raw += key.key_id + sized(key.spki)
        return raw

    def roster_digest(self, suite: Suite) -> bytes:
        return digest(b"TRNM/RootResearch/Roster/v1\0" + bytes([suite.code, 3, QUORUM])
                      + b"".join(k.key_id + sized(k.spki) for k in self.roster(suite)))


@dataclass(frozen=True)
class Expected:
    """A trusted research view. No field is populated by parsing incoming bytes."""
    operation_id: bytes
    sequence: int
    ml_signers: tuple[bytes, bytes]
    slh_signers: tuple[bytes, bytes]
    payload: bytes
    owner_generation: int = 7
    key_epoch: int = 3
    valid_from: int = 100
    valid_until: int = 200
    now_height: int = 150
    previous_state: bytes = b"\x33" * 64

    def selected(self, suite: Suite) -> tuple[bytes, bytes]:
        return self.ml_signers if suite == ML else self.slh_signers


def proposal(config: ResearchConfig, expected: Expected) -> bytes:
    config_bytes = config.canonical()
    integers = (expected.owner_generation, expected.key_epoch, expected.sequence,
                expected.valid_from, expected.valid_until, expected.now_height)
    require(all(type(n) is int and 0 <= n < 1 << 64 for n in integers), "trusted-state")
    require(expected.valid_from <= expected.now_height <= expected.valid_until, "expired")
    require(len(expected.operation_id) == 32 and len(expected.previous_state) == 64,
            "trusted-state")
    require(type(expected.payload) is bytes and len(expected.payload) <= MAX_MESSAGE, "size")
    for suite in SUITES:
        selected = expected.selected(suite)
        known = {key.key_id for key in config.roster(suite)}
        require(len(selected) == QUORUM and list(selected) == sorted(set(selected))
                and all(key in known for key in selected), "trusted-signers")
    raw = DOMAIN + config.network + config.genesis + struct.pack(">I", config.protocol)
    raw += digest(config_bytes) + sized(b"root-rotation-research") + sized(b"root")
    raw += struct.pack(">QQQQQ", *integers[:5]) + expected.previous_state
    raw += digest(b"TRNM/RootResearch/Content/v1\0" + sized(expected.payload)) + expected.operation_id
    raw += config.roster_digest(ML) + config.roster_digest(SLH) + b"AND\x02\x02"
    raw += b"".join(expected.ml_signers + expected.slh_signers) + sized(expected.payload)
    require(len(raw) <= MAX_MESSAGE, "size")
    return raw


def fixture_expected(config: ResearchConfig, index: int, *, pairs=None) -> Expected:
    """Independent expected snapshots, not a claim that any root was advanced."""
    combos = tuple(itertools.combinations(range(3), 2))
    ml_pair, slh_pair = pairs or (combos[index % 3], combos[(index // 3) % 3])
    return Expected(b"\x5a" * 24 + struct.pack(">Q", index + 1), 1000 + index,
                    tuple(config.ml_roster[i].key_id for i in ml_pair),
                    tuple(config.slh_roster[i].key_id for i in slh_pair),
                    b"Research root proposal; no installation or effect\0" + struct.pack(">Q", index))


@dataclass(frozen=True)
class Approval:
    family: int
    signer: bytes
    spki: bytes
    signature: bytes


def encode_frame(magic: bytes, message: bytes, approvals: tuple[Approval, ...]) -> bytes:
    """Bounded encoding only; this function does not authenticate an approval."""
    require(magic in (FULL_MAGIC, COMPONENT_MAGIC) and len(message) <= MAX_MESSAGE
            and len(approvals) <= 4, "size")
    wire = magic + sized(message) + struct.pack(">H", len(approvals))
    for item in approvals:
        require(len(item.signer) == 64 and 0 <= item.family <= 255
                and len(item.spki) <= ML.spki_bytes and len(item.signature) <= SLH.signature_bytes,
                "size")
        wire += bytes([item.family]) + item.signer + sized(item.spki) + sized(item.signature)
    require(len(wire) <= MAX_WIRE, "size")
    return wire


def _decode(config, expected, wire, magic, suites):
    require(type(wire) is bytes and 10 <= len(wire) <= MAX_WIRE, "size")
    expected_message = proposal(config, expected)
    at = 0

    def take(length):
        nonlocal at
        require(0 <= length <= len(wire) - at, "encoding")
        result = wire[at:at + length]
        at += length
        return result

    def field(limit):
        length = int.from_bytes(take(4), "big")
        require(length <= limit, "size")
        return take(length)

    require(take(4) == magic, "scope")
    message = field(MAX_MESSAGE)
    require(message == expected_message, "proposal")
    require(int.from_bytes(take(2), "big") == QUORUM * len(suites), "quorum")
    checked = []
    for suite in suites:
        keys = {key.key_id: key for key in config.roster(suite)}
        for expected_id in expected.selected(suite):
            family, key_id = take(1)[0], take(64)
            require(family == suite.code and key_id == expected_id, "signer")
            public = field(suite.spki_bytes)
            require(public == keys[expected_id].spki, "signer")
            signature = field(suite.signature_bytes)
            require(len(signature) == suite.signature_bytes, "size")
            checked.append((keys[expected_id], signature))
    require(at == len(wire), "encoding")
    return message, checked


def _verify(config, expected, wire, backend, *, component):
    message, signatures = _decode(config, expected, wire,
                                  COMPONENT_MAGIC if component else FULL_MAGIC,
                                  (ML,) if component else SUITES)
    for key, signature in signatures:
        if not backend.verify(key, message, signature):
            raise Rejected("signature")
    return {"verified_signatures": len(signatures), "hybrid_policy_satisfied": not component,
            "component_only": component, **NO_EFFECT}


def verify_root_candidate(config, expected, wire, backend):
    """Fixed AND verifier. No mode, algorithm or quorum is selected by input."""
    return _verify(config, expected, wire, backend, component=False)


def verify_ml_component_observation(config, expected, wire, backend):
    """Cost baseline only: successful output always has hybrid_policy_satisfied=false."""
    return _verify(config, expected, wire, backend, component=True)


class BackendFailure(RuntimeError):
    pass


class Journal:
    def __init__(self, path: Path):
        self.stream = path.open("x", encoding="utf-8")

    def emit(self, kind, **fields):
        self.stream.write(json.dumps({"schema": SCHEMA, "kind": kind, **fields},
                                     sort_keys=True, separators=(",", ":")) + "\n")
        self.stream.flush()

    def close(self):
        self.stream.close()


class OpenSSL:
    """No fallback, shell, user-selected suite, digest preprocessing or raw-mu path."""
    def __init__(self, executable: Path, expected_sha256: str, temporary: Path, journal: Journal):
        if (not executable.is_absolute() or executable.resolve(strict=True) != executable
                or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
            raise BackendFailure("canonical executable path and trusted SHA-256 required")
        self.executable, self.temporary, self.journal = executable, temporary, journal
        self.sha256, self.commands, self.verifications = expected_sha256, 0, 0
        self.started = time.monotonic()
        self.identity = self._identity()
        self.check_digest()
        self.environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C",
                            "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(temporary / "no-modules")}
        code, stdout = self._run(["version"], "version")
        if code != 0 or not stdout.startswith(b"OpenSSL 3.5.9 "):
            raise BackendFailure("requires exactly OpenSSL 3.5.9")
        self.version = stdout.decode("ascii").strip()
        self.private = {}

    def _identity(self):
        info = self.executable.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not os.access(self.executable, os.X_OK):
            raise BackendFailure("backend is not a regular executable")
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def check_digest(self):
        with self.executable.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != self.sha256:
            raise BackendFailure("OpenSSL executable digest mismatch")

    def _run(self, arguments, purpose):
        remaining = 1800 - (time.monotonic() - self.started)
        if self._identity() != self.identity or remaining <= 0:
            raise BackendFailure("backend changed or 1800-second run budget exhausted")
        started = time.perf_counter_ns()
        self.commands += 1
        try:
            result = subprocess.run([str(self.executable), *arguments], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=self.environment, timeout=min(30, remaining), check=False)
        except subprocess.TimeoutExpired as error:
            self.journal.emit("command", number=self.commands, purpose=purpose, exit_code=None,
                              elapsed_ns=time.perf_counter_ns() - started, failure="timeout",
                              stdout_sha256=hashlib.sha256(error.stdout or b"").hexdigest(),
                              stderr_sha256=hashlib.sha256(error.stderr or b"").hexdigest(),
                              stdout_prefix_hex=(error.stdout or b"")[:65536].hex(),
                              stderr_prefix=(error.stderr or b"")[:1024].decode("utf-8", errors="replace"))
            raise BackendFailure("OpenSSL command or shared run deadline expired") from error
        self.journal.emit("command", number=self.commands, purpose=purpose,
                          argv=arguments, exit_code=result.returncode,
                          elapsed_ns=time.perf_counter_ns() - started,
                          stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr),
                          stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                          stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
                          # All commands use public test fixtures. genpkey writes
                          # its private output to the private temporary file.
                          stdout_prefix_hex=result.stdout[:65536].hex(),
                          stderr_prefix=result.stderr[:1024].decode("utf-8", errors="replace"))
        if self._identity() != self.identity:
            raise BackendFailure("backend changed during command")
        if len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise BackendFailure("unexpected OpenSSL output size")
        return result.returncode, result.stdout

    def fixtures(self):
        rosters, fixtures = [], []
        for suite in SUITES:
            keys = []
            for index in range(3):
                seed = bytes([0x4d if suite == ML else 0x53]) * (suite.seed_bytes - 1) + bytes([index + 1])
                private = self.temporary / f"fixture-{suite.code}-{index}.pem"
                code, _ = self._run(["genpkey", "-provider", "default", "-propquery", "provider=default",
                                     "-algorithm", suite.name, "-pkeyopt", "hexseed:" + seed.hex(),
                                     "-out", str(private)], "fixture-keygen")
                if code != 0:
                    raise BackendFailure("fixture key generation failed")
                code, public = self._run(["pkey", "-provider", "default", "-propquery", "provider=default",
                                          "-in", str(private), "-pubout", "-outform", "DER"], "fixture-public")
                if code != 0 or len(public) != suite.spki_bytes:
                    raise BackendFailure("unexpected fixture SPKI")
                key = PublicKey(suite, public)
                self.private[key.key_id] = private
                keys.append(key)
                fixtures.append({"algorithm": suite.name, "key_id": key.key_id.hex(),
                                 "public_test_seed_hex": seed.hex(), "public_spki_hex": public.hex()})
            rosters.append(tuple(sorted(keys, key=lambda key: key.key_id)))
        config = ResearchConfig(*rosters)
        config.validate()
        return config, fixtures

    def sign(self, key: PublicKey, message: bytes, *, context=CONTEXT) -> bytes:
        if key.suite not in SUITES or len(message) > MAX_MESSAGE or len(context) > 255:
            raise BackendFailure("unsupported signing request")
        with tempfile.TemporaryDirectory(dir=self.temporary) as directory:
            source = Path(directory) / "message"
            source.write_bytes(message)
            args = ["pkeyutl", "-provider", "default", "-propquery", "provider=default", "-sign", "-rawin",
                    "-inkey", str(self.private[key.key_id]), "-in", str(source),
                    "-pkeyopt", "message-encoding:1", "-pkeyopt", "deterministic:1"]
            if key.suite == ML:
                args += ["-pkeyopt", "mu:0"]
            if context:
                args += ["-pkeyopt", "hexcontext-string:" + context.hex()]
            code, signature = self._run(args, "sign:" + key.suite.name)
        if code != 0 or len(signature) != key.suite.signature_bytes:
            raise BackendFailure("complete-message signing failed")
        return signature

    def verify(self, key: PublicKey, message: bytes, signature: bytes) -> bool:
        if key.suite not in SUITES or len(message) > MAX_MESSAGE or len(signature) != key.suite.signature_bytes:
            raise BackendFailure("unsupported verification request")
        with tempfile.TemporaryDirectory(dir=self.temporary) as directory:
            directory = Path(directory)
            for name, raw in (("message", message), ("signature", signature), ("public.der", key.spki)):
                (directory / name).write_bytes(raw)
            args = ["pkeyutl", "-provider", "default", "-propquery", "provider=default", "-verify", "-rawin",
                    "-pubin", "-keyform", "DER", "-inkey", str(directory / "public.der"),
                    "-in", str(directory / "message"), "-sigfile", str(directory / "signature")]
            if key.suite == ML:
                args += ["-pkeyopt", "mu:0"]
            self.verifications += 1
            code, stdout = self._run(args, "verify:" + key.suite.name)
        if code == 0 and stdout.strip() == b"Signature Verified Successfully":
            return True
        if code == 1 and stdout.strip() == b"Signature Verification Failure":
            return False
        raise BackendFailure("verification tool failure; not a signature rejection")


def sign_records(config, expected, backend, *, component=False):
    message = proposal(config, expected)
    records = []
    for suite in ((ML,) if component else SUITES):
        keys = {key.key_id: key for key in config.roster(suite)}
        for key_id in expected.selected(suite):
            key = keys[key_id]
            records.append(Approval(suite.code, key_id, key.spki, backend.sign(key, message)))
    return message, tuple(records)


def controls(config, backend, journal):
    combos = tuple(itertools.combinations(range(3), 2))
    for index, pair in enumerate(itertools.product(combos, repeat=2)):
        expected = fixture_expected(config, 100 + index, pairs=pair)
        message, records = sign_records(config, expected, backend)
        wire = encode_frame(FULL_MAGIC, message, records)
        journal.emit("control-start", name=f"legal-pair-{index}", expected="accept", wire_hex=wire.hex())
        result = verify_root_candidate(config, expected, wire, backend)
        journal.emit("control", name=f"legal-pair-{index}", expected="accept", result=result,
                     proposal_sha512=digest(message).hex(), wire_hex=wire.hex())
    expected = fixture_expected(config, 200)
    message, records = sign_records(config, expected, backend)
    valid = encode_frame(FULL_MAGIC, message, records)
    verify_root_candidate(config, expected, valid, backend)
    last_key = next(k for k in config.slh_roster if k.key_id == records[-1].signer)
    wrong_context = backend.sign(last_key, message, context=b"wrong-root-research-context")
    wrong_state = replace(expected, previous_state=b"\x44" * 64)
    stale_message, stale_records = sign_records(config, wrong_state, backend)
    broken = records[-1].signature[:-1] + bytes([records[-1].signature[-1] ^ 1])
    cases = [
        ("component-cannot-satisfy-AND", encode_frame(COMPONENT_MAGIC, message, records[:2]), expected, "scope", 0),
        ("missing-SLH-family", encode_frame(FULL_MAGIC, message, records[:2]), expected, "quorum", 0),
        ("missing-ML-family", encode_frame(FULL_MAGIC, message, records[2:]), expected, "quorum", 0),
        ("duplicate-signer", encode_frame(FULL_MAGIC, message, (records[0], records[0], *records[2:])), expected, "signer", 0),
        ("unknown-signer", encode_frame(FULL_MAGIC, message, (replace(records[0], signer=b"\xff" * 64), *records[1:])), expected, "signer", 0),
        ("wrong-context", encode_frame(FULL_MAGIC, message, (*records[:-1], replace(records[-1], signature=wrong_context))), expected, "signature", 4),
        ("signed-wrong-state", encode_frame(FULL_MAGIC, stale_message, stale_records), expected, "proposal", 0),
        ("split-proposal", encode_frame(FULL_MAGIC, message, records[:2] + stale_records[2:]), expected, "signature", 3),
        ("stale-owner-generation", valid, replace(expected, owner_generation=expected.owner_generation + 1), "proposal", 0),
        ("stale-key-epoch", valid, replace(expected, key_epoch=expected.key_epoch + 1), "proposal", 0),
        ("expired-current-view", valid, replace(expected, now_height=expected.valid_until + 1), "expired", 0),
        ("last-SLH-signature-bitflip", encode_frame(FULL_MAGIC, message, (*records[:-1], replace(records[-1], signature=broken))), expected, "signature", 4),
    ]
    for name, wire, view, reason, expected_calls in cases:
        journal.emit("control-start", name=name, expected="reject", expected_rejection=reason,
                     trusted_expected_generation=view.owner_generation,
                     trusted_expected_height=view.now_height,
                     trusted_expected_previous_state=view.previous_state.hex(), wire_hex=wire.hex())
        before = backend.verifications
        started = time.perf_counter_ns()
        try:
            verify_root_candidate(config, view, wire, backend)
        except Rejected as error:
            if error.code != reason:
                raise BackendFailure(f"{name}: expected {reason}, got {error.code}") from error
        else:
            raise BackendFailure(f"negative control accepted: {name}")
        calls = backend.verifications - before
        require(calls == expected_calls, "negative-control-call-accounting")
        journal.emit("control", name=name, expected="reject", rejection=reason,
                     verification_api_calls=calls, elapsed_ns=time.perf_counter_ns() - started,
                     wire_hex=wire.hex(), **NO_EFFECT)
    return {"legal_dual_quorum_pairs": 9, "rejected_controls": len(cases)}


def observe_ml_component(config, expected, backend):
    tick = time.perf_counter_ns()
    message, records = sign_records(config, expected, backend, component=True)
    wire = encode_frame(COMPONENT_MAGIC, message, records)
    signed = time.perf_counter_ns()
    result = verify_ml_component_observation(config, expected, wire, backend)
    verified = time.perf_counter_ns()
    return message, wire, result, {"sign_and_encode_ns": signed - tick,
                                  "verify_frame_ns": verified - signed}


def observe_and_candidate(config, expected, backend):
    tick = time.perf_counter_ns()
    message, records = sign_records(config, expected, backend)
    wire = encode_frame(FULL_MAGIC, message, records)
    signed = time.perf_counter_ns()
    result = verify_root_candidate(config, expected, wire, backend)
    verified = time.perf_counter_ns()
    return message, wire, result, {"sign_and_encode_ns": signed - tick,
                                  "verify_frame_ns": verified - signed}


def run(executable, expected_sha256, output):
    if not output.is_absolute():
        raise ValueError("output must be an absolute new directory")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    journal, commands = Journal(output / "observations.jsonl"), Journal(output / "commands.jsonl")
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    started = time.perf_counter_ns()
    try:
        journal.emit("start", samples_per_branch=SAMPLES, **NO_EFFECT,
                     source_sha256=source_sha, python=sys.version, platform=platform.platform(),
                     algorithms=[suite.name for suite in SUITES], quorum="2-of-3 AND 2-of-3",
                     quorum_wire_rule="exactly two distinct selected keys per required three-key roster; redundant signatures refused",
                     keys_are_public_test_fixtures=True, signature_mode="Pure", fips_context_hex="",
                     signing_variant="deterministic", max_message_bytes=MAX_MESSAGE, max_wire_bytes=MAX_WIRE,
                     baseline_scope="ML component only; cannot satisfy the signed AND policy",
                     timing_scope="command-cold; encode, sign, verify, subprocess startup, key import, temp IO, outcome checks and command receipt flush; key generation and observation output outside samples",
                     state_scope="independent caller-generated fixture expected snapshots; no state transition or durable anti-rollback enforcement",
                     wire_scope="shared proposal plus selected signer SPKIs/signatures; prior distribution of the complete trusted 3+3 roster/configuration is excluded; not total key-management protocol cost",
                     openssl_executable=str(executable), openssl_sha256_expected=expected_sha256,
                     caller_build_and_resource_receipt_required=True)
        with tempfile.TemporaryDirectory(prefix="root-research-") as temporary:
            backend = OpenSSL(executable, expected_sha256, Path(temporary), commands)
            config, fixtures = backend.fixtures()
            configuration_tick = time.perf_counter_ns()
            config_bytes = config.canonical()
            config_digest = digest(config_bytes).hex()
            configuration_ns = time.perf_counter_ns() - configuration_tick
            journal.emit("configuration", canonical_hex=config_bytes.hex(), profile_sha512=config_digest,
                         canonical_bytes=len(config_bytes), encode_and_hash_ns=configuration_ns,
                         distribution_cost_measured=False,
                         fixtures=fixtures, openssl_version=backend.version, **NO_EFFECT)
            checked = controls(config, backend, journal)
            raw = {"ML_COMPONENT": [], "AND_CANDIDATE": []}
            functions = {"ML_COMPONENT": observe_ml_component, "AND_CANDIDATE": observe_and_candidate}
            seen = set()
            for index in range(SAMPLES):
                expected = fixture_expected(config, index)
                message = proposal(config, expected)
                require(expected.operation_id not in seen, "repeated-operation")
                seen.add(expected.operation_id)
                order = ("ML_COMPONENT", "AND_CANDIDATE") if index % 2 == 0 else ("AND_CANDIDATE", "ML_COMPONENT")
                for position, branch in enumerate(order):
                    journal.emit("sample-start", index=index, within_pair_position=position, branch=branch,
                                 operation_id=expected.operation_id.hex(), sequence=expected.sequence,
                                 proposal_hex=message.hex(), proposal_sha512=digest(message).hex())
                    before = backend.commands
                    tick = time.perf_counter_ns()
                    observed, wire, result, stages = functions[branch](config, expected, backend)
                    require(observed == message, "paired-message-mismatch")
                    require(result["hybrid_policy_satisfied"] == (branch == "AND_CANDIDATE"), "scope")
                    elapsed = time.perf_counter_ns() - tick
                    require(sum(stages.values()) <= elapsed, "stage-accounting")
                    raw[branch].append(elapsed)
                    journal.emit("sample", index=index, within_pair_position=position, branch=branch,
                                 operation_id=expected.operation_id.hex(), sequence=expected.sequence,
                                 proposal_sha512=digest(message).hex(), proposal_bytes=len(message),
                                 wire_bytes=len(wire), wire_hex=wire.hex(), elapsed_ns=elapsed,
                                 command_count=backend.commands - before, result=result, **stages)
            backend.check_digest()
            require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source_sha, "source-changed")
            journal.emit("complete", measured_pairs=len(seen), sample_rows=2 * SAMPLES,
                         raw_group_latency_ns=raw, controls=checked, command_count=backend.commands,
                         elapsed_ns=time.perf_counter_ns() - started,
                         scope="local command-cold candidate observations; no production tail or effect", **NO_EFFECT)
        return 0
    except Exception as error:
        journal.emit("failure", exception=type(error).__name__, reason=str(error)[:2048],
                     elapsed_ns=time.perf_counter_ns() - started, **NO_EFFECT)
        return 1
    finally:
        journal.close()
        commands.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--openssl-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args.openssl, args.openssl_sha256, args.output)
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
