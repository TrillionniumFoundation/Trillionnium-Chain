#!/usr/bin/env python3
"""Fail closed on naked authority-session APIs or default I/O activation drift."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"{path}: {error}") from error


def toml(path: str) -> dict:
    try:
        with (ROOT / path).open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"{path}: {error}") from error
    require(isinstance(value, dict), f"{path}: top level must be table")
    return value


def require_linear_token(source: str, declaration: str) -> None:
    offset = source.find(declaration)
    require(offset >= 0, f"missing token declaration: {declaration}")
    # Only attributes attached to this declaration can derive Clone. Nearby
    # prose (including "deliberately not Clone") is not an implementation.
    attributes = re.search(r"((?:#\[[^\]]*\]\s*)+)$", source[:offset])
    require(attributes is not None, f"verification token lost attributes: {declaration}")
    derives = re.findall(r"\bderive\s*\(([^)]*)\)", attributes[1])
    require(bool(derives), f"verification token lost derive declaration: {declaration}")
    require(
        all(re.search(r"\bClone\b", derive) is None for derive in derives),
        f"verification token derives Clone: {declaration}",
    )
    token = declaration.removeprefix("pub struct ").removesuffix(" {")
    require(
        re.search(
            r"\bimpl\s*(?:<[^{};]*>\s*)?"
            r"(?:(?:std|core)\s*::\s*clone\s*::\s*)?Clone\s+for\s+"
            + re.escape(token)
            + r"\b",
            source,
        ) is None,
        f"verification token implements Clone: {declaration}",
    )


def self_test() -> None:
    declaration = "pub struct VerifiedAuthorityIngressV0 {"
    fixture = (
        "/// This token is deliberately not Clone.\n"
        "#[must_use = \"consume the verified token\"]\n"
        "#[derive(Debug)]\n"
        + declaration
        + "\n    private_field: u64,\n}\n"
    )
    require_linear_token(fixture, declaration)
    for mutation in (
        fixture.replace("derive(Debug)", "derive(Debug, Clone)"),
        fixture.replace("derive(Debug)", "derive(Debug, core::clone::Clone)"),
        fixture.replace("derive(Debug)", "derive(\n    Debug,\n    Clone,\n)"),
        fixture.replace("#[derive(Debug)]", "#[derive(Debug)]\n#[cfg_attr(test, derive(Clone))]"),
        fixture + "impl Clone for VerifiedAuthorityIngressV0 { }\n",
        fixture + "impl core::clone::Clone for VerifiedAuthorityIngressV0 { }\n",
        fixture + "impl std::clone::Clone for VerifiedAuthorityIngressV0 { }\n",
        fixture.replace("#[derive(Debug)]\n", ""),
    ):
        try:
            require_linear_token(mutation, declaration)
        except GateError:
            continue
        raise GateError("linear-token mutation was accepted")
    print("authenticated authority linear-token self-test: 1 control, 8 mutations PASS")


def main() -> int:
    production_path = "trillionnium/crates/trnm-poco-node-production-v0/src/lib.rs"
    production = read(production_path)
    production_manifest = toml(
        "trillionnium/crates/trnm-poco-node-production-v0/Cargo.toml"
    )
    host = read("trillionnium/crates/trnm-poco-node-host/src/lib.rs")
    host_manifest = toml("trillionnium/crates/trnm-poco-node-host/Cargo.toml")
    io_source = read("trillionnium/crates/trnm-poco-node-io/src/lib.rs")
    io_manifest = toml("trillionnium/crates/trnm-poco-node-io/Cargo.toml")

    for required in (
        "pub trait AuthorityIngressSourceV0",
        "pub struct VerifiedAuthorityIngressV0",
        "pub fn verify_ingress<",
        "pub fn begin_verified(",
        "pub trait AuthorityFactSourceV0",
        "pub struct VerifiedAuthorityFactV0",
        "pub fn verify_fact<",
        "pub fn advance_verified(",
    ):
        require(required in production, f"{production_path}: missing {required}")

    for forbidden in (
        "pub fn begin_prepared(",
        "pub fn begin_digest(",
        "pub fn advance_digest(",
        "pub fn advance_authority_exact(",
    ):
        require(forbidden not in production, f"public naked session API: {forbidden}")
        require(forbidden not in host, f"public naked host API: {forbidden}")

    # A broad public `advance` method would reopen caller-supplied digest entry.
    require(
        re.search(r"(?m)^\s*pub\s+fn\s+advance\s*\(", production) is None,
        "production session exposes public advance(...) bypass",
    )

    for declaration in (
        "pub struct VerifiedAuthorityIngressV0 {",
        "pub struct VerifiedAuthorityFactV0 {",
    ):
        require_linear_token(production, declaration)

    production_dependencies = production_manifest.get("dependencies", {})
    require(
        "trnm-durable-file-adapters-v0" not in production_dependencies,
        "wiring-only production crate depends on candidate durable adapter",
    )
    require(
        "trnm-poco-node-authority" not in production_dependencies,
        "wiring-only production crate depends on candidate authority facade",
    )

    host_metadata = host_manifest.get("package", {}).get("metadata", {}).get("trnm", {})
    require(
        host_metadata.get("raw_stage_advance_exported") is False,
        "host metadata must record raw stage advance as closed",
    )
    require(
        host_metadata.get("verified_stage_session_required") is True,
        "host metadata must require verified stage session",
    )
    require(
        host_metadata.get("production_candidate") is False
        and host_metadata.get("production_consensus_activation") is False,
        "host metadata promoted production authority",
    )

    io_features = io_manifest.get("features", {})
    require(io_features.get("default") == [], "node I/O default feature set is not empty")
    require(
        io_features.get("candidate-pacemaker") == [],
        "candidate pacemaker feature is missing or imports undeclared authority",
    )
    for required in (
        "pub struct CandidatePacemakerV0",
        "pub trait MonotonicClockV0",
        "PendingFire",
        "ClockRegressed",
    ):
        require(required in io_source, f"candidate pacemaker missing {required}")
    require(
        "pub const fn production_activation(&self) -> bool {\n        false\n    }"
        in io_source,
        "default node I/O production activation is not constant false",
    )

    for path in (
        "docs/architecture/TRNM_PRODUCTION_AUTHORITY_SESSION_V0.md",
        "docs/architecture/TRNM_AUTHENTICATED_STAGE_FACT_PORT_V0.md",
        "docs/architecture/TRNM_CANDIDATE_PACEMAKER_IO_V0.md",
        "trillionnium/crates/trnm-poco-node-production-v0/tests/authenticated_fact_port.rs",
        "trillionnium/crates/trnm-poco-node-production-v0/tests/public_authority_surface.rs",
        "trillionnium/crates/trnm-poco-node-host/tests/authority_session_durable.rs",
    ):
        require((ROOT / path).is_file(), f"required authority evidence path missing: {path}")

    report = {
        "schema": "trnm-authenticated-authority-ports-check-v0",
        "verified_ingress_required": True,
        "verified_stage_fact_required": True,
        "verification_tokens_cloneable": False,
        "host_raw_stage_advance_exported": False,
        "default_io_inert": True,
        "candidate_pacemaker_feature_gated": True,
        "production_activation": False,
        "result": "PASS",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test()
        elif sys.argv[1:]:
            raise GateError("usage: check_authenticated_authority_ports_v0.py [--self-test]")
        raise SystemExit(main())
    except GateError as error:
        print(f"authenticated authority port gate failed: {error}", file=sys.stderr)
        raise SystemExit(2)
