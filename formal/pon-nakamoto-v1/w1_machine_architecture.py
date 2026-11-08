"""Metered alternatives to the serial W1 initialization service.

The architectures are explicit service contracts, not compiled hardware. Parallel
reset/readout ports reserve their own auxiliary patches and classical channels;
all auxiliary patches enter the original complete lifecycle/error calculation.
The original illustrative serial lifecycle is unchanged. Energy, capital and
compiled-controller memory remain unknown until supported by external evidence.

The calibration reader checks exact binding, freshness, coverage and artifact
bytes only. It cannot promote a document's assertions into measured physical
upper bounds, a valid noise coupling, or quantum-mining qualification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from fractions import Fraction
import hashlib
from pathlib import Path
import re

from quantum_oracle_resources import ClassicalCosts, PhysicalModel, bounded, integer, label
from w1_bounded_search import ratio
from w1_machine_envelope import (LifecycleModel, SOURCES as MACHINE_SOURCES,
                                  build_machine_envelope)
from w1_quantum_oracle import canonical

SCHEMA = "trnm-w1-metered-service-architecture-v1"
CALIBRATION_SCHEMA = "trnm-w1-machine-calibration-manifest-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCES = MACHINE_SOURCES + ("formal/pon-nakamoto-v1/w1_machine_architecture.py",)
CALIBRATION_REQUIREMENTS = (
    "compiled_physical_layout_and_allocation",
    "history_conditional_physical_noise_bounds",
    "initialization_service_and_overrun_bound",
    "terminal_readout_service_and_overrun_bound",
    "input_and_output_transfer_service",
    "controller_decoder_and_feedforward_service",
    "factory_retries_storage_delivery_and_injection",
    "host_preprocessing_setup_and_candidate_checks",
    "proof_generation_service",
    "propagation_service",
    "full_machine_fault_coupling",
    "complete_machine_energy_metering",
    "capital_and_operating_cost_allocation",
)
MAX_CALIBRATION_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_CALIBRATION_TOTAL_BYTES = 16 * 1024 * 1024


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def _fraction(value):
    return Fraction(**value)


@dataclass(frozen=True)
class ServiceArchitecture:
    """A per-processor reservation, with no implied layout feasibility.

    The initialization ports must initialize the complete oracle *and service*
    patch allocation in bounded batches. Their service contract therefore also
    covers bootstrap, routing and reset of the port auxiliaries themselves.
    Readout operates on terminal nonce bits. The auxiliary patches remain live
    throughout all quantum phases, even if their own service is currently idle.
    """
    name: str
    initialization_ports: int
    readout_ports: int
    patches_per_initialization_port: int
    patches_per_readout_port: int
    controller_patches: int
    classical_controller_cores: int
    classical_controller_memory_bytes: int

    def validate(self):
        label(self.name, "ARCHITECTURE_NAME")
        for name in ("initialization_ports", "readout_ports", "patches_per_initialization_port",
                     "patches_per_readout_port", "controller_patches",
                     "classical_controller_cores", "classical_controller_memory_bytes"):
            integer(getattr(self, name), "ARCHITECTURE_" + name.upper(), 1, 10**9)
        integer(self.service_patches, "ARCHITECTURE_TOTAL_SERVICE_PATCHES", 1, 10**12)

    @property
    def service_patches(self):
        return (self.initialization_ports * self.patches_per_initialization_port
                + self.readout_ports * self.patches_per_readout_port + self.controller_patches)


def declared_architectures():
    """Predeclared examples; adding ports never changes noise or deadline premises."""
    return tuple(ServiceArchitecture(
        name=f"declared-reset-{ports}-readout-{readout}-v1",
        initialization_ports=ports, readout_ports=readout,
        patches_per_initialization_port=2, patches_per_readout_port=2,
        controller_patches=8, classical_controller_cores=1,
        classical_controller_memory_bytes=1024 * 1024)
        for ports, readout in ((1, 1), (1024, 8), (65536, 64)))


def build_service_architecture(domains, schedule, processors, classical_costs, physical_model,
                               lifecycle_model, architecture, physical_qubit_budget, horizon_seconds,
                               *, predicate="full", reserved_maximum_winners=1):
    """Build the complete modeled allocation before comparing delivery probability."""
    if type(architecture) is not ServiceArchitecture:
        raise ValueError("ARCHITECTURE_TYPE")
    architecture.validate()
    if type(lifecycle_model) is not LifecycleModel:
        raise ValueError("ARCHITECTURE_LIFECYCLE_TYPE")
    lifecycle_model.validate()
    sources = _sources()
    service = replace(lifecycle_model,
        name=architecture.name,
        initialization_parallel_patches=architecture.initialization_ports,
        readout_parallel_bits=architecture.readout_ports)
    machine = build_machine_envelope(domains, schedule, processors, classical_costs,
        physical_model, service, physical_qubit_budget, horizon_seconds, predicate=predicate,
        reserved_maximum_winners=reserved_maximum_winners,
        reserved_service_patches_per_processor=architecture.service_patches)
    envelope, rounds = machine["envelope"], machine["planned_rounds"]
    # This reserves the complete planned schedule, even when first-winner policy
    # or the deadline would stop sooner. K winner services use the largest cost
    # in the declared domains; there is no refund based on an observed outcome.
    search_seconds = sum((_fraction(row["search_seconds_exact"]) for row in rounds), Fraction(0))
    maximum_winner_seconds = max(_fraction(row["winner_seconds_exact"]) for row in rounds)
    provisioned_seconds = search_seconds + reserved_maximum_winners * maximum_winner_seconds
    initialization_ports = bounded(processors * architecture.initialization_ports)
    readout_ports = bounded(processors * architecture.readout_ports)
    controller_cores = bounded(processors * architecture.classical_controller_cores)
    controller_memory = bounded(processors * architecture.classical_controller_memory_bytes)
    distance = envelope["code_distance_for_whole_schedule"]
    resources = {
        "physical_qubits": envelope["physical_qubits_all_processors"],
        "oracle_logical_patches": bounded(processors * envelope["oracle_logical_patches_per_processor"]),
        "service_logical_patches": bounded(processors * architecture.service_patches),
        "initialization_service_ports": initialization_ports,
        "readout_service_ports": readout_ports,
        "classical_controller_cores_reserved": controller_cores,
        "classical_controller_memory_bytes_reserved": controller_memory,
        "initialized_patches": envelope["events_all_processors"]["initialization_patches"],
        "controller_commands": envelope["events_all_processors"]["controller_commands"],
        "planned_t_states": envelope["events_all_processors"]["magic_state_services"],
        "planned_transfer_bytes": envelope["events_all_processors"]["transfer_bytes"],
        "planned_host_calls_including_proofs": envelope["events_all_processors"]["host_calls_including_reserved_proofs"],
        "initialization_port_code_cycles_reserved": bounded(initialization_ports * distance * sum(
            row["cycles_per_distance_per_processor"]["initialize"] for row in rounds)),
        "readout_port_code_cycles_reserved": bounded(readout_ports * distance * sum(
            row["cycles_per_distance_per_processor"]["terminal_readout"] for row in rounds)),
        "complete_plan_seconds_reserved": ratio(provisioned_seconds),
        "physical_qubit_seconds_reserved": ratio(envelope["physical_qubits_all_processors"] * provisioned_seconds),
        "initialization_port_seconds_reserved": ratio(initialization_ports * provisioned_seconds),
        "readout_port_seconds_reserved": ratio(readout_ports * provisioned_seconds),
        "controller_core_seconds_reserved": ratio(controller_cores * provisioned_seconds),
        "controller_memory_byte_seconds_reserved": ratio(controller_memory * provisioned_seconds),
        "measured_complete_machine_energy_joules": None,
        "calibrated_capital_and_operating_cost": None,
        "compiled_controller_peak_memory_bytes": None,
    }
    target = {
        "source_sha256": sources,
        "construction_sha256": [row["construction_sha256"] for row in machine["domain_resources"]],
        "machine_premises": machine["premises"],
        "architecture": asdict(architecture),
        "complete_allocation": resources,
        "whole_plan_failure_union_upper": envelope["whole_plan_failure_union_upper"],
    }
    report = {
        "schema": SCHEMA, "source_sha256": sources,
        "architecture": asdict(architecture), "original_lifecycle_model": asdict(lifecycle_model),
        "machine_record": machine, "resources": resources,
        "calibration_target": target, "calibration_binding_sha256": _hash(target),
        "calibration": {"status": "MISSING_EXTERNAL_EVIDENCE",
            "required_coverage": list(CALIBRATION_REQUIREMENTS),
            "provenance_checks_are_not_physical_qualification": True},
        "scope": {
            "parallel_initialization": "explicit port batches, all oracle and auxiliary patches reset on every trial",
            "readout": "explicit ports, complete terminal nonce readout and existing serial host turnaround/checks",
            "service_resources": "ports and auxiliaries reserved even during idle phases; allocation never refunded after censoring",
            "service_premise": "existing history-conditional service bounds must cover actual bootstrap, routing, decoder and latency at the declared concurrency",
            "factory": "original serial finite retry/reset service unchanged; extra reset ports give no magic-state throughput credit",
            "memory": "declared reservation only; compiled controller image and peak workspace fit remain unverified",
            "cost": "resource vector; missing energy, capital, physical layout and service calibration prevent a scalar economic comparison",
        },
        "claims": {"physical_parameters_calibrated": False,
            "fault_tolerant_layout_and_controller_compiled": False,
            "complete_machine_energy_or_economic_cost": False,
            "same_total_resource_budget_proved": False, "minimum_attacker_cost_proved": False,
            "quantum_hardware_executed": False, "quantum_mining_qualified": False,
            "production_activation": False},
    }
    if _sources() != sources:
        raise ValueError("ARCHITECTURE_SOURCE_CHANGED")
    report["record_sha256"] = _hash(report)
    return report


def verify_service_architecture(report, domains):
    """Reconstruct counts and probabilities; a rehashed hand-edited record fails."""
    if type(report) is not dict or report.get("schema") != SCHEMA:
        raise ValueError("ARCHITECTURE_RECORD")
    for field, cls in (("architecture", ServiceArchitecture), ("original_lifecycle_model", LifecycleModel)):
        if type(report.get(field)) is not dict or set(report[field]) != set(cls.__dataclass_fields__):
            raise ValueError("ARCHITECTURE_SERIALIZED_MODEL")
    machine = report.get("machine_record")
    if type(machine) is not dict or type(machine.get("premises")) is not dict:
        raise ValueError("ARCHITECTURE_MACHINE_RECORD")
    from w1_machine_envelope import verify_machine_envelope
    machine = verify_machine_envelope(machine, domains)
    p = machine["premises"]
    rebuilt = build_service_architecture(domains, tuple(tuple(x) for x in p["schedule"]),
        p["processors"], tuple(ClassicalCosts(**x) for x in p["classical_costs_ns"]),
        PhysicalModel(**p["physical_model"]), LifecycleModel(**report["original_lifecycle_model"]),
        ServiceArchitecture(**report["architecture"]), p["physical_qubit_budget"],
        p["horizon_seconds"], predicate=p["predicate"],
        reserved_maximum_winners=p["reserved_maximum_winners"])
    if canonical(rebuilt) != canonical(report):
        raise ValueError("ARCHITECTURE_REPLAY_MISMATCH")
    return rebuilt


def _sha(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("CALIBRATION_SHA256")
    return value


def validate_calibration_manifest(report, manifest, artifact_bytes, *, now_unix_seconds,
                                   maximum_age_seconds):
    """Validate coverage/provenance only, never the truth of physical claims.

    ``report`` must already have been built or reconstructed in this process.
    Exact current source and its hash are checked again. Artifacts are bytes
    supplied by the caller, not remote URLs or arbitrary filesystem paths. The
    valid result explicitly remains unqualified, including for complete bundles.
    """
    if (type(report) is not dict or report.get("schema") != SCHEMA
            or report.get("source_sha256") != _sources()
            or report.get("record_sha256") != _hash({k: v for k, v in report.items() if k != "record_sha256"})
            or report.get("calibration_binding_sha256") != _hash(report.get("calibration_target"))):
        raise ValueError("CALIBRATION_TARGET_NOT_CURRENT")
    integer(now_unix_seconds, "CALIBRATION_NOW", 0, 1 << 63)
    integer(maximum_age_seconds, "CALIBRATION_MAXIMUM_AGE", 1, 366 * 24 * 3600)
    keys = {"schema", "target_binding_sha256", "hardware_id", "recorded_at_unix_seconds",
            "valid_until_unix_seconds", "coverage", "artifacts"}
    if type(manifest) is not dict or set(manifest) != keys or manifest["schema"] != CALIBRATION_SCHEMA:
        raise ValueError("CALIBRATION_MANIFEST_SCHEMA")
    if _sha(manifest["target_binding_sha256"]) != report["calibration_binding_sha256"]:
        raise ValueError("CALIBRATION_TARGET_BINDING")
    label(manifest["hardware_id"], "CALIBRATION_HARDWARE_ID")
    begin, end = manifest["recorded_at_unix_seconds"], manifest["valid_until_unix_seconds"]
    integer(begin, "CALIBRATION_RECORDED_TIME", 0, 1 << 63)
    integer(end, "CALIBRATION_EXPIRY_TIME", 0, 1 << 63)
    if not begin <= now_unix_seconds <= end or now_unix_seconds - begin > maximum_age_seconds:
        raise ValueError("CALIBRATION_STALE_OR_FUTURE")
    coverage, artifacts = manifest["coverage"], manifest["artifacts"]
    if type(coverage) is not list or len(coverage) != len(CALIBRATION_REQUIREMENTS):
        raise ValueError("CALIBRATION_INCOMPLETE_COVERAGE")
    if type(artifacts) is not list or not 1 <= len(artifacts) <= len(CALIBRATION_REQUIREMENTS):
        raise ValueError("CALIBRATION_ARTIFACT_LIST")
    if type(artifact_bytes) is not dict or len(artifact_bytes) != len(artifacts):
        raise ValueError("CALIBRATION_ARTIFACT_BIJECTION")
    declared, total = {}, 0
    for artifact in artifacts:
        if type(artifact) is not dict or set(artifact) != {"sha256", "bytes", "provenance"}:
            raise ValueError("CALIBRATION_ARTIFACT_METADATA")
        sha = _sha(artifact["sha256"])
        if sha in declared:
            raise ValueError("CALIBRATION_DUPLICATE_ARTIFACT")
        integer(artifact["bytes"], "CALIBRATION_ARTIFACT_SIZE", 1, MAX_CALIBRATION_ARTIFACT_BYTES)
        provenance = artifact["provenance"]
        if type(provenance) is not str or not 1 <= len(provenance) <= 4096 or any(ord(x) < 32 for x in provenance):
            raise ValueError("CALIBRATION_PROVENANCE")
        raw = artifact_bytes.get(sha)
        if type(raw) is not bytes or len(raw) != artifact["bytes"] or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError("CALIBRATION_ARTIFACT_BYTES")
        total += len(raw)
        if total > MAX_CALIBRATION_TOTAL_BYTES:
            raise ValueError("CALIBRATION_ARTIFACT_TOTAL_BUDGET")
        declared[sha] = artifact
    if set(artifact_bytes) != set(declared):
        raise ValueError("CALIBRATION_ARTIFACT_BIJECTION")
    seen, used = set(), set()
    for claim in coverage:
        if type(claim) is not dict or set(claim) != {"requirement", "artifact_sha256", "statement"}:
            raise ValueError("CALIBRATION_COVERAGE_SHAPE")
        name = claim["requirement"]
        if type(name) is not str or name not in CALIBRATION_REQUIREMENTS or name in seen:
            raise ValueError("CALIBRATION_COVERAGE_IDENTITY")
        sha = _sha(claim["artifact_sha256"])
        if sha not in declared:
            raise ValueError("CALIBRATION_UNBOUND_CLAIM")
        statement = claim["statement"]
        if type(statement) is not str or not 1 <= len(statement) <= 4096 or any(ord(x) < 32 for x in statement):
            raise ValueError("CALIBRATION_STATEMENT")
        seen.add(name)
        used.add(sha)
    if seen != set(CALIBRATION_REQUIREMENTS) or used != set(declared):
        raise ValueError("CALIBRATION_INCOMPLETE_COVERAGE")
    return {
        "schema": "trnm-w1-calibration-provenance-review-v1",
        "status": "PROVENANCE_AND_COVERAGE_ONLY",
        "target_binding_sha256": report["calibration_binding_sha256"],
        "manifest_sha256": _hash(manifest), "hardware_id": manifest["hardware_id"],
        "checked_at_unix_seconds": now_unix_seconds,
        "maximum_age_seconds": maximum_age_seconds, "artifact_bytes_checked": total,
        "coverage": sorted(seen), "artifact_sha256": sorted(declared),
        "artifact_authenticity_or_claim_truth_verified": False,
        "conditional_error_bounds_established": False,
        "calibrated_complete_machine_cost_closed": False,
        "quantum_hardware_executed_by_reader": False,
        "quantum_mining_qualified": False,
    }
