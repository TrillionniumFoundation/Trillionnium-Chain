"""Independently bind a paired development evaluation to Hepta's loop identity.

Identity equality neither authenticates people nor grants funding authority.
Bound v2 requests keep the complete identity inside the bytes committed by the
existing native contract. Historical v1 requests remain historical v1 requests.
"""

import hashlib
import importlib.metadata
import re
import sys
from pathlib import Path

from dev_circuit_evaluation import digest, read, require, sha, source_files

ADMISSION = "trnm-isolated-bound-paired-evaluation-request-v2"
DELIVERY = "trnm-isolated-bound-paired-evaluation-delivery-v2"
PACKAGES = ("torch", "transformers", "peft", "tokenizers", "safetensors")
CHAIN_SOURCES = ("dev_circuit_evaluation.py", "dev_intake_evaluation.py", "dev_loop_identity.py")


def chain_sources():
    return {name: sha((Path(__file__).parent / name).read_bytes()) for name in CHAIN_SOURCES}


def runtime_identity(entries):
    require(len({row["path"] for row in entries}) == len(entries), "duplicate implementation path")
    with Path(sys.executable).resolve(strict=True).open("rb") as stream:
        executable = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(package_sha256=digest({row["path"]: row["sha256"] for row in entries}),
                python=sys.version, executable_sha256=executable,
                packages={name: importlib.metadata.version(name) for name in PACKAGES},
                dependency_identity_kind="installed_versions_only", runtime_closure_complete=False)


def validate(identity, expected, release, request, frozen, *, runtime=None):
    require(isinstance(identity, dict) and digest(identity) == expected,
            "independently retained loop identity differs")
    require(identity.get("schema") == "hepta.paired-learning.loop-identity.v1", "unknown loop identity")
    for key in ("study_sha256", "admission_sha256", "freeze_sha256", "candidate_sha256", "request_sha256"):
        require(isinstance(release.get(key), str) and re.fullmatch("[0-9a-f]{64}", release[key])
                and release[key] != "0" * 64, "invalid release identity")
    require(release["schema"] == "hepta.paired-intake.release.v1"
            and release["scope"] in ("owner_intake", "engineering_fixture"), "unknown release scope")
    require(request["schema"] == "hepta.paired-cold.request.v1"
            and frozen["schema"] == "hepta.paired-cold.freeze.v1"
            and all(frozen[key] == request[key] for key in ("parent", "candidate", "retention", "timeout_seconds"))
            and digest(frozen) == release["freeze_sha256"]
            and digest(request) == release["request_sha256"], "freeze or request differs")
    parent, candidate = request["parent"], request["candidate"]
    require(parent["family"] == candidate["family"]
            and parent["schema"] == candidate["schema"] == "hepta.experimental-model.v1"
            and candidate["parent"] == digest(parent)
            and digest(candidate) == release["candidate_sha256"], "one ordinary model family required")
    native = identity.get("native_consent_sha256")
    require(isinstance(native, str) and re.fullmatch("[0-9a-f]{64}", native)
            and native != "0" * 64, "missing native consent identity")
    expected_identity = dict(
        schema="hepta.paired-learning.loop-identity.v1", release=release,
        release_sha256=digest(release), family=candidate["family"], model_schema=candidate["schema"],
        parent_sha256=digest(parent), candidate_sha256=digest(candidate),
        source_exposure_sha256=digest(candidate.get("paired_source_exposure")),
        router_sha256=digest(candidate.get("router")),
        model_runtime_sha256=digest({arm: request[arm]["runtime"] for arm in ("parent", "candidate")}),
        evaluation_sha256=digest({key: request[key] for key in ("future", "retention", "timeout_seconds")}),
        native_consent_sha256=native, implementation=identity["implementation"])
    require(identity == expected_identity, "loop model, data, route, evaluation or release differs")
    implementation = identity["implementation"]
    require(set(implementation) == {"package_sha256", "python", "executable_sha256", "packages",
                                    "dependency_identity_kind", "runtime_closure_complete"}
            and set(implementation["packages"]) == set(PACKAGES)
            and implementation["dependency_identity_kind"] == "installed_versions_only"
            and implementation["runtime_closure_complete"] is False, "unexpected executable identity scope")
    if runtime is not None:
        require(implementation == runtime, "actual source, interpreter or dependency differs")
    return expected


def check_terms(job, terms, *, live=False):
    require(terms["schema"] == ADMISSION and terms["output_schema"] == DELIVERY, "bound v2 request required")
    identity = terms["loop_identity"]
    value = validate(identity, terms["loop_identity_sha256"], terms["intake_release"],
                     read(job / "PAIRED_INPUT.json"), read(job / "FROZEN.json"),
                     runtime=runtime_identity(source_files(job / "runtime/cell_experiments")) if live else None)
    listing = read(job / "SOURCE.json")["package"]
    require(identity["implementation"]["package_sha256"] == digest({r["path"]: r["sha256"] for r in listing}),
            "retained evaluator implementation differs")
    require(set(terms["chain_evaluator_sources"]) == set(CHAIN_SOURCES), "missing Chain evaluator source pins")
    if live:
        require(terms["chain_evaluator_sources"] == chain_sources(), "Chain evaluator source changed")
    return value


def join_readback(job, readback, expected_readback):
    """Re-read native development payment and compare; never promote a JSON claim to authority."""
    from dev_circuit_evaluation import verify

    require(digest(readback) == expected_readback
            and readback["schema"] == "hepta.paired-learning.loop-readback.v1", "retained consumer readback differs")
    terms = read(job / "ADMISSION.json")
    pin = check_terms(job, terms)
    require(readback["loop_sha256"] == pin and readback["loop_identity"] == terms["loop_identity"],
            "consumer and funded evaluation belong to different loops")
    native = verify(job, expected_release=terms["intake_release_sha256"])
    return dict(schema="trnm-bound-consumer-evaluation-readback-v1", loop_sha256=pin,
                native_evaluation_request_sha256=sha((job / "ADMISSION.json").read_bytes()),
                consumer_readback_sha256=expected_readback, same_released_pair=True,
                development_evaluation=native, live_consumer_authority_reverified=False,
                independent_business_effect_verified=False, settlement_authorized=False,
                learning_reward_authorized=False, consensus_credit_authorized=False)
