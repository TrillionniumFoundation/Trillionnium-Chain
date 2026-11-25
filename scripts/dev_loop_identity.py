"""Independently bind a paired development evaluation to Hepta's loop identity.

Identity equality neither authenticates people nor grants funding authority.
Bound v2 requests keep the complete identity inside the bytes committed by the
existing native contract. Historical v1 requests remain historical v1 requests.
"""

import hashlib
import importlib.metadata
import os
import re
import sys
from pathlib import Path

from dev_circuit_evaluation import digest, read, require, sha, source_files

ADMISSION = "trnm-isolated-bound-paired-evaluation-request-v2"
DELIVERY = "trnm-isolated-bound-paired-evaluation-delivery-v2"
ARTIFACT_ADMISSION = "trnm-isolated-bound-paired-evaluation-request-v3"
ARTIFACT_DELIVERY = "trnm-isolated-bound-paired-evaluation-delivery-v3"
LOOP_V1 = "hepta.paired-learning.loop-identity.v1"
LOOP_V2 = "hepta.paired-learning.loop-identity.v2"
PACKAGES = ("torch", "transformers", "peft", "tokenizers", "safetensors")
CHAIN_SOURCES = ("dev_circuit_evaluation.py", "dev_intake_evaluation.py", "dev_loop_identity.py")
ARTIFACT_CHAIN_SOURCES = (*CHAIN_SOURCES, "dev_runtime_artifacts.py")


def schemas(identity):
    require(identity.get("schema") in (LOOP_V1, LOOP_V2), "unknown loop identity")
    return (ARTIFACT_ADMISSION, ARTIFACT_DELIVERY) if identity["schema"] == LOOP_V2 else (ADMISSION, DELIVERY)


def chain_sources(identity=None):
    names = ARTIFACT_CHAIN_SOURCES if identity is not None and identity["schema"] == LOOP_V2 else CHAIN_SOURCES
    return {name: sha((Path(__file__).parent / name).read_bytes()) for name in names}


def runtime_identity(entries, *, runtime_artifacts=None, artifact_root=None):
    require((runtime_artifacts is None) == (artifact_root is None), "runtime manifest and material root required together")
    require(len({row["path"] for row in entries}) == len(entries), "duplicate implementation path")
    with Path(sys.executable).resolve(strict=True).open("rb") as stream:
        executable = hashlib.file_digest(stream, "sha256").hexdigest()
    observed = dict(package_sha256=digest({row["path"]: row["sha256"] for row in entries}),
                python=sys.version, executable_sha256=executable,
                packages={name: importlib.metadata.version(name) for name in PACKAGES},
                dependency_identity_kind="installed_versions_only", runtime_closure_complete=False)
    if runtime_artifacts is not None:
        import dev_runtime_artifacts as artifacts

        artifacts.verify_installed(runtime_artifacts, artifact_root, PACKAGES)
        observed.update(dependency_identity_kind="verified_runtime_artifacts_v1", runtime_artifacts=runtime_artifacts)
    return observed


def observed_runtime(entries, identity):
    if identity.get("schema") == LOOP_V2:
        root = os.environ.get("TRNM_DEV_RUNTIME_ARTIFACTS_ROOT")
        require(root is not None, "artifact-bound loop requires actual runtime material root")
        return runtime_identity(entries, runtime_artifacts=identity["implementation"]["runtime_artifacts"], artifact_root=root)
    return runtime_identity(entries)


def validate(identity, expected, release, request, frozen, *, runtime=None):
    require(isinstance(identity, dict) and digest(identity) == expected,
            "independently retained loop identity differs")
    schemas(identity)
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
        schema=identity["schema"], release=release,
        release_sha256=digest(release), family=candidate["family"], model_schema=candidate["schema"],
        parent_sha256=digest(parent), candidate_sha256=digest(candidate),
        source_exposure_sha256=digest(candidate.get("paired_source_exposure")),
        router_sha256=digest(candidate.get("router")),
        model_runtime_sha256=digest({arm: request[arm]["runtime"] for arm in ("parent", "candidate")}),
        evaluation_sha256=digest({key: request[key] for key in ("future", "retention", "timeout_seconds")}),
        native_consent_sha256=native, implementation=identity["implementation"])
    require(identity == expected_identity, "loop model, data, route, evaluation or release differs")
    implementation = identity["implementation"]
    artifact_bound = identity["schema"] == LOOP_V2
    fields = {"package_sha256", "python", "executable_sha256", "packages",
              "dependency_identity_kind", "runtime_closure_complete"}
    kind = "verified_runtime_artifacts_v1" if artifact_bound else "installed_versions_only"
    require(set(implementation) == (fields | {"runtime_artifacts"} if artifact_bound else fields)
            and set(implementation["packages"]) == set(PACKAGES)
            and implementation["dependency_identity_kind"] == kind
            and implementation["runtime_closure_complete"] is False, "unexpected executable identity scope")
    if artifact_bound:
        import dev_runtime_artifacts as artifacts

        artifacts.validate(implementation["runtime_artifacts"])
    if runtime is not None:
        require(implementation == runtime, "actual source, interpreter or dependency differs")
    return expected


def check_terms(job, terms, *, live=False):
    require(terms["schema"] in (ADMISSION, ARTIFACT_ADMISSION), "bound v2 or artifact-bound v3 request required")
    identity = terms["loop_identity"]
    require((terms["schema"], terms["output_schema"]) == schemas(identity), "bound request and identity namespace differ")
    value = validate(identity, terms["loop_identity_sha256"], terms["intake_release"],
                     read(job / "PAIRED_INPUT.json"), read(job / "FROZEN.json"),
                     runtime=observed_runtime(source_files(job / "runtime/cell_experiments"), identity) if live else None)
    listing = read(job / "SOURCE.json")["package"]
    require(identity["implementation"]["package_sha256"] == digest({r["path"]: r["sha256"] for r in listing}),
            "retained evaluator implementation differs")
    names = ARTIFACT_CHAIN_SOURCES if identity["schema"] == LOOP_V2 else CHAIN_SOURCES
    require(set(terms["chain_evaluator_sources"]) == set(names), "missing Chain evaluator source pins")
    if live:
        require(terms["chain_evaluator_sources"] == chain_sources(identity), "Chain evaluator source changed")
    return value


def join_readback(job, readback, expected_readback):
    """Re-read native development payment and compare; never promote a JSON claim to authority."""
    from dev_circuit_evaluation import verify

    require(digest(readback) == expected_readback
            and readback["schema"] in ("hepta.paired-learning.loop-readback.v1", "hepta.paired-learning.loop-readback.v2"),
            "retained consumer readback differs")
    terms = read(job / "ADMISSION.json")
    pin = check_terms(job, terms)
    version = "v2" if terms["loop_identity"]["schema"] == LOOP_V2 else "v1"
    require(readback["schema"] == "hepta.paired-learning.loop-readback." + version, "consumer readback namespace differs")
    require(readback["loop_sha256"] == pin and readback["loop_identity"] == terms["loop_identity"],
            "consumer and funded evaluation belong to different loops")
    native = verify(job, expected_release=terms["intake_release_sha256"])
    return dict(schema="trnm-bound-consumer-evaluation-readback-" + version, loop_sha256=pin,
                native_evaluation_request_sha256=sha((job / "ADMISSION.json").read_bytes()),
                consumer_readback_sha256=expected_readback, same_released_pair=True,
                development_evaluation=native, live_consumer_authority_reverified=False,
                independent_business_effect_verified=False, settlement_authorized=False,
                learning_reward_authorized=False, consensus_credit_authorized=False)
