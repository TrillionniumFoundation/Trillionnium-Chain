"""Bind a released ordinary paired request to one isolated native development evaluation."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from dev_circuit_evaluation import digest, execute, prepare, read, require, sha
from dev_loop_identity import ADMISSION as BOUND_ADMISSION, DELIVERY as BOUND_DELIVERY
from dev_loop_identity import ARTIFACT_ADMISSION, ARTIFACT_DELIVERY

ADMISSION = "trnm-isolated-plain-paired-evaluation-request-v1"
DELIVERY = "trnm-isolated-plain-paired-evaluation-delivery-v1"
ADMISSIONS = {ADMISSION: DELIVERY, BOUND_ADMISSION: BOUND_DELIVERY, ARTIFACT_ADMISSION: ARTIFACT_DELIVERY}
BOUND_ADMISSIONS = {BOUND_ADMISSION, ARTIFACT_ADMISSION}
STUDY = "00e43fc72bb1cc2545d6f1d13fa67c448f413343c5e0c3ce1fdd9de91086f5fa"
FIELDS = {"study_sha256", "freeze_sha256", "candidate_sha256", "request_sha256", "admission_sha256"}


def requires_retention(release, candidate):
    return release["scope"] == "owner_intake" and "paired_source_exposure" in candidate


def check_release(release, commitment, pins, candidate, *, expected_study=STUDY):
    require(isinstance(release, dict) and release.get("schema") == "hepta.paired-intake.release.v1",
            "unexpected intake release shape")
    require(release.get("scope") in {"engineering_fixture", "owner_intake"}, "unknown intake scope")
    fields = FIELDS
    if requires_retention(release, candidate):
        require("source_retention_sha256" in release, "source owner release lacks pre-arrival retention")
        fields = fields | {"source_retention_sha256"}
    require(set(release) == fields | {"schema", "scope"}, "unexpected intake release shape")
    for key in fields:
        value = release[key]
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) and value != "0" * 64,
                "invalid intake release digest")
    require(digest(release) == commitment and release["study_sha256"] == expected_study and
            all(release[key + "_sha256"] == pins[key] for key in ("request", "candidate", "freeze")),
            "release differs from retained reference, study, or paired input")


def original_retention(report_path, retention_pin):
    report = read(report_path)
    require(digest(report) == retention_pin, "owner retention differs from original release")
    require(report["decision"] == "eligible_for_prospective_evaluation" and report["scope"] == "owner_intake",
            "original source qualification did not authorize prospective work")
    return report


def check_retention_record(job, terms):
    release = terms["intake_release"]
    candidate = read(job / "FROZEN.json")["candidate"]
    study = terms["loop_identity"]["release"]["study_sha256"] if terms["schema"] in BOUND_ADMISSIONS else STUDY
    check_release(release, terms["intake_release_sha256"], terms["pins"], candidate, expected_study=study)
    if requires_retention(release, candidate):
        pin = release["source_retention_sha256"]
        require(terms.get("source_retention_sha256") == pin, "signed retention differs from owner release")
        original_retention(job / "SOURCE_RETENTION.json", pin)
    else:
        require("source_retention_sha256" not in terms, "unexpected signed source retention")


def manifest_exposure(candidate):
    exposure = candidate.get("paired_source_exposure")
    if exposure is not None:
        require(isinstance(exposure, dict) and exposure.get("schema") == "hepta.paired-learning.source-exposure.v1",
                "unsupported candidate exposure encoding")
        for key in ("record_digests", "known_prompt_hashes", "input_ids_sha256", "source_keys"):
            values = exposure.get(key)
            require(isinstance(values, list) and values and all(
                isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in values), "missing bound source exposure digests")
        require(isinstance(exposure.get("registered_catalogs"), list), "missing inherited source protections")
    return exposure


def catalog_snapshot(job, source, freeze):
    candidate = read(job / "FROZEN.json")["candidate"]
    embedded = manifest_exposure(candidate)
    matches = [path for path in (source / "qualification").glob("*/prospective-exposures.json")
               if path.is_file() and not path.is_symlink() and read(path).get("freeze_sha256") == freeze]
    require(len(matches) <= 1 and (matches or embedded is not None), "missing or ambiguous exposure catalog")
    entry = {}
    if matches:
        original = matches[0]
        relative = original.relative_to(source)
        target = job / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = original.read_bytes()
        with target.open("xb") as handle:
            handle.write(raw)
        entry.update(path=relative.as_posix(), sha256=sha(raw))
    if embedded is not None:
        entry["manifest_exposure_sha256"] = digest(embedded)
    return entry


def check_catalog(job, entry, freeze):
    frozen = read(job / "FROZEN.json")
    require(digest(frozen) == freeze, "immutable source freeze differs")
    embedded = manifest_exposure(frozen["candidate"])
    if embedded is not None:
        require(entry.get("manifest_exposure_sha256") == digest(embedded),
                "candidate manifest exposure commitment differs")
    else:
        require("manifest_exposure_sha256" not in entry, "unbound manifest exposure")
    if not ({"path", "sha256"} & entry.keys()):
        require(embedded is not None and set(entry) == {"manifest_exposure_sha256"}, "missing registered catalog")
        return
    require(set(entry) == ({"path", "sha256", "manifest_exposure_sha256"} if embedded is not None
                           else {"path", "sha256"}), "unexpected exposure commitments")
    path = Path(entry["path"])
    require(len(path.parts) == 3 and path.parts[0] == "qualification" and path.parts[1] not in {".", ".."}
            and path.parts[2] == "prospective-exposures.json", "invalid catalog path")
    evidence = job / path
    require(not evidence.is_symlink() and sha(evidence.read_bytes()) == entry["sha256"] and
            read(evidence)["freeze_sha256"] == freeze, "exposure catalog differs")


def check_plain_result(result, terms):
    require(result["schema"] == "hepta.paired-cold.result.v1" and result["circuit_loaded"] is False and
            result["request_sha256"] == terms["pins"]["request"] and result["external_teacher_calls_by_runner"] == 0
            and all(result[key] is False for key in ("authenticated_users_established",
                                                     "prospective_arrival_authenticated", "production_adoption",
                                                     "settlement")), "unqualified paired result")
    receipts = result["cold_receipts"]
    require([r["arm"] for r in receipts] == ["parent", "candidate"] and receipts[0]["pid"] != receipts[1]["pid"]
            and [r["model_digest"] for r in receipts] == [terms["parent"], terms["pins"]["candidate"]]
            and all(r["request_sha256"] == terms["pins"]["request"] for r in receipts)
            and sum(len(r["row_hashes"]) for r in receipts) == terms["evaluated_examples"],
            "paired receipt differs from reservation")


def preflight(job, materials, request, retention_pin=None):
    env = dict(os.environ, PYTHONPATH=str(job / "runtime"), PYTHONDONTWRITEBYTECODE="1",
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false")
    subprocess.run(["unshare", "-Urn", "--", sys.executable, "-B", __file__,
                    "preflight", str(job), str(materials), request, *([retention_pin] if retention_pin else [])],
                   cwd=job, env=env, check=True)


if __name__ == "__main__":
    mode, directory, materials_path, *args = sys.argv[1:]
    if mode == "inspect-source":
        Path(directory).mkdir(mode=0o700, parents=False, exist_ok=False)
    job = Path(directory).resolve(strict=True)
    materials = Path(materials_path).resolve(strict=True)
    if mode == "preflight":
        from cell_experiments import paired_cold

        require(len(args) in (1, 2), "expected a request and optional owner retention digest")
        request_digest = args[0]
        if len(args) == 2:
            from cell_experiments import paired_source_dispatch

            actual = paired_source_dispatch.authorize(read(job / "FROZEN.json"),
                {"source_retention_sha256": args[1]}, job / "SOURCE_RETENTION.json")
            require(actual == args[1], "source authority retention digest differs")
        req = paired_cold.checked_request(job / "PAIRED_INPUT.json", request_digest)
        embedded = manifest_exposure(req["candidate"])
        if embedded is not None:
            from cell_experiments import paired_source

            paired_source.check_future(req)
        for arm in paired_cold.ARMS:
            require(paired_cold.verify_materials(req[arm], materials) == digest(req[arm]), "material pin differs")
            encoded = paired_cold.token_inputs(req, req[arm], materials)
            if embedded is not None:
                known = set(embedded["input_ids_sha256"])
                require(all(encoded[row["task_id"]] not in known for row in req["future"]),
                        "request repeats a trained source input")
    elif mode in ("inspect-source", "prepare", "prepare-bound"):
        source_path, freeze, request, candidate = args
        pins = dict(freeze=freeze, request=request, candidate=candidate)
        frozen_file = Path(os.environ.get("TRNM_DEV_FROZEN_FILE", materials / "FROZEN.json")).resolve(strict=True)
        frozen = read(frozen_file)
        require(digest(frozen) == pins["freeze"] and digest(frozen["candidate"]) == pins["candidate"],
                "retained freeze or candidate differs before dispatch")
        release = None
        loop_identity, expected_loop = None, None
        inspect_only = mode == "inspect-source"
        if not inspect_only:
            release = read(Path(os.environ["TRNM_DEV_INTAKE_RELEASE"]))
            commitment = os.environ["TRNM_DEV_INTAKE_RELEASE_SHA256"]
            study = os.environ["TRNM_DEV_STUDY_SHA256"] if mode == "prepare-bound" else STUDY
            check_release(release, commitment, pins, frozen["candidate"], expected_study=study)
            if mode == "prepare-bound":
                loop_identity = read(Path(os.environ["TRNM_DEV_LOOP_IDENTITY_FILE"]))
                expected_loop = os.environ["TRNM_DEV_LOOP_IDENTITY_SHA256"]
        result = prepare(job, materials, Path(source_path).resolve(strict=True), pins, intake=release,
                         request_path=Path(os.environ["TRNM_DEV_PAIRED_REQUEST_FILE"]).resolve(strict=True),
                         frozen_path=frozen_file,
                         inspect_only=inspect_only, loop_identity=loop_identity, expected_loop=expected_loop)
        if inspect_only:
            print(json.dumps(result, sort_keys=True))
    elif mode == "execute" and not args:
        execute(job, materials)
    else:
        raise ValueError("expected prepare or execute")
