"""Bind a released ordinary paired request to one isolated native development evaluation."""
import os
import re
import subprocess
import sys
from pathlib import Path

from dev_circuit_evaluation import digest, execute, prepare, read, require, sha

ADMISSION = "trnm-isolated-plain-paired-evaluation-request-v1"
DELIVERY = "trnm-isolated-plain-paired-evaluation-delivery-v1"
STUDY = "00e43fc72bb1cc2545d6f1d13fa67c448f413343c5e0c3ce1fdd9de91086f5fa"
FIELDS = {"study_sha256", "freeze_sha256", "candidate_sha256", "request_sha256", "admission_sha256"}


def check_release(release, commitment, pins):
    require(isinstance(release, dict) and set(release) == FIELDS | {"schema", "scope"} and
            release["schema"] == "hepta.paired-intake.release.v1", "unexpected intake release shape")
    require(release["scope"] in {"engineering_fixture", "owner_intake"}, "unknown intake scope")
    for key in FIELDS:
        value = release[key]
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) and value != "0" * 64,
                "invalid intake release digest")
    require(digest(release) == commitment and release["study_sha256"] == STUDY and
            all(release[key + "_sha256"] == pins[key] for key in ("request", "candidate", "freeze")),
            "release differs from retained reference, study, or paired input")


def catalog_snapshot(job, source, freeze):
    matches = [path for path in (source / "qualification").glob("*/prospective-exposures.json")
               if path.is_file() and not path.is_symlink() and read(path).get("freeze_sha256") == freeze]
    require(len(matches) == 1, "expected one exposure catalog for the issued freeze")
    original = matches[0]
    relative = original.relative_to(source)
    target = job / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = original.read_bytes()
    with target.open("xb") as handle:
        handle.write(raw)
    return {"path": relative.as_posix(), "sha256": sha(raw)}


def check_catalog(job, entry, freeze):
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


def preflight(job, materials, request):
    env = dict(os.environ, PYTHONPATH=str(job / "runtime"), PYTHONDONTWRITEBYTECODE="1",
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false")
    subprocess.run(["unshare", "-Urn", "--", sys.executable, "-B", __file__,
                    "preflight", str(job), str(materials), request], cwd=job, env=env, check=True)


if __name__ == "__main__":
    mode, directory, materials_path, *args = sys.argv[1:]
    job = Path(directory).resolve(strict=True)
    materials = Path(materials_path).resolve(strict=True)
    if mode == "preflight":
        from cell_experiments import paired_cold

        (request_digest,) = args
        req = paired_cold.checked_request(job / "PAIRED_INPUT.json", request_digest)
        for arm in paired_cold.ARMS:
            require(paired_cold.verify_materials(req[arm], materials) == digest(req[arm]), "material pin differs")
            paired_cold.token_inputs(req, req[arm], materials)
    elif mode == "prepare":
        source_path, freeze, request, candidate = args
        pins = dict(freeze=freeze, request=request, candidate=candidate)
        release = read(Path(os.environ["TRNM_DEV_INTAKE_RELEASE"]))
        commitment = os.environ["TRNM_DEV_INTAKE_RELEASE_SHA256"]
        check_release(release, commitment, pins)
        prepare(job, materials, Path(source_path).resolve(strict=True), pins, intake=release,
                request_path=Path(os.environ["TRNM_DEV_PAIRED_REQUEST_FILE"]).resolve(strict=True))
    elif mode == "execute" and not args:
        execute(job, materials)
    else:
        raise ValueError("expected prepare or execute")
