"""Dispatch a funded, retrospective public A replay with its original retrospective labels."""
import importlib.metadata
import os
from pathlib import Path
import secrets
import shutil
import sys

from dev_circuit_evaluation import attempt_cost_fields, digest, measure, read, record, require, sha, source_files


DRIVERS = ("historical_a.py", "replay_historical.py")
SCOPE = "retrospective_historical_A_and_authored_retention"


def public_digest(path):
    import hashlib

    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def historical_work(frozen, source):
    require(source["public"] is True and source["row_zero_based"] == 52, "wrong public A source")
    return dict(scope=SCOPE, freeze_sha256=digest(frozen), public_parquet_sha256=source["file_sha256"],
                historical_prompt_sha256=source["prompt_sha256"], historical_target_sha256=source["target_sha256"],
                historical_source_row=source["row_zero_based"], retention_digest=digest(frozen["retention"]),
                future_records=0, prospective_arrivals=0, certified_hepta_users=0)


def snapshot(job, hepta):
    original = hepta / "scripts/cell_experiments"
    package = job / "runtime/cell_experiments"
    files = source_files(original)
    for entry in files:
        target = package / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / entry["path"], target)
    require(source_files(package) == files, "source changed while copying")
    qualified = hepta / "qualification/public-historical-a-qwen2-052-20261123"
    drivers = {}
    for name in DRIVERS:
        target = job / "runtime" / name
        shutil.copyfile(qualified / name, target)
        drivers[name] = sha(target.read_bytes())
    return dict(package=files, drivers=drivers)


def prepare(job, materials, source, freeze_pin, parquet_pin, candidate_pin):
    frozen = read(materials / "FROZEN.json")
    metadata = read(materials / "source.json")
    work = historical_work(frozen, metadata)
    require(frozen["schema"] == "hepta.paired-cold.freeze.v1" and digest(frozen) == freeze_pin and
            digest(frozen["candidate"]) == candidate_pin and metadata["file_sha256"] == parquet_pin and
            public_digest(Path(os.environ["TRNM_DEV_PUBLIC_PARQUET"])) == parquet_pin,
            "historical freeze, candidate or public source pin differs")
    package = snapshot(job, source)
    listing = record(job / "SOURCE.json", package)
    shutil.copyfile(materials / "FROZEN.json", job / "FROZEN.json")
    admission = dict(schema="trnm-isolated-historical-evaluation-request-v1", job_id=secrets.token_hex(16),
                     historical_work=work, pins=dict(freeze=freeze_pin, candidate=candidate_pin, request=digest(work)),
                     parent=digest(frozen["parent"]), source_listing_sha256=listing,
                     freeze_file_sha256=sha((job / "FROZEN.json").read_bytes()),
                     runtime=dict(python=sys.version.split()[0],
                                  packages={n: importlib.metadata.version(n) for n in ("torch", "transformers", "pyarrow")}),
                     cpu_limit_ns=1_000_000_000_000, evaluated_examples=4,
                     output_schema="trnm-isolated-historical-evaluation-delivery-v1")
    record(job / "ADMISSION.json", admission)


def execute(job, materials):
    admission = read(job / "ADMISSION.json")
    reservation = read(job / "RESERVATION.json")
    require(reservation["request"] == sha((job / "ADMISSION.json").read_bytes()), "admission mismatch")
    output = job / "evaluation"
    require(not output.exists(), "historical evaluation output exists")
    listing = read(job / "SOURCE.json")
    def source_matches():
        return (sha((job / "SOURCE.json").read_bytes()) == admission["source_listing_sha256"] and
                source_files(job / "runtime/cell_experiments") == listing["package"] and
                {name: sha((job / "runtime" / name).read_bytes()) for name in DRIVERS} == listing["drivers"])
    require(source_matches(), "historical evaluator differs")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(job / "runtime"), os.environ["TRNM_DEV_PYARROW_SITE"])),
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PYTHONDONTWRITEBYTECODE="1", TOKENIZERS_PARALLELISM="false")
    command = ["unshare", "-Urn", "--", sys.executable, "-B", str(job / "runtime/replay_historical.py"),
               os.environ["TRNM_DEV_PUBLIC_PARQUET"], str(materials), str(output)]
    cpu_ns, wall_ns = measure(job, command, env)
    result, expected = read(output / "RESULT.json"), admission["historical_work"]
    require(0 < cpu_ns <= admission["cpu_limit_ns"] and source_matches() and
            read(output / "REQUEST.json") == expected and
            result["request_sha256"] == admission["pins"]["request"] and
            all(result[k] == v for k, v in expected.items()) and
            result["external_teachers_used"] == result["weight_updates"] == 0 and result["adoption"] is False,
            "historical replay changed inputs or scope")
    arms = result["arms"]
    require(arms["parent"]["pid"] != arms["candidate"]["pid"] and
            arms["parent"]["model_sha256"] == admission["parent"] and
            arms["candidate"]["model_sha256"] == admission["pins"]["candidate"] and
            all(set(arms[k]["outcomes"]) == {"historical_training_A", "old_capability"} and
                arms[k]["model_calls"] == 2 for k in ("parent", "candidate")), "wrong tasks, models or workers")
    cost = record(job / "COST.json", dict(schema="trnm-isolated-historical-evaluation-cost-v3",
                  cpu_ns=cpu_ns, wall_ns=wall_ns, evaluated_examples=4,
                  **attempt_cost_fields(job),
                  work={arm:{k:arms[arm][k] for k in ("model_calls","input_tokens","output_tokens")} for arm in arms}))
    files = {p.relative_to(output).as_posix(): sha(p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()}
    record(job / "DELIVERY.json", dict(schema=admission["output_schema"], request=reservation["request"],
        task=reservation["task"], model=admission["pins"]["candidate"], retrospective_request=admission["pins"]["request"],
        reservation_sha256=sha((job / "RESERVATION.json").read_bytes()), result_sha256=files["RESULT.json"],
        cost_sha256=cost, raw_evaluation_files=files))


if __name__ == "__main__":
    mode, job_arg, materials_arg, *extra = sys.argv[1:]
    job, materials = Path(job_arg).resolve(strict=True), Path(materials_arg).resolve(strict=True)
    if mode == "prepare":
        source, *pins = extra
        prepare(job, materials, Path(source).resolve(strict=True), *pins)
    elif mode == "execute" and not extra:
        execute(job, materials)
    else:
        raise ValueError("expected prepare or execute")
