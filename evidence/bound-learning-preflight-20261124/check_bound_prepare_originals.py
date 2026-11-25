#!/usr/bin/env python3
"""Replay only the admission preflight of the retained engineering fixture.

No fitting, inference, authorization issuance, reservation, or payment is performed.
The real prepare-bound CLI and its original unshare isolation are mandatory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import subprocess
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hepta", type=Path)
    parser.add_argument("chain", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    hepta, chain = args.hepta.resolve(strict=True), args.chain.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    sys.path[:0] = [str(hepta / "scripts"), str(chain / "scripts")]
    from cell_experiments import data, paired_loop
    import dev_circuit_evaluation as evaluation
    import dev_loop_identity as bound

    archive = hepta / "qualification/paired-consumer-use-20261123/CONSUMER_ENGINEERING_ORIGINALS.zip"
    inputs = output / "inputs"
    materials = output / "materials"
    job = output / "job"
    for directory in (inputs, materials, job):
        directory.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as z:
        database = z.read("original/intake/intake.sqlite")
        db = sqlite3.connect(":memory:")
        db.deserialize(database)
        config = json.loads(db.execute("SELECT value FROM settings").fetchone()[0])
        rows = db.execute("SELECT id,binding,request_sha,state FROM admissions").fetchall()
        db.close()
        assert config["scope"] == "engineering_fixture"
        assert len(rows) == 1 and rows[0][3] == "released"
        admission, encoded, request_pin, _ = rows[0]
        binding = json.loads(encoded)
        original = "original/intake/" + admission + "/"
        originals = {"FROZEN.json": z.read("original/FROZEN.json"),
                     "paired.json": z.read(original + "paired.json"),
                     "release.json": z.read(original + "release.json")}
        for name, raw in originals.items():
            (inputs / name).write_bytes(raw)
        for entry in z.infolist():
            if not entry.filename.startswith("original/materials/") or entry.is_dir():
                continue
            relative = PurePosixPath(entry.filename.removeprefix("original/materials/"))
            assert not relative.is_absolute() and ".." not in relative.parts
            target = materials.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(z.read(entry))

    frozen, request, release = (json.loads(originals[name]) for name in
                                 ("FROZEN.json", "paired.json", "release.json"))
    runtime = paired_loop.implementation()
    entries = evaluation.source_files(hepta / "scripts/cell_experiments")
    assert runtime == bound.runtime_identity(entries)
    identity = paired_loop.identity(config, binding, request, runtime)
    pin = data.digest(identity)
    assert data.digest(binding) == admission
    assert data.digest(request) == request_pin
    assert identity["release"] == release
    assert bound.validate(identity, pin, release, request, frozen, runtime=runtime) == pin
    identity_file = inputs / "LOOP_IDENTITY.json"
    identity_file.write_bytes(data.canonical(identity) + b"\n")
    chain_sources = bound.chain_sources()
    command = [sys.executable, "-B", str(chain / "scripts/dev_intake_evaluation.py"),
               "prepare-bound", str(job), str(materials), str(hepta),
               *[release[key + "_sha256"] for key in ("freeze", "request", "candidate")]]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", HF_HUB_OFFLINE="1",
               TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false",
               TRNM_DEV_FROZEN_FILE=str(inputs / "FROZEN.json"),
               TRNM_DEV_PAIRED_REQUEST_FILE=str(inputs / "paired.json"),
               TRNM_DEV_INTAKE_RELEASE=str(inputs / "release.json"),
               TRNM_DEV_INTAKE_RELEASE_SHA256=data.digest(release),
               TRNM_DEV_STUDY_SHA256=release["study_sha256"],
               TRNM_DEV_LOOP_IDENTITY_FILE=str(identity_file),
               TRNM_DEV_LOOP_IDENTITY_SHA256=pin)
    completed = subprocess.run(command, env=env, text=True, capture_output=True)
    (output / "stdout.log").write_text(completed.stdout)
    (output / "stderr.log").write_text(completed.stderr)
    assert chain_sources == bound.chain_sources()
    assert runtime == paired_loop.implementation()
    assert entries == evaluation.source_files(hepta / "scripts/cell_experiments")
    result = dict(schema="trnm-bound-originals-preflight-check-v1", scope="engineering_fixture",
                  command=command, returncode=completed.returncode,
                  status="PASS" if completed.returncode == 0 else "BLOCKED",
                  original_archive=str(archive), original_admission_sha256=admission,
                  loop_identity_sha256=pin, actual_runtime=runtime,
                  chain_evaluator_sources=chain_sources,
                  original_file_sha256={k: hashlib.sha256(v).hexdigest() for k, v in originals.items()},
                  original_database_sha256=hashlib.sha256(database).hexdigest(),
                  isolation_unmodified=True, new_training_runs=0, new_human_authorizations=0,
                  model_forward_executed=False, payments_executed=0,
                  reservation_exists=(job / "RESERVATION.json").exists(),
                  admission_exists=(job / "ADMISSION.json").exists())
    assert result["reservation_exists"] is False
    if completed.returncode == 0:
        terms = evaluation.read(job / "ADMISSION.json")
        assert terms["schema"] == bound.ADMISSION
        assert terms["loop_identity"] == identity and terms["loop_identity_sha256"] == pin
        assert terms["chain_evaluator_sources"] == chain_sources
        assert bound.check_terms(job, terms, live=True) == pin
        result.update(check_terms_live=True,
                      admission_file_sha256=evaluation.sha((job / "ADMISSION.json").read_bytes()),
                      source_listing_file_sha256=evaluation.sha((job / "SOURCE.json").read_bytes()))
    else:
        assert result["admission_exists"] is False
        result.update(check_terms_live=None, stderr=completed.stderr)
    (output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if completed.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
