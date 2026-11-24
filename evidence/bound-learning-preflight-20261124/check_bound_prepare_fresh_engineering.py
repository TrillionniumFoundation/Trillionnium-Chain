#!/usr/bin/env python3
"""New fictional engineering admission over existing weights and an existing catalog.

No old admission is reused. No fitting, generation, real consent, payment, reward,
or scientific qualification occurs. The actual isolated prepare-bound CLI runs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
from types import SimpleNamespace


def main():
    p = argparse.ArgumentParser()
    p.add_argument("hepta", type=Path)
    p.add_argument("chain", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()
    hepta, chain = args.hepta.resolve(strict=True), args.chain.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(mode=0o700, exist_ok=False)
    sys.path[:0] = [str(hepta / "scripts"), str(chain / "scripts")]
    from cell_experiments import coding_sft, data, paired_cold, paired_intake
    from cell_experiments import paired_loop, paired_observation, prospective_exposure
    from cell_experiments.test_paired_consumer import NATIVE
    from cell_experiments.test_prospective_exposure import artificial
    import dev_circuit_evaluation as evaluation
    import dev_loop_identity as bound

    def put(path, value):
        with path.open("xb") as f:
            f.write(data.canonical(value) + b"\n")
        path.chmod(0o600)

    qual = hepta / "qualification/public-historical-a-qwen2-052-20261123"
    original = qual / "run"
    frozen = evaluation.read(original / "FROZEN.json")
    catalog = prospective_exposure.catalog_for(frozen["candidate"])
    freeze = data.digest(frozen)
    assert freeze == catalog["freeze_sha256"]
    source, plan, training = [evaluation.read(original / name) for name in
                              ("source.json", "plan.json", "training.json")]
    assert training["candidate"] == data.digest(frozen["candidate"])
    assert source["target_sha256"] == plan["historical_target"]
    assert (source["file_sha256"], source["revision"], source["row_zero_based"]) == tuple(
        catalog["public_origin"][k] for k in ("parquet_sha256", "revision", "row_zero_based"))
    known = {row["exposure"]: row for row in catalog["known_inputs"]}
    assert set(known) == {"historical_A", "old_rehearsal", "old_retention"}
    assert known["historical_A"]["prompt_sha256"] == source["prompt_sha256"]
    assert known["old_rehearsal"]["prompt_sha256"] == evaluation.sha(b"Give the digit zero.")
    assert known["old_retention"]["prompt_sha256"] == evaluation.sha(frozen["retention"][0]["task"]["input"].encode())
    assert plan["config"]["future_records"] == 0
    assert catalog["known_artifact_sources"] == [r["source"]["sha256"] for r in frozen["retention"]]
    assert catalog["known_record_ids"] == [{k: r[k] for k in ("record_id", "source_id", "task_id")}
                                            for r in frozen["retention"]]
    materials, inbox, home, job = [out / n for n in ("materials", "site", "intake", "job")]
    for directory in (materials, inbox, job):
        directory.mkdir(mode=0o700)
    for arm in ("parent", "candidate"):
        for entry in frozen[arm]["files"]:
            target = materials / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original / entry["path"], target)
        assert paired_cold.verify_materials(frozen[arm], materials) == data.digest(frozen[arm])
        tokenizer = paired_cold.frozen_tokenizer(frozen[arm], materials)
        for label, text in (("old_rehearsal", "Give the digit zero."),
                            ("old_retention", frozen["retention"][0]["task"]["input"])):
            rendered = coding_sft.prompt_text(text, tokenizer, frozen[arm]["runtime"]["message_protocol"])
            assert data.digest(tokenizer.encode(rendered, add_special_tokens=False)) == known[label]["input_ids_sha256"]
    shutil.copyfile(qual / "prospective-exposures.json", out / "REGISTERED_EXPOSURES.json")
    registration = dict(scope="new_engineering_fixture_only", catalog_unchanged=True,
        catalog_sha256=data.digest(catalog), catalog_file_sha256=evaluation.sha((out / "REGISTERED_EXPOSURES.json").read_bytes()),
        source_files={n: evaluation.sha((original / n).read_bytes()) for n in
                      ("source.json", "plan.json", "training.json", "parent-training.json")},
        historical_prompt_pin_matches_original_source=True, historical_parquet_reread=False,
        exact_known_plaintext_token_checks=4, before_new_arrival=True,
        real_humans=False, payment=False, reward=False, scientific_qualification=False)
    put(out / "PREARRIVAL_REGISTRATION.json", registration)
    # The new study binds the retained catalog registration before creating its new B record.
    descriptor = dict(purpose="new fictional prepare-bound integration, no model evaluation",
                      nonce=secrets.token_hex(16), registration_sha256=data.digest(registration))
    study = data.digest(descriptor)
    put(out / "NEW_STUDY.json", descriptor)
    snapshot = out / "FROZEN.json"
    shutil.copyfile(original / "FROZEN.json", snapshot)
    native = out / "SIMULATED_NATIVE_ONLY.py"
    native.write_text(NATIVE)
    native.chmod(0o700)
    paired_observation.observe(inbox, study, freeze, 10)
    paired_intake.install(SimpleNamespace(home=home, study=study, freeze=freeze,
        scope="engineering_fixture", snapshot=snapshot, inbox=inbox, native=native,
        native_sha256=evaluation.sha(native.read_bytes())))
    row = artificial(20261124, "New fictional integration question " + descriptor["nonce"])
    row["authorization"]["rights_basis"] = "synthetic engineering only; no human supplied this task"
    row["source"]["repository"] = "unittest:fictional-bound-preflight-20261124"
    record_pin = data.digest(row)
    arrival, delivery, principal = [data.digest([study, tag]) for tag in
                                    ("fictional arrival", "fictional delivery", "fictional person")]
    paired_observation.observe(inbox, study, freeze, 11, arrival=arrival, record=record_pin,
                               delivery=delivery, principal=principal)
    statement = (f"Hepta paired learning consent v1\nStudy SHA-256: {study}\n"
                 "I authorize Hepta to evaluate the frozen pair on this task. Training on this task is prohibited.\n"
                 f"Pair freeze SHA-256: {freeze}\nTask SHA-256: {record_pin}")
    base = dict(study_sha256=study, delivery_id=delivery)
    route, future = out / "SIMULATED_ROUTE_ONLY.json", out / "FICTIONAL_FUTURE_ONLY.json"
    put(route, dict(request=dict(base, scope=dict(use="evaluate_only", freeze=freeze, task=record_pin)),
        receipt=dict(base, schema="hepta.paired-learning.consent-readback.v1", use="evaluate_only",
                     consent_text_sha256=evaluation.sha(statement.encode()), study_principal_sha256=principal)))
    put(future, [row])
    env = dict(os.environ, PYTHONPATH=str(hepta / "scripts"), PYTHONDONTWRITEBYTECODE="1",
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false")
    command = ["/bin/sh", "-c", 'exec 3</dev/null 4</dev/null; exec "$@"', "fictional-fixture",
        sys.executable, "-B", "-m", "cell_experiments.paired_intake", str(home), "admit",
        arrival, str(snapshot), str(materials), str(future), "fixture-pid", "unused", str(route)]
    admitted = subprocess.run(command, env=env, text=True, capture_output=True)
    (out / "intake.stdout").write_text(admitted.stdout)
    (out / "intake.stderr").write_text(admitted.stderr)
    assert admitted.returncode == 0, admitted.stderr
    admission = admitted.stdout.strip()
    release = paired_intake.release(home, admission)
    with sqlite3.connect(home / "intake.sqlite") as db:
        config = json.loads(db.execute("SELECT value FROM settings").fetchone()[0])
        binding = json.loads(db.execute("SELECT binding FROM admissions WHERE id=?", (admission,)).fetchone()[0])
    request_file = home / admission / "paired.json"
    request = evaluation.read(request_file)
    runtime = paired_loop.implementation()
    identity = paired_loop.identity(config, binding, request, runtime)
    loop_pin = data.digest(identity)
    identity_file = out / "LOOP_IDENTITY.json"
    put(identity_file, identity)
    assert bound.runtime_identity(evaluation.source_files(hepta / "scripts/cell_experiments")) == runtime
    assert bound.validate(identity, loop_pin, release, request, frozen, runtime=runtime) == loop_pin
    env.update(TRNM_DEV_FROZEN_FILE=str(snapshot), TRNM_DEV_PAIRED_REQUEST_FILE=str(request_file),
        TRNM_DEV_INTAKE_RELEASE=str(home / admission / "release.json"),
        TRNM_DEV_INTAKE_RELEASE_SHA256=data.digest(release), TRNM_DEV_STUDY_SHA256=study,
        TRNM_DEV_LOOP_IDENTITY_FILE=str(identity_file), TRNM_DEV_LOOP_IDENTITY_SHA256=loop_pin)
    prepare = [sys.executable, "-B", str(chain / "scripts/dev_intake_evaluation.py"), "prepare-bound",
               str(job), str(materials), str(hepta), *[release[k + "_sha256"] for k in ("freeze", "request", "candidate")]]
    finished = subprocess.run(prepare, env=env, text=True, capture_output=True)
    (out / "prepare.stdout").write_text(finished.stdout)
    (out / "prepare.stderr").write_text(finished.stderr)
    result = dict(schema="trnm-new-engineering-bound-preflight-v1", scope="engineering_fixture",
        status="PASS" if finished.returncode == 0 else "BLOCKED", prepare_command=prepare,
        returncode=finished.returncode, new_study_sha256=study, new_admission_sha256=admission,
        loop_identity_sha256=loop_pin, old_admission_or_payment_reused=False,
        simulated_native_and_person=True, real_humans=False, new_training=False, model_forward=False,
        payment=False, reward=False, scientific_qualification=False, isolated_preflight_unmodified=True,
        historical_parquet_reread=False, original_catalog_unchanged=True,
        actual_implementation=runtime, people_status=paired_intake.people_status(home, admission),
        reservation_exists=(job / "RESERVATION.json").exists(), admission_exists=(job / "ADMISSION.json").exists())
    assert result["reservation_exists"] is False
    if finished.returncode == 0:
        terms = evaluation.read(job / "ADMISSION.json")
        assert terms["schema"] == bound.ADMISSION and terms["loop_identity"] == identity
        assert bound.check_terms(job, terms, live=True) == loop_pin
        assert terms["chain_evaluator_sources"] == bound.chain_sources()
        result.update(check_terms_live=True, admission_file_sha256=evaluation.sha((job / "ADMISSION.json").read_bytes()),
                      source_listing_file_sha256=evaluation.sha((job / "SOURCE.json").read_bytes()))
    else:
        assert result["admission_exists"] is False
        result.update(check_terms_live=None, stderr=finished.stderr)
    put(out / "RESULT.json", result)
    print(json.dumps(result, indent=2))
    return 0 if finished.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
