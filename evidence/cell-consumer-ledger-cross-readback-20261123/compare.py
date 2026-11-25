"""Read three archived engineering sources and compare the subjects of their receipts."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

CHAIN = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CHAIN / "scripts"))
import cell_learning_business_join as business
import dev_circuit_evaluation as funded

CASES = {
    "adopt-v1": "8ba561db51a2808a3d6a4ebcc684436cbb3619c94387c0f3939eadc34b7c88a8",
    "no-update-v9": "56821f43e6af00c0e7eeb21a1e965628333a0522b9833491f9e1f5bfac897bd6",
}
RELEASE = "ffafe1803eae4de802b46ca3e97e424ab4478228b789bb837b18c87046301b19"
HEPTA = "60347d4d1687147ddf7c1e12350711583dac5918"
ZIP = "db8549ee2f08810072571f2aa3892ff518277fa371f1029566d78a11b7e89360"
VERIFIER = "eea6c44e5770e9d69256ef9ad69369f3dae4ff133c1cc56e9d5e8e11229bebea"
JOB = CHAIN / "evidence/cell-released-pair-funded-evaluation-20261123"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_file(path, expected):
    with path.open("rb") as f:
        require(hashlib.file_digest(f, "sha256").hexdigest() == expected, "original file digest differs")


def legacy(case, repository=CHAIN):
    root = repository / "evidence/hepta-real-native-adoption-20261108/chain-reader" / case
    bindings = repository / "evidence/cell-learning-business-readback-20261109/bindings" / (case + ".json")
    files = {key: (root / (key + (".bin" if key in ("selection", "completed") else ".json"))).read_bytes()
             for key in business.MATERIAL_NAMES}
    report = business.review_business_iteration(files, bindings_raw=bindings.read_bytes(),
                                                expected_bindings_sha256=CASES[case])
    require(report["completion_review"] == funded.read(root / "stdout.json"), "archived completion differs")
    return dict(case=case, operation=report["operation_id"], decision=report["decision"],
                checkpoint_codec=report["checkpoint_codec"], selected_bundle_digest=report["selected_bundle_digest"],
                original_actor_relation=report["next_use_provenance"]["status"],
                independent_consumer_gate=report["independent_consumer_gate"],
                original_funded_mapping_observed=report["funded_mapping_observed"],
                original_settlement_verified=report["settlement_verified"],
                improvement_reward=report["economic_categories"]["improvement_reward"])


def consumer(folder):
    archive = folder / "CONSUMER_ENGINEERING_ORIGINALS.zip"
    verifier = folder / "verify_fixture.py"
    check_file(archive, ZIP)
    check_file(verifier, VERIFIER)
    # Invoke only the pinned, offline standard-library verifier for this fixture.
    raw = subprocess.check_output([sys.executable, "-I", "-B", str(verifier), str(archive)], timeout=60)
    audit = json.loads(raw)
    require(audit["archive_sha256"] == ZIP and audit["study_scope"] == "engineering_fixture"
            and audit["real_participants"] == audit["payments"] == 0, "fixture provenance differs")
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if n.startswith("original/intake/") and n.endswith("/release.json")]
        require(len(names) == 1, "ambiguous fixture admission")
        release = json.loads(z.read(names[0]))
        root = names[0].removesuffix("release.json") + "consumer/"
        rows = []
        for decision in audit["decisions"]:
            scope = json.loads(z.read(root + decision["operation"] + "/OUTCOME.json"))["scope"]
            require(scope["candidate"] == release["candidate_sha256"] and scope["pair"] == release["request_sha256"]
                    and scope["output"] == decision["output_sha256"] and scope["run_receipt"] == decision["run_receipt_sha256"],
                    "subsequent use and selected pair differ")
            rows.append(dict(**decision, task_sha256=scope["task"], participant_effect_sha256=scope["effect"]))
    return release, rows


def compare(folder, job=JOB):
    release, rows = consumer(folder)
    native = funded.verify(job, expected_release=RELEASE)
    funded_admission = funded.read(job / "ADMISSION.json")
    chain_release = funded_admission["intake_release"]
    current = funded.read(job / "CURRENT.json")
    payment = current["current_payment"]
    require(payment["subject"] == native["output"], "native fee is not bound to the signed evaluation delivery")
    fields = {}
    for field in ("scope", "study_sha256", "admission_sha256", "freeze_sha256", "candidate_sha256", "request_sha256"):
        fields[field] = dict(chain_evaluation=chain_release[field], hepta_consumer=release[field],
                             equal=chain_release[field] == release[field])
    return dict(schema="trnm.archived-consumer-ledger-cross-readback.v1",
                hepta_commit=HEPTA, hepta_originals_sha256=ZIP,
                legacy_operations=[legacy(case) for case in CASES],
                common_release_fields=fields, same_released_pair=chain_release == release,
                checked_development_evaluation=dict(release_sha256=RELEASE, task=native["task"],
                    payment_operation=native["payment_operation"], payment_subject=payment["subject"],
                    payment_subject_schema=funded.read(job / "DELIVERY.json")["schema"],
                    development_units=native["development_units"], verified_evaluation_files=native["checked_evaluation_files"],
                    future_gain=native["paired_performance"]["future_success_count_delta"]),
                subsequent_fixture_uses=rows, independently_verified_business_effect="UNVERIFIED",
                real_independent_consumer_use="UNVERIFIED", external_payer_and_settlement="UNVERIFIED",
                improvement_reward="UNVERIFIED", consensus_credit="UNVERIFIED",
                actual_external_payment_amount=None, settlement_authorized=False)


def public_comparison_summary(folder):
    """Keep the full internal comparison and its payment material out of stdout."""
    report = compare(folder)
    return dict(schema="trnm.archived-consumer-ledger-cross-readback-public-summary.v1",
                status="VERIFIED_ARCHIVE_READBACK",
                same_released_pair=report["same_released_pair"],
                release_field_equality={field: report["common_release_fields"][field]["equal"]
                    for field in ("scope", "study_sha256", "admission_sha256", "freeze_sha256",
                                  "candidate_sha256", "request_sha256")},
                legacy_operations_checked=len(report["legacy_operations"]),
                subsequent_fixture_uses_checked=len(report["subsequent_fixture_uses"]),
                verified_evaluation_files=report["checked_development_evaluation"]["verified_evaluation_files"],
                independently_verified_business_effect="UNVERIFIED",
                real_independent_consumer_use="UNVERIFIED", external_payer_and_settlement="UNVERIFIED",
                improvement_reward="UNVERIFIED", consensus_credit="UNVERIFIED",
                settlement_authorized=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hepta_evidence", type=Path, help="directory of the pinned public, fictional engineering archive")
    print(json.dumps(public_comparison_summary(parser.parse_args().hepta_evidence), indent=2, sort_keys=True))
