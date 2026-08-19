#!/usr/bin/env python3
"""Positive and negative tests for private G3 run-material generation."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap


HERE = pathlib.Path(__file__).resolve().parent
GENERATOR = HERE / "prepare_run_material.py"
sys.path.insert(0, str(HERE))

import check_run_material  # noqa: E402
import prepare_run_material  # noqa: E402


HASH_A = "11" * 32
HASH_C = "33" * 32
RUN_ID = "poco-g3-7-20260813T120000Z-1234abcd"


def fake_material_builder(parent: pathlib.Path) -> tuple[pathlib.Path, str]:
    binary = parent / "fake-trnm-poco-lab-material-builder"
    binary.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import hashlib
            import json
            import pathlib
            import sys

            sys.path.insert(0, __POCO_FLEET_HELPER_DIRECTORY__)
            from poco_consensus_contract import canonical_lab_genesis_hash

            if len(sys.argv) == 10 and sys.argv[1] == "zero-comet-bootstrap":
                template = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
                corpus_path = pathlib.Path(sys.argv[3])
                policy_path = pathlib.Path(sys.argv[5])
                validator_set_path = pathlib.Path(sys.argv[8])
                bootstrap_dir = pathlib.Path(sys.argv[9])
                if hashlib.sha256(corpus_path.read_bytes()).hexdigest() != sys.argv[4]:
                    raise SystemExit("fake corpus hash mismatch")
                if hashlib.sha256(policy_path.read_bytes()).hexdigest() != sys.argv[6]:
                    raise SystemExit("fake policy hash mismatch")
                canonical_records = [
                    (
                        bytes.fromhex(value["validator_id"]),
                        bytes.fromhex(value["consensus_public_key"]),
                        value["voting_power"],
                    )
                    for value in template["validators"]
                ]
                genesis_hash = canonical_lab_genesis_hash(
                    template["chain_id"], canonical_records
                ).hex()
                canonical_inventory = json.dumps(
                    canonical_records,
                    default=lambda value: value.hex() if isinstance(value, bytes) else value,
                    separators=(",", ":"),
                ).encode("utf-8")
                validator_set_id = hashlib.sha256(
                    b"fake-validator-set\\0" + bytes.fromhex(genesis_hash) + canonical_inventory
                ).hexdigest()
                validator_set = dict(template)
                validator_set["genesis_hash"] = genesis_hash
                validator_set_bytes = (
                    json.dumps(validator_set, indent=2, sort_keys=True) + "\\n"
                ).encode("utf-8")
                validator_set_path.write_bytes(validator_set_bytes)
                bootstrap_dir.mkdir(mode=0o700)
                signer_ids = [value["validator_id"] for value in template["validators"]]
                proposals = []
                blocks = []
                parent = genesis_hash
                for height in (1, 2, 3):
                    proposal = hashlib.sha256(
                        b"fake-existing-proposal-wire\\0"
                        + bytes.fromhex(genesis_hash)
                        + height.to_bytes(8, "big")
                        + bytes.fromhex(parent)
                    ).digest()
                    proposal_path = bootstrap_dir / f"h{height}.proposal"
                    proposal_path.write_bytes(proposal)
                    proposals.append(proposal)
                    block_id = hashlib.sha256(b"fake-block\\0" + proposal).hexdigest()
                    def commitment(label):
                        return hashlib.sha256(
                            label + bytes.fromhex(genesis_hash) + height.to_bytes(8, "big")
                        ).hexdigest()
                    blocks.append({
                        "height": height,
                        "view": height,
                        "timestamp_ms": height * 1000,
                        "parent_block_id": parent,
                        "block_id": block_id,
                        "proposer_validator_id": signer_ids[height - 1],
                        "payload_root": commitment(b"payload"),
                        "state_root": commitment(b"state"),
                        "receipts_root": commitment(b"receipts"),
                        "evidence_root": commitment(b"evidence"),
                        "proposal": {
                            "path": f"public/bootstrap/h{height}.proposal",
                            "sha256": hashlib.sha256(proposal).hexdigest(),
                            "bytes": len(proposal),
                        },
                        "certifying_qc_id": commitment(b"qc"),
                        "qc_signer_validator_ids": signer_ids,
                    })
                    parent = block_id
                finality = hashlib.sha256(
                    b"fake-existing-cev0-finality\\0" + b"".join(proposals)
                ).digest()
                finality_path = bootstrap_dir / "finality-proof.cev0"
                finality_path.write_bytes(finality)
                finality_id = hashlib.sha256(b"fake-finality-id\\0" + finality).hexdigest()
                def chain_fact(label):
                    return hashlib.sha256(label + bytes.fromhex(genesis_hash)).hexdigest()
                bootstrap = {
                    "schema_version": 1,
                    "schema": "trnm.poco.zero-comet-public-bootstrap.v1",
                    "chain_id": template["chain_id"],
                    "genesis_hash": genesis_hash,
                    "protocol_version": 0,
                    "epoch": 0,
                    "validator_set_id": validator_set_id,
                    "consensus_parameters_profile": "reference-shadow-v0",
                    "consensus_parameters_hash": chain_fact(b"parameters"),
                    "genesis_timestamp_ms": 0,
                    "ordinary_start_height": 4,
                    "chain_descriptor_hash": chain_fact(b"descriptor"),
                    "signer_policy_commitment": chain_fact(b"signers"),
                    "initial_block_id": genesis_hash,
                    "initial_state_root": chain_fact(b"state0"),
                    "initial_commit_id": chain_fact(b"commit0"),
                    "validator_count": len(signer_ids),
                    "qc_signer_count": len(signer_ids),
                    "all_validator_signers": True,
                    "blocks": blocks,
                    "finality_proof": {
                        "path": "public/bootstrap/finality-proof.cev0",
                        "sha256": hashlib.sha256(finality).hexdigest(),
                        "bytes": len(finality),
                    },
                    "finality_proof_id": finality_id,
                    "finalized_height": 1,
                    "private_key_material_emitted": False,
                    "production_activation": False,
                }
                bootstrap_bytes = (
                    json.dumps(bootstrap, indent=2, sort_keys=True) + "\\n"
                ).encode("utf-8")
                (bootstrap_dir / "bootstrap.json").write_bytes(bootstrap_bytes)
                print(json.dumps({
                    "schema_version": 1,
                    "status": "public-zero-comet-bootstrap-created",
                    "validator_set_sha256": hashlib.sha256(validator_set_bytes).hexdigest(),
                    "genesis_hash": genesis_hash,
                    "validator_set_id": validator_set_id,
                    "bootstrap_sha256": hashlib.sha256(bootstrap_bytes).hexdigest(),
                    "finality_proof_sha256": hashlib.sha256(finality).hexdigest(),
                    "finality_proof_id": finality_id,
                    "ordinary_start_height": 4,
                    "validator_count": len(signer_ids),
                    "qc_signer_count": len(signer_ids),
                    "all_validator_signers": True,
                    "consensus_private_key_retained": False,
                    "consensus_private_key_emitted": False,
                    "production_activation": False,
                }, separators=(",", ":")))
                raise SystemExit(0)

            if len(sys.argv) != 7 or sys.argv[1] != "workload-corpus":
                raise SystemExit("unsupported fake material-builder command")
            chain_id = sys.argv[2]
            ordinary_start_height = int(sys.argv[3])
            max_height = int(sys.argv[4])
            corpus_path = pathlib.Path(sys.argv[5])
            policy_path = pathlib.Path(sys.argv[6])
            ordinary_entry_count = max_height - ordinary_start_height + 1
            operator_key = "44" * 32
            client_key = "55" * 32
            header = {
                "schema_version": 1,
                "schema": "trnm_poco_g3_workload_corpus_v1",
                "chain_id": chain_id,
                "ordinary_start_height": ordinary_start_height,
                "max_height": max_height,
                "ordinary_entry_count": ordinary_entry_count,
                "genesis_timestamp_ms": 0,
                "block_time_step_ms": 1000,
                "validity_width_ms": 1,
                "operator": {
                    "signer_id": "did:trnm:g3:workload-operator",
                    "signer_role": "operator",
                    "public_key_hex": operator_key,
                },
                "client": {
                    "signer_id": "did:trnm:g3:workload-client",
                    "signer_role": "hepta",
                    "public_key_hex": client_key,
                },
                "governance_signer_id": "did:trnm:g3:workload-operator",
                "credit_amount": "1000000",
                "task_reward": "1",
                "task_worker_stake": "1",
                "task_deadline_lead": 1000,
                "task_challenge_window": 10,
                "max_gas": 100000,
                "fee_limit": "1000000",
            }
            header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
            corpus = bytearray(b"trnm-poco-g3-workload-corpus-v1\\n")
            corpus.extend((1).to_bytes(4, "big"))
            corpus.extend(len(header_bytes).to_bytes(4, "big"))
            corpus.extend(header_bytes)
            corpus.extend(ordinary_entry_count.to_bytes(8, "big"))
            entry_root = bytes.fromhex("66" * 32)
            for ordinal, height in enumerate(
                range(ordinary_start_height, max_height + 1), start=1
            ):
                corpus.extend(height.to_bytes(8, "big"))
                corpus.extend((height * 1000).to_bytes(8, "big"))
                corpus.extend(bytes([ordinal]) * (64 + 64 + 32))
            corpus.extend(entry_root)
            corpus.extend(b"trnm-poco-g3-workload-corpus-end-v1\\n")
            corpus_path.write_bytes(corpus)
            corpus_hash = hashlib.sha256(corpus).hexdigest()
            policy = {
                "schema_version": 1,
                "schema": "trnm_poco_g3_workload_policy_v1",
                "corpus_sha256": corpus_hash,
                "entry_chain_root": entry_root.hex(),
                "header": header,
                "execution_preflight_height": min(
                    max_height, ordinary_start_height + 1024 - 1
                ),
                "application_private_key_retained": False,
                "application_private_key_deployed": False,
                "production_activation": False,
            }
            policy_bytes = json.dumps(policy, separators=(",", ":")).encode("utf-8")
            policy_path.write_bytes(policy_bytes)
            print(json.dumps({
                "schema_version": 1,
                "status": "public-pre-signed-workload-corpus-created",
                "corpus_sha256": corpus_hash,
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
                "entry_chain_root": entry_root.hex(),
                "operator_public_key_hex": operator_key,
                "client_public_key_hex": client_key,
                "ordinary_start_height": ordinary_start_height,
                "max_height": max_height,
                "ordinary_entry_count": ordinary_entry_count,
                "execution_preflight_height": min(
                    max_height, ordinary_start_height + 1024 - 1
                ),
                "application_private_key_retained": False,
                "application_private_key_deployed": False,
                "production_activation": False,
            }, separators=(",", ":")))
            """
        ).replace("__POCO_FLEET_HELPER_DIRECTORY__", repr(str(HERE))),
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def fake_validator_binary(parent: pathlib.Path) -> tuple[pathlib.Path, str]:
    binary = parent / "fake-trnm-poco-lab-validator"
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'fake validator has no author commands' >&2\nexit 2\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def generation_command(
    root: pathlib.Path,
    material_builder: pathlib.Path,
    material_builder_hash: str,
    validator_binary: pathlib.Path,
    validator_binary_hash: str,
) -> list[str]:
    return [
        sys.executable,
        str(GENERATOR),
        "7",
        "--output",
        str(root),
        "--weight-profile",
        "bounded-unequal",
        "--source-sha256",
        HASH_A,
        "--linux-sha256",
        validator_binary_hash,
        "--macos-sha256",
        HASH_C,
        "--material-builder",
        str(material_builder),
        "--material-builder-sha256",
        material_builder_hash,
        "--validator-binary",
        str(validator_binary),
        "--ordinary-start-height",
        "4",
        "--workload-max-height",
        "6",
        "--run-id",
        RUN_ID,
    ]


def generate(
    root: pathlib.Path,
    material_builder: pathlib.Path,
    material_builder_hash: str,
    validator_binary: pathlib.Path,
    validator_binary_hash: str,
) -> None:
    subprocess.run(
        generation_command(
            root,
            material_builder,
            material_builder_hash,
            validator_binary,
            validator_binary_hash,
        ),
        check=True,
        capture_output=True,
        text=True,
    )


def expect_prepare_failure(action, expected: str) -> None:
    try:
        action()
    except SystemExit as error:
        if expected not in str(error):
            raise AssertionError(
                f"prepare negative hit {error!s}, expected {expected!r}"
            ) from error
        return
    raise AssertionError(f"prepare negative was accepted; expected {expected!r}")


def verify_pinned_builder_inode(parent: pathlib.Path) -> None:
    trusted = parent / "trusted-builder"
    trusted.write_text("#!/bin/sh\nprintf 'trusted-pinned\\n'\n", encoding="utf-8")
    trusted.chmod(0o700)
    trusted_hash = hashlib.sha256(trusted.read_bytes()).hexdigest()
    descriptor = prepare_run_material.open_exact_binary(
        trusted, trusted_hash, "--material-builder"
    )
    try:
        replacement = parent / "replacement-builder"
        replacement.write_text("#!/bin/sh\nprintf 'replacement-ran\\n'\n", encoding="utf-8")
        replacement.chmod(0o700)
        os.replace(replacement, trusted)
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}"],
            check=True,
            capture_output=True,
            text=True,
            pass_fds=(descriptor,),
        )
        if completed.stdout != "trusted-pinned\n":
            raise AssertionError("pinned builder execution followed a replaced pathname")
    finally:
        os.close(descriptor)

    symlink = parent / "builder-symlink"
    symlink.symlink_to(trusted)
    expect_prepare_failure(
        lambda: prepare_run_material.open_exact_binary(
            symlink, trusted_hash, "--material-builder"
        ),
        "cannot pin --material-builder",
    )
    nonexec = parent / "builder-nonexec"
    nonexec.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    nonexec.chmod(0o600)
    nonexec_hash = hashlib.sha256(nonexec.read_bytes()).hexdigest()
    expect_prepare_failure(
        lambda: prepare_run_material.open_exact_binary(
            nonexec, nonexec_hash, "--material-builder"
        ),
        "must be executable",
    )
    expect_prepare_failure(
        lambda: prepare_run_material.open_exact_binary(
            trusted, "ff" * 32, "--material-builder"
        ),
        "differs from its expected SHA-256",
    )


def expect_reject(source: pathlib.Path, name: str, expected: str, mutate) -> None:
    target = source.parent / name
    shutil.copytree(source, target)
    mutate(target)
    try:
        check_run_material.validate(target, 7, emit=False)
    except (check_run_material.MaterialError, OSError, subprocess.SubprocessError) as error:
        if expected not in str(error):
            raise AssertionError(
                f"mutant {name} hit {error!s}, expected error containing {expected!r}"
            ) from error
        return
    raise AssertionError(f"mutant {name} was accepted")


def expect_root_reject(root: pathlib.Path, expected: str) -> None:
    try:
        check_run_material.validate(root, 7, emit=False)
    except (check_run_material.MaterialError, OSError, subprocess.SubprocessError) as error:
        if expected not in str(error):
            raise AssertionError(
                f"root mutant hit {error!s}, expected error containing {expected!r}"
            ) from error
        return
    raise AssertionError("symlink run-root mutant was accepted")


def rewrite_json(root: pathlib.Path, relative: str, mutate) -> None:
    path = root / relative
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rehash_manifest_ref(root: pathlib.Path, relative: str, *, validator_set: bool = False) -> None:
    path = root / relative
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for collection in (manifest["public_files"], manifest["secret_files"]):
        for reference in collection:
            if reference["path"] == relative:
                reference["sha256"] = digest
                reference["bytes"] = len(content)
                break
        else:
            continue
        break
    else:
        raise AssertionError(f"manifest has no reference for {relative}")
    if validator_set:
        manifest["validator_set_sha256"] = digest
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def mutate_validator_set(root: pathlib.Path, mutate) -> None:
    relative = "public/validator-set.json"
    rewrite_json(root, relative, mutate)
    rehash_manifest_ref(root, relative, validator_set=True)


def mutate_secret(root: pathlib.Path) -> None:
    secrets = sorted((root / "secrets").iterdir())
    secrets[0].write_bytes(secrets[1].read_bytes())
    rehash_manifest_ref(root, secrets[0].relative_to(root).as_posix())


def mutate_peer(root: pathlib.Path) -> None:
    name = sorted(path.name for path in (root / "public/configs").iterdir())[0]
    relative = f"public/configs/{name}"
    rewrite_json(root, relative, lambda value: value["peers"][0].update(lan_ip="192.168.0.254"))
    rehash_manifest_ref(root, relative)


def mutate_observer(root: pathlib.Path, mutate) -> None:
    relative = "public/observer-configs/mac.json"
    rewrite_json(root, relative, mutate)
    rehash_manifest_ref(root, relative)


def mutate_policy(root: pathlib.Path, mutate) -> None:
    relative = "public/workload-policy.json"
    rewrite_json(root, relative, mutate)
    rehash_manifest_ref(root, relative)


def mutate_config_workload_hash(root: pathlib.Path) -> None:
    name = sorted(path.name for path in (root / "public/configs").iterdir())[0]
    relative = f"public/configs/{name}"
    rewrite_json(
        root,
        relative,
        lambda value: value.update(workload_corpus_sha256="ff" * 32),
    )
    rehash_manifest_ref(root, relative)


def mutate_config_start_height(root: pathlib.Path) -> None:
    name = sorted(path.name for path in (root / "public/configs").iterdir())[0]
    relative = f"public/configs/{name}"
    rewrite_json(
        root,
        relative,
        lambda value: value.update(ordinary_start_height=5),
    )
    rehash_manifest_ref(root, relative)


def mutate_bootstrap_sidecar_with_manifest_readdress(root: pathlib.Path) -> None:
    relative = "public/bootstrap/h2.proposal"
    path = root / relative
    path.write_bytes(path.read_bytes() + b"substitution")
    rehash_manifest_ref(root, relative)


def inject_bootstrap_deployment_field(root: pathlib.Path) -> None:
    relative = "public/bootstrap/bootstrap.json"
    rewrite_json(root, relative, lambda value: value.update(run_id=RUN_ID))
    rehash_manifest_ref(root, relative)


def leak_secret_into_fully_readdressed_bootstrap(root: pathlib.Path) -> None:
    relative = "public/bootstrap/h1.proposal"
    proposal_path = root / relative
    secret_path = sorted((root / "secrets").iterdir())[0]
    proposal_path.write_bytes(secret_path.read_bytes()[-32:])
    proposal_hash = hashlib.sha256(proposal_path.read_bytes()).hexdigest()
    bootstrap_relative = "public/bootstrap/bootstrap.json"
    rewrite_json(
        root,
        bootstrap_relative,
        lambda value: value["blocks"][0]["proposal"].update(
            sha256=proposal_hash,
            bytes=proposal_path.stat().st_size,
        ),
    )
    rehash_manifest_ref(root, relative)
    rehash_manifest_ref(root, bootstrap_relative)


def readdress_workload(
    root: pathlib.Path,
    corpus: bytes,
    *,
    policy_mutate=None,
    config_start_height: int | None = None,
) -> None:
    corpus_path = root / "public/workload.corpus"
    corpus_path.write_bytes(corpus)
    corpus_hash = hashlib.sha256(corpus).hexdigest()
    policy_path = root / "public/workload-policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["corpus_sha256"] = corpus_hash
    if policy_mutate is not None:
        policy_mutate(policy)
    policy_bytes = json.dumps(policy, separators=(",", ":")).encode("utf-8")
    policy_path.write_bytes(policy_bytes)
    policy_hash = hashlib.sha256(policy_bytes).hexdigest()
    for config_path in sorted((root / "public/configs").iterdir()):
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["workload_corpus_sha256"] = corpus_hash
        config["workload_policy_sha256"] = policy_hash
        if config_start_height is not None:
            config["ordinary_start_height"] = config_start_height
        config_path.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        rehash_manifest_ref(root, config_path.relative_to(root).as_posix())
    rehash_manifest_ref(root, "public/workload.corpus")
    rehash_manifest_ref(root, "public/workload-policy.json")


def mutate_noncontiguous_corpus_with_full_readdress(root: pathlib.Path) -> None:
    corpus = bytearray((root / "public/workload.corpus").read_bytes())
    magic_length = len(b"trnm-poco-g3-workload-corpus-v1\n")
    header_length = int.from_bytes(corpus[magic_length + 4 : magic_length + 8], "big")
    entries_start = magic_length + 8 + header_length + 8
    second_height = entries_start + (8 + 8 + 64 + 64 + 32)
    corpus[second_height : second_height + 8] = (6).to_bytes(8, "big")
    readdress_workload(root, bytes(corpus))


def mutate_start_height_with_full_readdress(root: pathlib.Path) -> None:
    corpus = bytearray((root / "public/workload.corpus").read_bytes())
    magic_length = len(b"trnm-poco-g3-workload-corpus-v1\n")
    header_length = int.from_bytes(corpus[magic_length + 4 : magic_length + 8], "big")
    header_start = magic_length + 8
    header_end = header_start + header_length
    header = json.loads(corpus[header_start:header_end].decode("utf-8"))
    header["ordinary_start_height"] = 5
    header["ordinary_entry_count"] = 2
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(header_bytes) != header_length:
        raise AssertionError("same-width start-height readdress changed corpus framing")
    corpus[header_start:header_end] = header_bytes

    def update_policy(policy: dict) -> None:
        policy["header"] = header
        policy["execution_preflight_height"] = 6

    readdress_workload(
        root,
        bytes(corpus),
        policy_mutate=update_policy,
        config_start_height=5,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="poco-g3-run-material-test-") as temporary:
        parent = pathlib.Path(temporary)
        verify_pinned_builder_inode(parent)
        material_builder, material_builder_hash = fake_material_builder(parent)
        validator_binary, validator_binary_hash = fake_validator_binary(parent)
        if material_builder_hash == validator_binary_hash:
            raise AssertionError("fake authority binaries unexpectedly have identical hashes")

        same_binary_command = generation_command(
            parent / "same-authority-binary",
            material_builder,
            material_builder_hash,
            material_builder,
            material_builder_hash,
        )
        same_binary = subprocess.run(
            same_binary_command, capture_output=True, text=True
        )
        if (
            same_binary.returncode == 0
            or "must have distinct SHA-256 values"
            not in same_binary.stdout + same_binary.stderr
        ):
            raise AssertionError("run-material generator accepted one binary in both roles")

        copied_builder = parent / "copied-material-builder-as-validator"
        shutil.copyfile(material_builder, copied_builder)
        copied_builder.chmod(0o700)
        copied_binary_command = generation_command(
            parent / "copied-authority-binary",
            material_builder,
            material_builder_hash,
            copied_builder,
            material_builder_hash,
        )
        copied_binary = subprocess.run(
            copied_binary_command, capture_output=True, text=True
        )
        if (
            copied_binary.returncode == 0
            or "must have distinct SHA-256 values"
            not in copied_binary.stdout + copied_binary.stderr
        ):
            raise AssertionError(
                "run-material generator accepted byte-identical binaries in both roles"
            )

        output_symlink = parent / "generator-output-symlink"
        output_symlink.symlink_to(parent / "missing-output", target_is_directory=True)
        rejected_output = subprocess.run(
            generation_command(
                output_symlink,
                material_builder,
                material_builder_hash,
                validator_binary,
                validator_binary_hash,
            ),
            capture_output=True,
            text=True,
        )
        if (
            rejected_output.returncode == 0
            or "output root already exists" not in rejected_output.stdout + rejected_output.stderr
        ):
            raise AssertionError("run-material generator accepted a dangling output symlink")
        wrong_start_command = generation_command(
            parent / "wrong-bootstrap-start",
            material_builder,
            material_builder_hash,
            validator_binary,
            validator_binary_hash,
        )
        wrong_start_command[wrong_start_command.index("--ordinary-start-height") + 1] = "5"
        wrong_start = subprocess.run(wrong_start_command, capture_output=True, text=True)
        if (
            wrong_start.returncode == 0
            or "must be exactly 4" not in wrong_start.stdout + wrong_start.stderr
        ):
            raise AssertionError("run-material generator accepted ordinary_start_height != 4")
        source = parent / "valid"
        generate(
            source,
            material_builder,
            material_builder_hash,
            validator_binary,
            validator_binary_hash,
        )
        check_run_material.validate(source, 7, emit=False)
        symlink_root = parent / "run-root-symlink"
        symlink_root.symlink_to(source, target_is_directory=True)
        expect_root_reject(symlink_root, "must be a real directory")

        expect_reject(
            source,
            "production",
            "must not activate production",
            lambda root: rewrite_json(
                root, "manifest.json", lambda value: value.update(production_activation=True)
            ),
        )
        expect_reject(
            source,
            "missing-material-author",
            "manifest keys must be exactly",
            lambda root: rewrite_json(
                root, "manifest.json", lambda value: value.pop("material_author")
            ),
        )
        expect_reject(
            source,
            "runtime-binary-as-material-author",
            "material_author must bind one distinct non-deployed author binary",
            lambda root: rewrite_json(
                root,
                "manifest.json",
                lambda value: value["material_author"].update(
                    binary_sha256=value["candidate"]["linux_x86_64_sha256"]
                ),
            ),
        )
        expect_reject(
            source,
            "deployed-material-author",
            "material_author must bind one distinct non-deployed author binary",
            lambda root: rewrite_json(
                root,
                "manifest.json",
                lambda value: value["material_author"].update(runtime_deployed=True),
            ),
        )
        expect_reject(
            source,
            "duplicate-key",
            "public keys must be unique",
            lambda root: mutate_validator_set(
                root,
                lambda value: value["validators"][1].update(
                    consensus_public_key=value["validators"][0]["consensus_public_key"]
                ),
            ),
        )
        expect_reject(
            source,
            "foreign-canonical-genesis",
            "genesis differs from the chain-only canonical derivation",
            lambda root: mutate_validator_set(
                root, lambda value: value.update(genesis_hash="ff" * 32)
            ),
        )
        expect_reject(
            source,
            "bad-key-pop",
            "proof-of-possession is invalid",
            lambda root: mutate_validator_set(
                root,
                lambda value: value["validators"][0].update(
                    key_pop_signature="00" * 64
                ),
            ),
        )
        expect_reject(
            source,
            "wrong-secret",
            "secret key differs from its public validator descriptor",
            mutate_secret,
        )
        expect_reject(
            source,
            "open-secret-mode",
            "secret mode must be exactly 0600",
            lambda root: (root / "secrets" / sorted((root / "secrets").iterdir())[0].name).chmod(
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP
            ),
        )
        expect_reject(
            source,
            "peer-substitution",
            "config peer differs from topology/key descriptor",
            mutate_peer,
        )
        expect_reject(
            source,
            "unreferenced-file",
            "unreferenced, missing, or symlink file",
            lambda root: (root / "unexpected").write_text("not referenced\n", encoding="utf-8"),
        )
        expect_reject(
            source,
            "observer-role",
            "observer config differs from topology/key/candidate inputs",
            lambda root: mutate_observer(
                root, lambda value: value.update(run_roles=["validator"])
            ),
        )
        expect_reject(
            source,
            "observer-binary",
            "observer config differs from topology/key/candidate inputs",
            lambda root: mutate_observer(
                root, lambda value: value.update(binary_sha256=validator_binary_hash)
            ),
        )
        expect_reject(
            source,
            "observer-endpoint",
            "observer config differs from topology/key/candidate inputs",
            lambda root: mutate_observer(
                root,
                lambda value: value["validator_endpoints"][0].update(
                    lan_ip="192.168.0.254"
                ),
            ),
        )
        expect_reject(
            source,
            "workload-corpus-tamper",
            "content address mismatch",
            lambda root: (root / "public/workload.corpus").write_bytes(
                (root / "public/workload.corpus").read_bytes() + b"tamper"
            ),
        )
        expect_reject(
            source,
            "workload-private-authority",
            "retains private authority",
            lambda root: mutate_policy(
                root,
                lambda value: value.update(application_private_key_retained=True),
            ),
        )
        expect_reject(
            source,
            "workload-consensus-key-overlap",
            "overlap each other or consensus authority",
            lambda root: mutate_policy(
                root,
                lambda value: value["header"]["operator"].update(
                    public_key_hex=json.loads(
                        (root / "public/validator-set.json").read_text(encoding="utf-8")
                    )["validators"][0]["consensus_public_key"]
                ),
            ),
        )
        expect_reject(
            source,
            "config-workload-substitution",
            "workload_corpus_sha256 differs from trusted inputs",
            mutate_config_workload_hash,
        )
        expect_reject(
            source,
            "config-wrong-start-height",
            "ordinary_start_height differs from trusted inputs",
            mutate_config_start_height,
        )
        expect_reject(
            source,
            "workload-noncontiguous-readdressed",
            "ordinal-to-height/timestamp schedule is non-canonical",
            mutate_noncontiguous_corpus_with_full_readdress,
        )
        expect_reject(
            source,
            "workload-start-height-readdressed",
            "must follow the fixed empty h1-h3 prefix",
            mutate_start_height_with_full_readdress,
        )
        expect_reject(
            source,
            "bootstrap-sidecar-manifest-readdressed",
            "proposal reference differs from its exact public bytes",
            mutate_bootstrap_sidecar_with_manifest_readdress,
        )
        expect_reject(
            source,
            "bootstrap-deployment-field",
            "bootstrap keys must be exactly",
            inject_bootstrap_deployment_field,
        )
        expect_reject(
            source,
            "bootstrap-secret-leak-fully-readdressed",
            "contains consensus secret material",
            leak_secret_into_fully_readdressed_bootstrap,
        )
        expect_reject(
            source,
            "duplicate-workload-reference",
            "duplicate or cross-authority paths",
            lambda root: rewrite_json(
                root,
                "manifest.json",
                lambda value: value["public_files"].append(
                    next(
                        dict(reference)
                        for reference in value["public_files"]
                        if reference["path"] == "public/workload.corpus"
                    )
                ),
            ),
        )

    print(
        "poco_g3_run_material_self_test=passed positives=2 negatives=33 "
        "validator_hosts=5 mac_observer=true ephemeral_keys=true pop=true "
        "public_workload=true ordinary_start_height=4 ordinal_height_mapping=true "
        "content_addressed=true application_private_keys=false "
        "builder_inode_pinned=true builder_path_substitution_rejected=true "
        "material_builder_validator_binary_distinct=true same_binary_fallback_rejected=true "
        "material_author_hash_bound=true material_author_runtime_deployed=false "
        "run_root_symlink_rejected=true generator_output_symlink_rejected=true "
        "public_bootstrap_bundle=true bootstrap_runtime_closed=false "
        "production_activation=false geo_wan=false"
    )


if __name__ == "__main__":
    main()
