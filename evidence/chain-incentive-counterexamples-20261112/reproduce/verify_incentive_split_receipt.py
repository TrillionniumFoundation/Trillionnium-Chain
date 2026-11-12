#!/usr/bin/env python3
"""Independently recompute V4 arithmetic, signed inputs and fixture-account fees.

This checks a retained native counterexample, not general protocol acceptance,
independent operators, all real-world costs, or permissionless economic security.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


def require(value, message):
    if not value:
        raise ValueError(message)


def verify(repo, receipt):
    sys.path.insert(0, str(repo / "formal/pon-nakamoto-v1"))
    import model_composition_oracle as oracle
    from contract_wire import H, read_config, tx_decode, u64, unique
    from ledger import key, public
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw_receipt = receipt.read_bytes()
    report = json.loads(raw_receipt, object_pairs_hook=unique)
    require(report["schema"] == "native-model-composition-v4-split-counterexample-v1", "schema")
    for flag in ("unknown_common_control_discovered", "source_cap_bypassed",
                 "unauthorized_payer_debit", "production_activation", "economic_security_qualified"):
        require(report[flag] is False, flag)
    context = {name: report[name] for name in ("network", "parameters", "family", "plan")}
    family = bytes.fromhex(context["family"])
    owners = {who: public(key(who)).hex() for who in range(4)}
    alias_owners = {owners[0], owners[1]}
    sources = {row["author"]: row["source"] for row in oracle.EMPIRICAL["sources"]}
    require(sources[owners[0]] == sources[owners[1]] != sources[owners[2]], "known alias mapping")
    fees = {row["tag"]: row["base_fee_units"] for row in read_config("config/pon/ledger-v1.json")["commands"]}
    fees.update({int(tag): fee for tag, fee in read_config("config/pon/public-evaluation-native-v1.json")["base_fee_units"].items()})
    fees[23] = read_config("config/pon/integer-factor-candidate-v2.json")["base_fee_units"]
    byte_fee = read_config("config/pon/devnet-v1.json")["byte_fee_units"]
    summary = {}
    expected_counts = {"original": 2, "split": 3}
    actual_b_ids = []
    for label in ("original", "split"):
        value = report[label]
        parent = oracle.decode_model(bytes.fromhex(value["parent_model_hex"]), family)
        bundle = oracle.decode_model(bytes.fromhex(value["bundle_model_hex"]), family)
        models = [oracle.decode_model(bytes.fromhex(raw), family) for raw in value["component_model_hex"]]
        require(len(models) == expected_counts[label], "component count")
        require(oracle.derive(parent, models) == bundle, "complete derivation")
        publication = value["publication"]
        retained = publication["model_composition_v4"]
        metadata = {"parent": retained["parent"], "factor_parent_artifact": retained["parent_artifact"],
                    "family": family.hex(), "submission_round": 0, "slot": 0}
        by_artifact = {oracle.artifact(family, model): (who, model, raw) for who, model, raw in
                       zip(value["component_authors"], models, value["component_model_hex"])}
        require(len(by_artifact) == len(models), "duplicate component models")
        components = []
        empirical = {}
        candidate_authors = {}
        for row in retained["components"]:
            who, model, raw = by_artifact[row["artifact"]]
            require(row["owner"] == owners[who], "component owner")
            components.append({"id": row["contribution"], "model_hex": raw, "weight": row["weight"],
                               "contribution": dict(metadata, artifact=row["artifact"], owner=owners[who])})
            empirical[row["contribution"]] = oracle.empirical_record(context, row["contribution"], model, parent)
            candidate_authors[row["contribution"]] = owners[who]
            if who == 2:
                actual_b_ids.append(row["contribution"])
        bundle_id = publication["bundle"]
        empirical[bundle_id] = oracle.empirical_record(context, bundle_id, bundle, parent)
        candidate_authors[bundle_id] = owners[3]
        observed = {"context": context, "parent_ref": retained["parent"],
                    "parent_model_hex": value["parent_model_hex"], "release": value["release"],
                    "budget": 100_000, "components": components,
                    "bundle": {"id": bundle_id, "model_hex": value["bundle_model_hex"],
                               "contribution": dict(metadata, artifact=oracle.artifact(family, bundle),
                                                    components_root=publication["root"], owner=owners[3])},
                    "source_reserved": {source: 0 for source in sources.values()}}
        computed = oracle.composition_release(observed)
        require(computed["composition"] == retained, "complete native composition receipt")
        require(computed["payouts"] == value["claims"], "actual claimed payouts")
        require(computed["source_reserved"] == value["source_budgets"], "actual source reservations")
        require(computed["dust"] == 1, "dust")
        require(value["known_alias_quota"]["intakes"] == (1 if label == "original" else 2), "alias intake")
        commands = value["signed_commands"]
        require([row["height"] for row in commands] == [1, 16, 32, 56, 76], "phase order")
        expected_tag = {1: 23, 16: 14, 32: 15, 56: 8, 76: 9}
        nonces, commits, reveals = {}, {}, {}
        alias_fees = 0
        verified_signatures = 0
        for command in commands:
            for encoded in command["transactions"]:
                raw = bytes.fromhex(encoded)
                require(159 <= len(raw) <= 2048 and raw[:4] == b"PNX1", "envelope")
                require(raw[4:36].hex() == context["network"], "network")
                sender = raw[36:68].hex()
                nonce, expiry, fee_limit = struct.unpack_from("<QQQ", raw, 68)
                tag, size = raw[92], struct.unpack_from("<H", raw, 93)[0]
                require(tag == expected_tag[command["height"]] and len(raw) == 159 + size, "phase bytes")
                require(sender in owners.values() and nonce == nonces.get(sender, 0) + 1, "contiguous nonce")
                require(command["height"] <= expiry and fees[tag] + len(raw) * byte_fee <= fee_limit, "expiry/fee")
                nonces[sender] = nonce
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(sender)).verify(raw[-64:], H("tx-sign", raw[:-64]))
                verified_signatures += 1
                if sender in alias_owners:
                    alias_fees += fees[tag] + len(raw) * byte_fee
                payload = raw[95:-64]
                if tag == 14:
                    require(len(payload) == 96, "commit length")
                    commits[(payload[:32].hex(), sender)] = (payload[32:64], payload[64:96])
                elif tag == 15:
                    require(len(payload) == 168, "reveal length")
                    cid, round_id = payload[:32].hex(), payload[32:64]
                    plan, evidence = payload[64:96], payload[96:128]
                    score = struct.unpack_from("<Q", payload, 128)[0]
                    salt = payload[136:168]
                    require(plan.hex() == context["plan"], "reveal plan")
                    require(score == empirical[cid]["score"] and evidence.hex() == empirical[cid]["digest"], "native empirical score/digest")
                    require(commits[(cid, sender)] == (round_id, H("native-public-evaluation-reveal-v1", round_id, bytes.fromhex(cid), bytes.fromhex(sender), plan, evidence, u64(score), salt)), "commit reveal binding")
                    reveals[(cid, sender)] = score
                elif tag == 8:
                    fields = tx_decode(raw)["fields"]
                    require(sender == owners[3] and fields["budget"] == 100_000 and fields["release"].hex() == value["release"], "authorized publisher")
                elif tag == 9:
                    fields = tx_decode(raw)["fields"]
                    require(fields["release"].hex() == value["release"], "claim release")
                    leaf = H("allocation-leaf", fields["contribution"], bytes.fromhex(sender), u64(fields["score"]))
                    for sibling in fields["siblings"]:
                        leaf = H("allocation-node", *sorted((leaf, sibling)))
                    require(leaf.hex() == publication["root"], "claim proof")
        require(set(commits) == set(reveals), "complete matched commitments")
        for cid, author in candidate_authors.items():
            require({sender for candidate, sender in reveals if candidate == cid} == {owners[i] for i in range(3)} - {author}, "complete eligible roster")
        alias_gross = sum(amount for cid, amount in computed["payouts"].items() if candidate_authors[cid] in alias_owners)
        require(alias_gross == value["alias_gross_payment"], "group gross")
        require(alias_gross - alias_fees == int(value["alias_net_account_change_after_all_own_fees"]), "all charged own-account fees")
        before = sum(row["balance"] for row in value["alias_accounts_initial"])
        after = sum(row["balance"] for row in value["alias_accounts_final"])
        require(after - before == alias_gross - alias_fees, "actual account balances")
        summary[label] = {"verified_signatures": verified_signatures, "alias_gross": alias_gross,
                          "alias_fees": alias_fees, "alias_net_account_change": after - before,
                          "total_claimed": sum(computed["payouts"].values()), "dust": computed["dust"],
                          "zero_subset_checks": retained["zero_subset_checks"]}
    require(report["original"]["bundle_model_hex"] == report["split"]["bundle_model_hex"], "same complete bundle")
    require(report["original"]["parent_model_hex"] == report["split"]["parent_model_hex"], "same actual parent")
    require(len(actual_b_ids) == 2 and actual_b_ids[0] == actual_b_ids[1], "same B contribution identity")
    summary["alias_net_account_increase"] = summary["split"]["alias_net_account_change"] - summary["original"]["alias_net_account_change"]
    require(summary["alias_net_account_increase"] == 26_814, "retained counterexample")
    return {"schema": "independent-v4-split-receipt-check-v1", "receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
            "scope": "native-receipt-arithmetic-signatures-and-charged-fixture-account-fees-not-complete-chain-replay",
            "result": "COUNTEREXAMPLE_REPRODUCED", "observations": summary,
            "economic_security_qualified": False, "all_real_world_costs_measured": False, "production_activation": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.repo, args.receipt), sort_keys=True, indent=2))
