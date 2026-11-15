#!/usr/bin/env python3
"""Read only a pinned historical private copy; independently decode public fees.

No Node API, original database connection, signing, dispatch or transaction
submission occurs. Ed25519 verification is independent of the retained native
run. This does not reverify W1 or the account multiproof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import subprocess

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SOURCE = "0f18f93f2d35b62c6ca6d63faf4f336d55cbf4bf"
SOURCE_TREE = "94334bb6b52cfd13040059a5e71f47d8cc9603f2"
DB_SHA = "95b879a5fd90bff92adf59910c4b57349fbcb826260684daadef8ff7e5e00bd5"
OLD_READBACK_SHA = "fdf24c78021513e1ba544c5838009351afe2c61fdf50d02ce2a83e7ffa690d93"
PACKETS = {1: "1307e3306eb84a1f5f90d5fb35216473c4f869d6296d749905d215f012da0b40",
           2: "6a6125eceb7916ccf4afb673e9abeaa54d4c66ea6a21de5b0a45956dc4805295"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pon_hash(tag, *parts):
    raw = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    for part in parts:
        raw += struct.pack("<I", len(part)) + part
    return hashlib.sha256(raw).digest()


def decode_packet(raw, block_id):
    require(49900 <= len(raw) <= 1048576 and raw[:8] == b"PNP2PGH2", "fixed growth packet grammar")
    header, ledger = raw[4:358], raw[8:326]
    require(ledger[:6] == b"PNH1\1\0", "fixed ledger header grammar")
    count = struct.unpack_from("<H", raw, 358)[0]
    require(count == 1, "exact historical one-transaction block required")
    pos, txs = 360, []
    for _ in range(count):
        size = struct.unpack_from("<H", raw, pos)[0]
        pos += 2
        require(159 <= size <= 2048, "transaction size")
        txs.append(raw[pos:pos + size])
        pos += size
    size = struct.unpack_from("<I", raw, pos)[0]
    pos += 4
    witness = raw[pos:pos + size]
    pos += size
    require(len(raw) - pos == 49188 and raw[pos:pos + 4] == b"PNW1", "exact retained W1 byte shape")
    require(44 <= size and header[-32:] == pon_hash(b"native-growth-account-witness-v2", witness),
            "witness bytes must match header commitment")
    require(block_id == pon_hash(b"permanent-account-growth-block-v2", header, raw[-32:]),
            "stored block identifier differs from retained header/trace")
    return txs[0], {"network": ledger[6:38].hex(), "parameters": ledger[38:70].hex(),
                    "parent": ledger[70:102].hex(), "height": struct.unpack_from("<Q", ledger, 102)[0],
                    "transaction_count": count, "witness_bytes": size,
                    "full_W1_reverified": False, "account_multiproof_reverified": False}


def decode_wire(raw, expected_tag, network, sender, fee_policy, byte_fee):
    require(159 <= len(raw) <= 2048 and raw[:4] == b"PNX1", "PNX1 envelope")
    nonce, expiry, fee_limit = struct.unpack_from("<QQQ", raw, 68)
    tag, size = raw[92], struct.unpack_from("<H", raw, 93)[0]
    require(tag == expected_tag and size == {2: 80, 3: 32}[tag] and len(raw) == 159 + size,
            "canonical historical task command grammar")
    require(raw[4:36].hex() == network and raw[36:68].hex() == sender and nonce > 0,
            "wire context/owner/nonce")
    require(fee_limit <= 10000000, "fee envelope bound")
    unsigned, signature = raw[:-64], raw[-64:]
    signing_digest = pon_hash(b"tx-sign", unsigned)
    key = Ed25519PublicKey.from_public_bytes(raw[36:68])
    key.verify(signature, signing_digest)
    bad = bytearray(signature)
    bad[-1] ^= 1
    try:
        key.verify(bytes(bad), signing_digest)
    except InvalidSignature:
        pass
    else:
        raise ValueError("modified-signature negative control accepted")
    changed = bytearray(unsigned)
    changed[-1] ^= 1
    try:
        key.verify(signature, pon_hash(b"tx-sign", bytes(changed)))
    except InvalidSignature:
        pass
    else:
        raise ValueError("modified-payload negative control accepted")
    base = fee_policy[tag]
    fee = base + len(raw) * byte_fee
    require(fee <= fee_limit, "wire fee limit insufficient")
    return {"tag": tag, "nonce": nonce, "expiry_height": expiry, "fee_limit": fee_limit,
            "network": network, "sender": sender, "wire_bytes": len(raw), "wire_sha256": sha(raw),
            "payload_bytes": size, "task": raw[95:127].hex(), "transaction_id": pon_hash(b"tx-id", raw).hex(),
            "signing_digest": signing_digest.hex(), "ed25519_signature_verified": True,
            "modified_signature_rejected": True, "modified_payload_rejected": True,
            "base_fee_units": base, "byte_fee_units": byte_fee, "computed_fee_units": fee}, raw[95:-64]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--private-copy", required=True, type=Path)
    parser.add_argument("--old-readback", required=True, type=Path)
    parser.add_argument("--cancel-wire", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    original = args.old_readback.read_bytes()
    require(sha(original) == OLD_READBACK_SHA, "exact retained old funding readback")
    old = json.loads(original)
    database = args.private_copy.resolve()
    before = sha(database.read_bytes())
    require(before == DB_SHA, "exact immutable historical database copy")
    sources = {}
    def git_blob(path):
        raw = subprocess.check_output(["git", "-C", str(args.repo), "show", SOURCE + ":" + path], timeout=30)
        sources[path] = {"bytes": len(raw), "sha256": sha(raw)}
        return raw
    tree = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", SOURCE + "^{tree}"], text=True).strip()
    require(tree == SOURCE_TREE, "exact C1b source tree")
    policy_raw = git_blob("config/pon/ledger-v1.json")
    params_raw = git_blob("config/pon/devnet-v1.json")
    fees = {row["tag"]: row["base_fee_units"] for row in json.loads(policy_raw)["commands"]}
    byte_fee = json.loads(params_raw)["byte_fee_units"]
    for path in ("trillionnium/crates/trnm-protocol/src/pon_wire.rs",
                 "trillionnium/crates/trnm-protocol/src/pon_growth.rs",
                 "trillionnium/crates/trnm-pon-node/src/store/growth/packet.rs",
                 "trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
                 "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests.rs"):
        git_blob(path)
    owner = old["M12"]["original_statement_decoded"]["owner"]
    network = old["M12"]["configuration"]["network"]
    task = old["M12"]["original_statement_decoded"]["task"]
    parameters = old["M12"]["configuration"]["parameters"]
    connection = sqlite3.connect("file:" + str(database) + "?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        blocks = connection.execute("select id,parent,height,packet from blocks order by height").fetchall()
        active = connection.execute("select tip,generation from active where singleton=1").fetchone()
        require(len(blocks) == 3 and active[0] == blocks[2][0] and active[1] == 2, "exact historical canonical chain")
        raw_public, rows = {}, []
        for block_id, parent, height, packet in blocks[1:]:
            require(sha(packet) == PACKETS[height], "retained canonical packet pin")
            wire, header = decode_packet(packet, block_id)
            require(header["height"] == height and header["parent"] == parent.hex()
                    and header["network"] == network and header["parameters"] == parameters, "header context")
            decoded, payload = decode_wire(wire, height + 1, network, owner, fees, byte_fee)
            require(decoded["nonce"] == height and decoded["task"] == task, "same original owner task/nonce")
            if height == 1:
                provider, principal, deadline = payload[32:64], *struct.unpack_from("<QQ", payload, 64)
                require(principal == 1000 and deadline == 20, "original principal/deadline")
                require(pon_hash(b"task-instance-v3", bytes.fromhex(network), bytes.fromhex(parameters),
                                 bytes.fromhex(owner), struct.pack("<Q", decoded["nonce"]), provider,
                                 struct.pack("<Q", principal), struct.pack("<Q", deadline)).hex() == task,
                        "independent task identifier")
                decoded.update(provider=provider.hex(), principal_units=principal, task_deadline_height=deadline)
            else:
                require(wire == args.cancel_wire.read_bytes() and sha(wire) == old["native_funding"]["signed_wire_sha256"],
                        "exact original signed Cancel wire")
            account = connection.execute("select before,after from deltas where block=? and key=?",
                                         (block_id, "account:" + owner)).fetchone()
            before_account, after_account = map(json.loads, account)
            change = after_account["balance"] - before_account["balance"]
            expected = -1000 - decoded["computed_fee_units"] if height == 1 else 1000 - decoded["computed_fee_units"]
            require(change == expected and before_account["nonce"] + 1 == after_account["nonce"] == height,
                    "independent computed fee/principal differs from historical actual account transition")
            rows.append({"block": block_id.hex(), "parent": parent.hex(), "height": height,
                         "packet_sha256": sha(packet), "packet_bytes": len(packet), "header": header,
                         "wire": decoded, "account_before": before_account, "account_after": after_account,
                         "actual_net_balance_change": change})
            label = "reserve" if height == 1 else "cancel"
            raw_public[label + "-wire.bin"], raw_public[label + "-packet.bin"] = wire, packet
    finally:
        connection.close()
    require(sha(database.read_bytes()) == before, "historical private copy changed")
    result = {"schema": "TRNM-W1-OWNER-CANCEL-C1B-INDEPENDENT-FEE-READBACK1", "readback_complete": True,
              "source_commit": SOURCE, "source_tree": tree, "sources": sources,
              "private_copy_sha256_before_and_after": before, "old_funding_readback_sha256": sha(original),
              "cryptography_version": cryptography.__version__, "rows": rows,
              "gross_principal_refund_units": 1000, "reserve_fee_units": rows[0]["wire"]["computed_fee_units"],
              "cancel_fee_units": rows[1]["wire"]["computed_fee_units"],
              "net_cancel_balance_change": rows[1]["actual_net_balance_change"],
              "net_reserve_and_cancel_balance_change": sum(row["actual_net_balance_change"] for row in rows),
              "scope": {"original_database_connections_opened": 0, "private_copy_read_only": True,
                        "new_node_calls": 0, "new_transactions": 0, "new_proof_generations": 0,
                        "fee_fields_decoded_independently_of_balance_residuals": True,
                        "fee_policy_from_exact_C1b_source_configuration": True,
                        "native_executor_reexecuted": False, "full_W1_or_account_multiproof_reverified": False,
                        "provider_payment_observed": False, "M12_resource_release_authorized": False,
                        "production_qualified": False}}
    args.out.mkdir(parents=True, exist_ok=False)
    raw_public["ledger-v1.json"], raw_public["devnet-v1.json"] = policy_raw, params_raw
    for name, raw in raw_public.items():
        (args.out / name).write_bytes(raw)
    result["public_files"] = {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in raw_public.items()}
    (args.out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("readback_complete", "reserve_fee_units", "cancel_fee_units",
                                                  "gross_principal_refund_units", "net_cancel_balance_change",
                                                  "net_reserve_and_cancel_balance_change")}))


if __name__ == "__main__":
    main()
