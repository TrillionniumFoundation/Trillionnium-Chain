#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import asdict, dataclass
import argparse, hashlib, json
from typing import Any

class Reject(ValueError):
    pass

PLANES = ("da", "agent-market", "execution", "verify-challenge", "settlement")
PROOF_FAMILIES = ("order", "da", "execution", "result", "settlement", "upgrade")
MAX_U128 = (1 << 128) - 1

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda x: asdict(x)).encode()

def digest(label: str, value: Any) -> str:
    return hashlib.sha256(label.encode() + b"\x00" + canonical(value)).hexdigest()

@dataclass(frozen=True)
class PlaneHead:
    plane: str
    store_id: str
    sequence: int
    order_height: int
    order_block_id: str
    state_root: str
    journal_root: str
    file_identity: str

@dataclass(frozen=True)
class OrderProof:
    chain_id: str
    epoch: int
    height: int
    block_id: str
    parent_block_id: str
    post_state_root: str
    validator_set_hash: str
    signed_weight: int
    total_weight: int
    finality_chain_length: int

@dataclass(frozen=True)
class Snapshot:
    chain_id: str
    namespace_id: str
    manifest_hash: str
    epoch: int
    height: int
    block_id: str
    predecessor_checkpoint: str
    planes: tuple[PlaneHead, ...]
    application_root: str
    inventory_digest: str

@dataclass(frozen=True)
class Checkpoint:
    generation: int
    chain_id: str
    namespace_id: str
    manifest_hash: str
    epoch: int
    height: int
    block_id: str
    application_root: str
    inventory_digest: str
    previous_checkpoint: str
    checksum: str

class ExternalAnchor:
    def __init__(self, chain_id: str) -> None:
        self.chain_id = chain_id
        self.generation = 0
        self.checkpoint_hash = "0" * 64

    def compare_and_swap(self, expected_generation: int, expected_hash: str,
                         target_generation: int, target_hash: str) -> None:
        if self.generation != expected_generation or self.checkpoint_hash != expected_hash:
            raise Reject("anchor-predecessor")
        if target_generation != expected_generation + 1 or not target_hash:
            raise Reject("anchor-target")
        self.generation = target_generation
        self.checkpoint_hash = target_hash

class WholeNodeOwner:
    def __init__(self, chain_id: str, namespace_id: str, manifest_hash: str,
                 external_anchor: ExternalAnchor) -> None:
        if not all((chain_id, namespace_id, manifest_hash)):
            raise Reject("owner-identity")
        if external_anchor.chain_id != chain_id:
            raise Reject("anchor-chain")
        self.chain_id = chain_id
        self.namespace_id = namespace_id
        self.manifest_hash = manifest_hash
        self.external_anchor = external_anchor
        self.checkpoints: dict[int, Checkpoint] = {}
        self.tip_hash = "0" * 64
        self.tip_generation = 0

    @staticmethod
    def derive_application_root(planes: tuple[PlaneHead, ...]) -> str:
        if len(planes) != len(PLANES) or set(p.plane for p in planes) != set(PLANES):
            raise Reject("plane-set")
        projection = [
            {
                "plane": p.plane,
                "store_id": p.store_id,
                "sequence": p.sequence,
                "order_height": p.order_height,
                "order_block_id": p.order_block_id,
                "state_root": p.state_root,
                "journal_root": p.journal_root,
            }
            for p in sorted(planes, key=lambda x: x.plane)
        ]
        return digest("trnm.whole-node.application-root.model.v1", projection)

    @staticmethod
    def derive_inventory_digest(planes: tuple[PlaneHead, ...]) -> str:
        inventory = [(p.plane, p.store_id, p.file_identity) for p in sorted(planes, key=lambda x: x.plane)]
        return digest("trnm.whole-node.inventory.v1", inventory)

    def prepare_snapshot(self, order: OrderProof, planes: tuple[PlaneHead, ...],
                         predecessor_checkpoint: str) -> Snapshot:
        verify_order(order)
        if order.chain_id != self.chain_id:
            raise Reject("order-chain")
        if predecessor_checkpoint != self.tip_hash:
            raise Reject("snapshot-predecessor")
        if len(planes) != len(PLANES) or set(p.plane for p in planes) != set(PLANES):
            raise Reject("plane-set")
        if any(not all((p.store_id, p.order_block_id, p.state_root, p.journal_root, p.file_identity))
               or p.sequence < 0 for p in planes):
            raise Reject("plane-field")
        if any(p.order_height != order.height or p.order_block_id != order.block_id for p in planes):
            raise Reject("plane-order-cut")
        app_root = self.derive_application_root(planes)
        if app_root != order.post_state_root:
            raise Reject("order-application-root")
        return Snapshot(
            self.chain_id,
            self.namespace_id,
            self.manifest_hash,
            order.epoch,
            order.height,
            order.block_id,
            predecessor_checkpoint,
            tuple(sorted(planes, key=lambda x: x.plane)),
            app_root,
            self.derive_inventory_digest(planes),
        )

    def commit(self, snapshot: Snapshot) -> Checkpoint:
        if snapshot.chain_id != self.chain_id or snapshot.namespace_id != self.namespace_id:
            raise Reject("snapshot-identity")
        if snapshot.manifest_hash != self.manifest_hash:
            raise Reject("snapshot-manifest")
        if snapshot.predecessor_checkpoint != self.tip_hash:
            for checkpoint in self.checkpoints.values():
                if (
                    checkpoint.previous_checkpoint == snapshot.predecessor_checkpoint
                    and checkpoint.application_root == snapshot.application_root
                    and checkpoint.height == snapshot.height
                    and checkpoint.block_id == snapshot.block_id
                    and checkpoint.inventory_digest == snapshot.inventory_digest
                ):
                    return checkpoint
            raise Reject("checkpoint-predecessor")
        if snapshot.height <= 0 or (self.tip_generation and snapshot.height <= self.checkpoints[self.tip_generation].height):
            raise Reject("checkpoint-height")
        generation = self.tip_generation + 1
        body = {
            "generation": generation,
            "chain_id": self.chain_id,
            "namespace_id": self.namespace_id,
            "manifest_hash": self.manifest_hash,
            "epoch": snapshot.epoch,
            "height": snapshot.height,
            "block_id": snapshot.block_id,
            "application_root": snapshot.application_root,
            "inventory_digest": snapshot.inventory_digest,
            "previous_checkpoint": self.tip_hash,
        }
        checksum = digest("trnm.whole-node.checkpoint.v1", body)
        checkpoint = Checkpoint(**body, checksum=checksum)
        old_generation = self.tip_generation
        old_hash = self.tip_hash
        self.external_anchor.compare_and_swap(old_generation, old_hash, generation, checksum)
        self.checkpoints[generation] = checkpoint
        self.tip_generation = generation
        self.tip_hash = checksum
        return checkpoint

    def reopen(self, namespace_id: str, manifest_hash: str, inventory_digest: str,
               local_generation: int, local_checkpoint_hash: str) -> Checkpoint | None:
        if namespace_id != self.namespace_id or manifest_hash != self.manifest_hash:
            raise Reject("reopen-identity")
        if local_generation != self.external_anchor.generation or local_checkpoint_hash != self.external_anchor.checkpoint_hash:
            raise Reject("external-anti-rollback")
        if local_generation == 0:
            return None
        checkpoint = self.checkpoints.get(local_generation)
        if checkpoint is None or checkpoint.checksum != local_checkpoint_hash:
            raise Reject("checkpoint-missing-or-torn")
        if checkpoint.inventory_digest != inventory_digest:
            raise Reject("namespace-inventory")
        expected = digest("trnm.whole-node.checkpoint.v1", {
            "generation": checkpoint.generation,
            "chain_id": checkpoint.chain_id,
            "namespace_id": checkpoint.namespace_id,
            "manifest_hash": checkpoint.manifest_hash,
            "epoch": checkpoint.epoch,
            "height": checkpoint.height,
            "block_id": checkpoint.block_id,
            "application_root": checkpoint.application_root,
            "inventory_digest": checkpoint.inventory_digest,
            "previous_checkpoint": checkpoint.previous_checkpoint,
        })
        if expected != checkpoint.checksum:
            raise Reject("checkpoint-checksum")
        return checkpoint

def verify_order(proof: OrderProof) -> None:
    if not all((proof.chain_id, proof.block_id, proof.parent_block_id, proof.post_state_root,
                proof.validator_set_hash)):
        raise Reject("order-field")
    if proof.height <= 0 or proof.epoch < 0 or proof.total_weight <= 0 or proof.signed_weight < 0:
        raise Reject("order-bounds")
    threshold = (2 * proof.total_weight) // 3 + 1
    if proof.signed_weight < threshold:
        raise Reject("order-quorum")
    if proof.finality_chain_length != 3:
        raise Reject("order-finality-chain")

@dataclass(frozen=True)
class SyncManifest:
    chain_id: str
    source_checkpoint: str
    target_height: int
    target_application_root: str
    target_inventory_digest: str
    chunk_hashes: tuple[str, ...]
    order_proof: OrderProof

def stage_sync(manifest: SyncManifest, chunks: tuple[bytes, ...],
               highest_local_height: int, trusted_checkpoint: str) -> dict[str, Any]:
    if manifest.chain_id != manifest.order_proof.chain_id:
        raise Reject("sync-chain")
    if manifest.source_checkpoint != trusted_checkpoint:
        raise Reject("sync-trust-anchor")
    if manifest.target_height <= highest_local_height:
        raise Reject("sync-nonmonotonic")
    if len(chunks) != len(manifest.chunk_hashes) or not chunks:
        raise Reject("sync-chunk-count")
    actual = tuple(hashlib.sha256(chunk).hexdigest() for chunk in chunks)
    if actual != manifest.chunk_hashes:
        raise Reject("sync-chunk-hash")
    verify_order(manifest.order_proof)
    if manifest.order_proof.height != manifest.target_height:
        raise Reject("sync-order-height")
    state_root = digest("trnm.state-sync.snapshot-root.model.v1", [chunk.hex() for chunk in chunks])
    if state_root != manifest.target_application_root or state_root != manifest.order_proof.post_state_root:
        raise Reject("sync-application-root")
    return {
        "namespace": "staging",
        "height": manifest.target_height,
        "application_root": state_root,
        "inventory_digest": manifest.target_inventory_digest,
        "verified": True,
    }

def atomic_swap(staging: dict[str, Any], expected_height: int, external_anchor: ExternalAnchor) -> dict[str, Any]:
    if staging.get("namespace") != "staging" or staging.get("verified") is not True:
        raise Reject("sync-staging")
    if staging.get("height") != expected_height:
        raise Reject("sync-target-height")
    if external_anchor.generation <= 0:
        raise Reject("sync-external-anchor")
    return {**staging, "namespace": "active", "swapped": True}

def make_proof_bundle(checkpoint: Checkpoint) -> dict[str, Any]:
    common = {
        "chain_id": checkpoint.chain_id,
        "height": checkpoint.height,
        "block_id": checkpoint.block_id,
        "application_root": checkpoint.application_root,
    }
    return {
        "schema": "trnm-light-client-proof-bundle-v1",
        "checkpoint": checkpoint.checksum,
        "families": {
            "order": {**common, "finality_chain_length": 3, "quorum": True},
            "da": {**common, "mode": "DA-FULLREP-V1", "complete_retrieval": True},
            "execution": {**common, "jmt_inclusion": True, "composite_root": False},
            "result": {**common, "profile": "deterministic-reexecution-v1", "mature": True},
            "settlement": {**common, "exactly_once": True, "conserved": True, "poco_weight": False},
            "upgrade": {**common, "no_downgrade": True, "trusted_checkpoint": checkpoint.checksum},
        },
    }

def verify_bundle_reference(bundle: dict[str, Any]) -> None:
    if bundle.get("schema") != "trnm-light-client-proof-bundle-v1":
        raise Reject("bundle-schema")
    families = bundle.get("families")
    if not isinstance(families, dict) or tuple(sorted(families)) != tuple(sorted(PROOF_FAMILIES)):
        raise Reject("proof-family-set")
    first = families["order"]
    common = (first.get("chain_id"), first.get("height"), first.get("block_id"), first.get("application_root"))
    if not all(common):
        raise Reject("proof-common")
    for family, value in families.items():
        if (value.get("chain_id"), value.get("height"), value.get("block_id"), value.get("application_root")) != common:
            raise Reject(f"proof-binding:{family}")
    if first.get("finality_chain_length") != 3 or first.get("quorum") is not True:
        raise Reject("proof-order")
    if families["da"].get("mode") != "DA-FULLREP-V1" or families["da"].get("complete_retrieval") is not True:
        raise Reject("proof-da")
    if families["execution"].get("jmt_inclusion") is not True or families["execution"].get("composite_root") is not False:
        raise Reject("proof-execution")
    if families["result"].get("profile") != "deterministic-reexecution-v1" or families["result"].get("mature") is not True:
        raise Reject("proof-result")
    settlement = families["settlement"]
    if settlement.get("exactly_once") is not True or settlement.get("conserved") is not True or settlement.get("poco_weight") is not False:
        raise Reject("proof-settlement")
    upgrade = families["upgrade"]
    if upgrade.get("no_downgrade") is not True or upgrade.get("trusted_checkpoint") != bundle.get("checkpoint"):
        raise Reject("proof-upgrade")

def sample_planes(height: int, block_id: str) -> tuple[PlaneHead, ...]:
    return tuple(
        PlaneHead(
            plane=plane,
            store_id=digest("store", plane),
            sequence=height * 10 + index,
            order_height=height,
            order_block_id=block_id,
            state_root=digest("state", (plane, height)),
            journal_root=digest("journal", (plane, height)),
            file_identity=digest("file", (plane, "inode", 1)),
        )
        for index, plane in enumerate(PLANES)
    )

def order_for(chain_id: str, epoch: int, height: int, block_id: str,
              parent_block_id: str, planes: tuple[PlaneHead, ...]) -> OrderProof:
    return OrderProof(
        chain_id,
        epoch,
        height,
        block_id,
        parent_block_id,
        WholeNodeOwner.derive_application_root(planes),
        digest("validator-set", epoch),
        7,
        10,
        3,
    )

def self_test() -> dict[str, Any]:
    anchor = ExternalAnchor("chain")
    owner = WholeNodeOwner("chain", "namespace", "manifest", anchor)
    planes = sample_planes(10, "block-10")
    order = order_for("chain", 1, 10, "block-10", "block-9", planes)
    snap = owner.prepare_snapshot(order, planes, owner.tip_hash)
    cp = owner.commit(snap)
    assert owner.commit(snap).checksum == cp.checksum
    reopened = owner.reopen("namespace", "manifest", snap.inventory_digest, 1, cp.checksum)
    assert reopened == cp
    bundle = make_proof_bundle(cp)
    verify_bundle_reference(bundle)

    chunks = (b"snapshot-a", b"snapshot-b")
    sync_root = digest("trnm.state-sync.snapshot-root.model.v1", [chunk.hex() for chunk in chunks])
    sync_order = OrderProof("chain", 2, 20, "block-20", "block-19", sync_root,
                            digest("validator-set", 2), 7, 10, 3)
    manifest = SyncManifest("chain", cp.checksum, 20, sync_root,
                            digest("inventory", 20),
                            tuple(hashlib.sha256(c).hexdigest() for c in chunks), sync_order)
    staging = stage_sync(manifest, chunks, 10, cp.checksum)
    active = atomic_swap(staging, 20, anchor)
    assert active["swapped"]

    negative: list[dict[str, str]] = []
    def reject(name: str, fn) -> None:
        try:
            fn()
        except Reject as exc:
            negative.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")

    wrong_plane = tuple(p for p in planes if p.plane != "settlement")
    reject("missing-plane", lambda: owner.prepare_snapshot(order, wrong_plane, cp.checksum))
    forked = tuple(PlaneHead(**{**asdict(p), "order_block_id": "fork"}) if p.plane == "execution" else p for p in planes)
    reject("forked-plane-cut", lambda: owner.prepare_snapshot(order, forked, cp.checksum))
    bad_root = OrderProof(**{**asdict(order), "post_state_root": "bad"})
    reject("order-root-substitution", lambda: owner.prepare_snapshot(bad_root, planes, cp.checksum))
    reject("namespace-copy-or-rename", lambda: owner.reopen("copied", "manifest", snap.inventory_digest, 1, cp.checksum))
    reject("inventory-rename", lambda: owner.reopen("namespace", "manifest", "wrong", 1, cp.checksum))
    reject("coherent-local-rollback", lambda: owner.reopen("namespace", "manifest", snap.inventory_digest, 0, "0" * 64))
    torn = dict(owner.checkpoints); original = owner.checkpoints[1]; owner.checkpoints[1] = Checkpoint(**{**asdict(original), "checksum": "bad"})
    reject("torn-checkpoint", lambda: owner.reopen("namespace", "manifest", snap.inventory_digest, 1, cp.checksum))
    owner.checkpoints = torn

    bad_chunks = (b"snapshot-a", b"wrong")
    reject("sync-chunk-drift", lambda: stage_sync(manifest, bad_chunks, 10, cp.checksum))
    reject("sync-downgrade", lambda: stage_sync(manifest, chunks, 20, cp.checksum))
    reject("sync-wrong-anchor", lambda: stage_sync(manifest, chunks, 10, "other"))
    unverified = dict(staging); unverified["verified"] = False
    reject("unverified-atomic-swap", lambda: atomic_swap(unverified, 20, anchor))

    missing = json.loads(json.dumps(bundle)); del missing["families"]["settlement"]
    reject("missing-proof-family", lambda: verify_bundle_reference(missing))
    das = json.loads(json.dumps(bundle)); das["families"]["da"]["mode"] = "DA-DAS-V1"
    reject("sampling-proof-while-disabled", lambda: verify_bundle_reference(das))
    composite = json.loads(json.dumps(bundle)); composite["families"]["execution"]["composite_root"] = True
    reject("composite-root-substitution", lambda: verify_bundle_reference(composite))
    immature = json.loads(json.dumps(bundle)); immature["families"]["result"]["mature"] = False
    reject("immature-result", lambda: verify_bundle_reference(immature))
    double = json.loads(json.dumps(bundle)); double["families"]["settlement"]["exactly_once"] = False
    reject("duplicate-settlement", lambda: verify_bundle_reference(double))
    downgrade = json.loads(json.dumps(bundle)); downgrade["families"]["upgrade"]["no_downgrade"] = False
    reject("upgrade-downgrade", lambda: verify_bundle_reference(downgrade))
    weak_order = json.loads(json.dumps(bundle)); weak_order["families"]["order"]["quorum"] = False
    reject("insufficient-order-proof", lambda: verify_bundle_reference(weak_order))

    return {
        "schema": "trnm-whole-node-light-client-model-evidence-v1",
        "checkpoint": cp.checksum,
        "positive": {
            "checkpoint_cas": True,
            "response_loss_replay": True,
            "external_anchor_reopen": True,
            "state_sync_staging_and_swap": True,
            "proof_families": list(PROOF_FAMILIES),
        },
        "negative": negative,
        "candidate_only": True,
        "production_jmt_authority": False,
        "signing_or_voting_authority": False,
        "node_support": False,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--bundle-out")
    args = parser.parse_args()
    if not args.self_test:
        raise SystemExit("use --self-test")
    evidence = self_test()
    if args.bundle_out:
        anchor = ExternalAnchor("chain")
        owner = WholeNodeOwner("chain", "namespace", "manifest", anchor)
        planes = sample_planes(10, "block-10")
        order = order_for("chain", 1, 10, "block-10", "block-9", planes)
        cp = owner.commit(owner.prepare_snapshot(order, planes, owner.tip_hash))
        with open(args.bundle_out, "w", encoding="utf-8") as f:
            json.dump(make_proof_bundle(cp), f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
