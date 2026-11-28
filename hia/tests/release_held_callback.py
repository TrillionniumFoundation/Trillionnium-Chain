"""Join independent, real held content and linked signed bundle observations."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import tempfile

from hia.platform.release_file_shadow.owner import DESCRIPTOR, STREAM, Budget, Candidate, HeldReleaseOwner
from hia.tests.release_linked_shadow import observe, request

RUNTIME_ARTIFACTS = (DESCRIPTOR, *STREAM)
ARTIFACT_START, ARTIFACT_WIDTH = 1067, 877
CONTENT_CLAIM_WIDTH = 213
CASES = (
    ("same_held_artifact_and_signed_bundle", "complete", 0),
    ("same_size_incorrect_raw_bytes", "artifact", 6),
    ("valid_v0_scope_but_different_expected_strong_claim", "claim", 112),
    ("valid_held_content_then_original_invalid_quorum", "linked", 2),
)


@dataclass(frozen=True)
class AcceptedShadow:
    claim: bytes
    checkpoint_proposal: bytes


def artifact_from_signed_bundle(bundle, original_claim):
    if (type(bundle) is not bytes or type(original_claim) is not bytes
            or len(bundle) < ARTIFACT_START + ARTIFACT_WIDTH or bundle[4:6] != b"\x01\x00"
            or len(original_claim) != CONTENT_CLAIM_WIDTH
            or original_claim[:4] != b"CCH1" or original_claim[68] != 2
            or original_claim[69:133] != bytes([7]) * 64
            or original_claim[133:141] != b"\0" * 7 + b"\1"):
        raise ValueError("Unexpected original signed held fixture shape")
    row = bundle[ARTIFACT_START:ARTIFACT_START + ARTIFACT_WIDTH]
    n, m, size, executable = struct.unpack_from("<HHQB", row)
    if not 0 < n <= 512 or not 0 < m <= 256 or executable not in (0, 1):
        raise ValueError("Malformed signed artifact row")
    return Candidate(size, row[13:45], row[109:109+n], row[621:621+m],
                     row[45:77], row[77:109], original_claim[4:68], original_claim[69:133],
                     1, 2, bool(executable))


def run(modules, linked, fd, signed, original_claim, expected_claim):
    """Never pass a claim/PASS into linked V0. The join owns both real observations."""
    bundle, borrowed_state, pins, signatures = signed
    artifact = artifact_from_signed_bundle(bundle, original_claim)
    with HeldReleaseOwner(fd) as held:
        native = held.observe(modules, artifact, Budget(1, 1 << 20))
    if native.status:
        return "artifact", native.status, native, None, None
    if native.claim != expected_claim:
        return "claim", 112, native, None, None
    call, = observe(linked, [(request(bundle, borrowed_state, pins, signatures), 72)])
    if call[0]:
        return "linked", call[0], native, call, None
    return "complete", 0, native, call, AcceptedShadow(native.claim, call[-1])


def qualify(modules, linked, artifact_path, original_bytes, original_claim, original_budget,
            valid, invalid, expected_checkpoint):
    data_size = len(original_bytes)
    if not 0 < data_size <= 64 * 1024:
        raise ValueError("unexpected synthetic held raw extent")
    artifact = artifact_from_signed_bundle(valid[0], original_claim)
    if artifact.size != data_size or hashlib.sha256(original_bytes).digest() != artifact.locator:
        raise ValueError("Original fixture differs from the exact signed artifact declaration")
    if artifact_from_signed_bundle(invalid[0], original_claim) != artifact:
        raise ValueError("compound refusal signed a different artifact")
    rows = []
    with tempfile.TemporaryDirectory(prefix="trnm-held-bundle-") as tmp:
        wrong = Path(tmp) / "same-size-different-content"
        wrong.write_bytes(bytes([original_bytes[0] ^ 1]) + original_bytes[1:])
        changed_claim = original_claim[:-1] + bytes([original_claim[-1] ^ 1])
        requests = ((artifact_path, valid, original_claim),
                    (wrong, valid, original_claim),
                    (artifact_path, valid, changed_claim),
                    (artifact_path, invalid, original_claim))
        for (label, expected_stage, expected_code), (path, signed, expected_claim) in zip(CASES, requests, strict=True):
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                phase, code, held, call, published = run(modules, linked, fd, signed, original_claim, expected_claim)
            finally:
                os.close(fd)
            if (phase, code) != (expected_stage, expected_code) or not held.requested \
                    or (held.reads_reserved, held.bytes_reserved) != original_budget \
                    or held.consumed != data_size or held.requested[-1] != 1:
                raise ValueError(f"Unexpected held+signed stage, charged bytes or EOF: {label}")
            if not code:
                if published is None or published.claim != original_claim or published.checkpoint_proposal != expected_checkpoint:
                    raise ValueError("Joint success differs from real Rust claim/checkpoint")
            elif published is not None:
                raise ValueError("A refusal published a partial joint observation")
            if ((phase in ("artifact", "claim") and call is not None)
                    or (phase == "linked" and (call is None or call[:3] != (2, "quorum", 106)))):
                raise ValueError("Linked call ordering or first original failure changed")
            rows.append({"label": label, "stage": phase, "status": code,
                         "actual_requested": list(held.requested), "consumed": held.consumed,
                         "linked_terminal": list(call[:3]) if call is not None else None,
                         "held_claim_sha256": hashlib.sha256(held.claim).hexdigest() if held.claim else None,
                         "linked_checkpoint": call[-1][:32].hex() if call is not None and call[-1] else None,
                         "published": published is not None})
    return rows
