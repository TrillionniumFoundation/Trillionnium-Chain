"""Bounded complete decoder for the pinned SDK's exported witness shape.

This is a provenance/diagnostic parser, NOT a STARK verifier. The original
r0vm deserializes each frozen witness; check_frozen_receipts and the unchanged
Composite verifier provide cryptographic acceptance. No field is normalized.
SDK source: risc0/risc0@1cc70cf05033a79ebc90f07c679cb4bd1cd301b9.
"""
from segment_continue_source import require, sha


class Cursor:
    def __init__(self, data):
        require(isinstance(data, bytes) and len(data) <= 1024 * 1024, "witness byte budget")
        self.data, self.pos = data, 0

    def take(self, count):
        require(type(count) is int and 0 <= count <= len(self.data) - self.pos, "truncated witness")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def uint(self, count):
        return int.from_bytes(self.take(count), "little")

    def length(self, cap):
        value = self.uint(8)
        require(value <= cap, "witness collection budget")
        return value

    def blob(self, cap):
        return self.take(self.length(cap)).hex()

    def option(self, read):
        tag = self.uint(1)
        require(tag in (0, 1), "noncanonical witness option")
        return read() if tag else None

    def ordered(self, cap, read):
        result = {}
        previous = -1
        for _ in range(self.length(cap)):
            key = self.uint(4)
            require(previous < key, "unordered or duplicate witness map key")
            previous = key
            result[key] = read()
        return result


def decode_segment(data):
    c = Cursor(data)
    result = {"index": c.uint(4)}

    def page():
        require(c.length(1024) == 1024, "wrong SDK page size")
        return c.take(1024).hex()

    result["partial_image"] = {
        "pages": c.ordered(512, page),
        "digests": c.ordered(4096, lambda: c.take(32).hex()),
        "dirty": list(c.ordered(512, lambda: None)),
    }
    result["claim"] = {
        "pre_state": c.take(32).hex(), "post_state": c.take(32).hex(),
        "input": c.take(32).hex(), "output": c.option(lambda: c.take(32).hex()),
        "terminate_state": c.option(lambda: [c.uint(2) for _ in range(4)]),
        "shutdown_cycle": c.option(lambda: c.uint(4)),
    }
    result["read_record"] = [c.blob(128 * 1024) for _ in range(c.length(4096))]
    result["write_record"] = [c.uint(4) for _ in range(c.length(4096))]
    for field in ["suspend_cycle", "paging_cycles", "segment_threshold", "po2"]:
        result[field] = c.uint(4)
    result["inner_index"] = c.uint(8)
    # This profile never requested PoVW. A present nonce is a hard refusal.
    require(c.uint(1) == 0, "PoVW witness refused")
    result["povw_nonce"] = None

    def output():
        # The pinned no-assumption original discloses its final journal.
        require(c.uint(4) == 0, "pruned witness journal refused")
        journal = c.blob(228)
        require(len(journal) == 456, "fixed W1 journal size")
        require(c.uint(4) == 0 and c.length(0) == 0, "witness assumptions refused")
        return {"journal": journal, "assumptions": []}

    result["output"] = c.option(output)
    require(c.pos == len(data), "trailing witness bytes")
    return result


def check_chain(session, encoded):
    require(len(encoded) == len(session["segments"]) == 62, "all 62 witnesses required")
    decoded = []
    for index, (item, data) in enumerate(zip(session["segments"], encoded)):
        require(set(item) == {"bytes", "file", "index", "po2", "sha256", "user_cycles"}
                and item["index"] == index and item["file"] == f"segment-{index}"
                and item["po2"] == 18 and item["bytes"] == len(data)
                and item["sha256"] == sha(data), "witness identity/hash/order differs")
        segment = decode_segment(data)
        require(segment["index"] == segment["inner_index"] == index
                and segment["po2"] == 18 and segment["suspend_cycle"] == item["user_cycles"],
                "witness index/profile/cycles differ")
        claim = segment["claim"]
        require(claim["input"] == "00" * 32 and claim["shutdown_cycle"] is None,
                "witness input/shutdown profile differs")
        require(segment["partial_image"]["dirty"] == [], "dirty frozen memory image")
        require(segment["partial_image"]["digests"].get(1) == claim["pre_state"],
                "witness memory root differs from pre-state")
        if index:
            require(decoded[-1]["claim"]["post_state"] == claim["pre_state"],
                    "witness adjacent pre/post chain differs")
        if index < 61:
            require(claim["terminate_state"] is None and claim["output"] is None
                    and segment["output"] is None and segment["segment_threshold"] == 237144,
                    "nonfinal witness termination/output differs")
        else:
            require(claim["terminate_state"] == [0, 0, 0, 0]
                    and claim["output"] is not None and segment["segment_threshold"] == 0
                    and segment["output"] == {"journal": session["journal_hex"], "assumptions": []},
                    "final witness output/termination differs")
        decoded.append(segment)
    # SDK SystemState.digest binds this root to image_id in check_frozen_receipts.
    require(sum(s["suspend_cycle"] for s in decoded) == session["user_cycles"] == 13364385,
            "complete W1 cycle count differs")
    return decoded


def claims_record(session, encoded):
    decoded = check_chain(session, encoded)
    return {"schema": "pon-w1-frozen-witness-claims-v2", "cryptographic_proof_verified": False,
        "image_id": session["image_id"], "session_claim_digest": session["session_claim_digest"],
        "session_claim_sha256": session["session_claim_sha256"], "journal_hex": session["journal_hex"],
        "segments": [{"index": i, "raw_sha256": sha(data), "bytes": len(data),
            **s["claim"]} for i, (s, data) in enumerate(zip(decoded, encoded))]}
