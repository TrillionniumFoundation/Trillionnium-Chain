#!/usr/bin/env python3
"""M17 structural receipt regressions; fixtures are NOT cryptographic evidence."""
import copy
import hashlib
import unittest
import native_client_campaign_v1 as c


def structural_document():
    records = []
    for i in range(2):
        h = f"{i+1:064x}"
        envelope = {"schema": "trnm.native-client.response.v1", "request_id": f"campaign-{3*i+1}",
                    "ok": True, "candidate_only": True, "chain_id": "structural-test",
                    "genesis_hash": "44"*32, "profile_sha256": "22"*32,
                    "data": {"native_tx_hash": h, "receive_sequence": str(i+1), "status": "pending",
                             "proof_verified": False, "m05_intent_binding": False}}
        retry = copy.deepcopy(envelope); retry["request_id"] = f"campaign-{3*i+2}"
        proof = copy.deepcopy(envelope); proof["request_id"] = f"campaign-{3*i+3}"
        proof["data"] = {"native_tx_hash": h, "proof_class": "poco-three-chain-v0",
                         "package_hex": "00", "parent_header_hex": "00",
                         "proof_verified": True, "m05_intent_binding": False}
        outer = b"{}"  # deliberately non-cryptographic; never sent to the real verifier
        records.append({"kind": "funding" if i == 0 else "transfer", "native_tx_hash": h,
            "outer_hex": outer.hex(), "outer_sha256": hashlib.sha256(outer).hexdigest(),
            "submitted_monotonic_ns": 10+i*10, "ack_monotonic_ns": 11+i*10,
            "verified_monotonic_ns": 12+i*10, "ack": envelope, "retry_ack": retry,
            "proof_response": proof, "mac_verification": {"candidate_only": True,
                "m05_intent_binding": False, "native_tx_hash": h, "proof_verified_by_client": True,
                "height": str(4+i), "index": i}})
    return {"schema": c.PROFILE, "run_id": "candidate", "coordinator_manifest_sha256": "11"*32,
        "profile_sha256": "22"*32, "submit_validator_id": "33"*32, "signing_host": "mac",
        "verification_host": "mac", "transport": "ssh-private-unix-ipc", "started_monotonic_ns": 1,
        "completed_monotonic_ns": 30, "business_transfer_count": 1, "business_window_ns": 2,
        "business_goodput_per_second": 500000000.0, "history_growth": c.derive_history_growth_v1(records, 1),
        "records": records, "candidate_only": True, "m05_intent_binding": False,
        "fault_matrix_completed": False, "performance_acceptance": False, "host_attestation": False,
        "production_activation": False}


def validate(d):
    c.validate_document(d, run_id="candidate", anchor="11"*32, validator_ids={"33"*32})


def set_at(d, path, value):
    for item in path[:-1]: d = d[item]
    d[path[-1]] = value


class NativeCampaignContractTests(unittest.TestCase):
    def test_positive_structure_only(self):
        validate(structural_document())

    def test_positive_committed_retry_preserves_sequence(self):
        d = structural_document()
        for record in d["records"]:
            record["retry_ack"]["data"].update(status="committed", proof_verified=True)
        validate(d)

    def test_boolean_rate_is_rejected(self):
        d = structural_document()
        d["records"][1]["verified_monotonic_ns"] = 1000000020
        d["completed_monotonic_ns"] = 1000000021
        d["business_window_ns"] = 1000000000
        d["business_goodput_per_second"] = True
        d["history_growth"] = c.derive_history_growth_v1(d["records"], 1)
        with self.assertRaises(RuntimeError): validate(d)

    def test_nonfinite_rate_is_rejected(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            d = structural_document(); d["business_goodput_per_second"] = number
            with self.assertRaises(RuntimeError): validate(d)

    def test_funding_height_precedes_business(self):
        d = structural_document(); d["records"][0]["mac_verification"]["height"] = "6"
        with self.assertRaises(RuntimeError): validate(d)

    def test_success_response_cannot_contain_error(self):
        d = structural_document(); d["records"][0]["ack"]["error"] = {"code": "failed"}
        with self.assertRaises(RuntimeError): validate(d)

    def test_retry_cannot_regress_from_committed(self):
        d = structural_document()
        d["records"][0]["ack"]["data"].update(status="committed", proof_verified=True)
        with self.assertRaises(RuntimeError): validate(d)

    def test_server_claim_is_not_verification_authority(self):
        d = structural_document()
        d["records"][0]["proof_response"]["data"]["proof_verified"] = False
        validate(d)  # independent client verification, not this flag, supplies authority


MUTATIONS = [
    ("profile_nonhex", ["profile_sha256"], "z"*64),
    ("profile_uppercase", ["profile_sha256"], "AB"*32),
    ("funding_height_zero", ["records",0,"mac_verification","height"], "0"),
    ("funding_height_leading_zero", ["records",0,"mac_verification","height"], "04"),
    ("funding_height_overflow", ["records",0,"mac_verification","height"], str(2**64)),
    ("funding_height_bool", ["records",0,"mac_verification","height"], True),
    ("funding_height_huge", ["records",0,"mac_verification","height"], "9"*200),
    ("proof_index_bool", ["records",0,"mac_verification","index"], False),
    ("proof_index_negative", ["records",0,"mac_verification","index"], -1),
    ("proof_index_float", ["records",0,"mac_verification","index"], 0.0),
    ("proof_index_overflow", ["records",0,"mac_verification","index"], 2**32),
    ("verification_bool_alias", ["records",0,"mac_verification","proof_verified_by_client"], 1),
    ("verification_candidate_alias", ["records",0,"mac_verification","candidate_only"], 1),
    ("verification_binding_alias", ["records",0,"mac_verification","m05_intent_binding"], 0),
    ("response_schema", ["records",0,"ack","schema"], "wrong"),
    ("response_chain_empty", ["records",0,"ack","chain_id"], ""),
    ("response_chain_mixed", ["records",1,"ack","chain_id"], "another-chain"),
    ("response_genesis_mixed", ["records",1,"ack","genesis_hash"], "55"*32),
    ("response_genesis_nonhex", ["records",0,"ack","genesis_hash"], "q"*64),
    ("response_id_empty", ["records",0,"ack","request_id"], ""),
    ("response_id_control", ["records",0,"ack","request_id"], "bad\nrequest"),
    ("response_id_reused", ["records",0,"retry_ack","request_id"], "campaign-1"),
    ("receive_negative", ["records",0,"ack","data","receive_sequence"], "-1"),
    ("receive_leading_zero", ["records",0,"ack","data","receive_sequence"], "01"),
    ("receive_bool", ["records",0,"ack","data","receive_sequence"], True),
    ("receive_overflow", ["records",0,"ack","data","receive_sequence"], str(2**64)),
    ("retry_status_unsupported", ["records",0,"retry_ack","data","status"], "accepted"),
    ("retry_status_rejected", ["records",0,"retry_ack","data","status"], "rejected"),
    ("ack_binding_true", ["records",0,"ack","data","m05_intent_binding"], True),
    ("ack_proof_alias", ["records",0,"ack","data","proof_verified"], 0),
    ("proof_class_unsupported", ["records",0,"proof_response","data","proof_class"], "self-certified"),
    ("proof_binding_true", ["records",0,"proof_response","data","m05_intent_binding"], True),
    ("proof_boolean_alias", ["records",0,"proof_response","data","proof_verified"], 1),
    ("proof_package_empty", ["records",0,"proof_response","data","package_hex"], ""),
    ("proof_package_uppercase", ["records",0,"proof_response","data","package_hex"], "AB"),
    ("proof_package_nonhex", ["records",0,"proof_response","data","package_hex"], "gg"),
    ("proof_package_space", ["records",0,"proof_response","data","package_hex"], "00 00"),
    ("proof_package_odd", ["records",0,"proof_response","data","package_hex"], "0"),
    ("proof_parent_empty", ["records",0,"proof_response","data","parent_header_hex"], ""),
    ("proof_parent_overlimit", ["records",0,"proof_response","data","parent_header_hex"], "00"*(16*1024+1)),
    ("history_flag_alias", ["history_growth","performance_acceptance"], 0),
]


def mutation_test(path, value):
    def run(self):
        d=structural_document(); set_at(d,path,value)
        with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)): validate(d)
    return run

for name,path,value in MUTATIONS:
    setattr(NativeCampaignContractTests,"test_reject_"+name,mutation_test(path,value))


def missing_field_test(path):
    def run(self):
        d=structural_document(); target=d
        for key in path[:-1]: target=target[key]
        del target[path[-1]]
        with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)): validate(d)
    return run

for name,path in [("schema",["records",0,"ack","schema"]),
    ("genesis",["records",0,"ack","genesis_hash"]),
    ("proof_package",["records",0,"proof_response","data","package_hex"]),
    ("parent_header",["records",0,"proof_response","data","parent_header_hex"])]:
    setattr(NativeCampaignContractTests,"test_reject_missing_"+name,missing_field_test(path))


def run_contract_tests():
    result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeCampaignContractTests))
    if not result.wasSuccessful(): raise AssertionError("native campaign structural contract failed")

if __name__=="__main__": unittest.main()
