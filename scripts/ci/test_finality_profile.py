#!/usr/bin/env python3
"""V1 freezes exactly four members. V2 derives quorum from the actual manifest."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"formal/release-finality-v2"))
from protocol import quorum, require

def validate(profile):
    require(profile["status"]=="specified-disabled", "V1_DISABLED")
    for field in ("activation","legacy_profile_bridge","automatic_fallback"):
        require(profile[field] is False,"V1_AUTHORITY")
    c=profile["committee"]
    require(c["minimum_members"]==c["maximum_members"]==c["actual_members"]==4,"EXACT_V1_MEMBERSHIP")
    require(c["fault_bound_f"]==1 and c["quorum_members"]==3,"EXACT_V1_QUORUM")
    require(c["manifest_count_must_equal_actual_members"] is True,"MANIFEST_COUNT")
    quorum(c["actual_members"],c["fault_bound_f"],c["quorum_members"])
    require(profile["effect_gate"]["chain_confirmation_grants_final_use"] is False,"FINAL_USE")
    require(profile["migration"]["new_namespace_required"] is True and profile["migration"]["fresh_genesis_required"] is True,"NAMESPACE")

def main():
    validate(json.loads((ROOT/"config/finality-profile-v1.json").read_text()))
    p=json.loads((ROOT/"config/release-finality-v2.json").read_text())
    for field in ("activation","native_runtime_integrated","independent_accepted","hepta_final_use","active_pon_changed","automatic_fallback"):
        require(p[field] is False,"V2_AUTHORITY")
    print(json.dumps(dict(result="PASS",scope="disabled profile constraints only",activation=False)))
if __name__=="__main__":main()
