"""Runs only in a full checkout. Reuses actual signed V3 fixtures and verifier.

These are synthetic signatures and held-out plan bindings, NOT new neural runs.
"""
import copy
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"pon-nakamoto-v1"))
from test_model_generation_sequence_parent import ParentBoundGenerationSequenceTests
from campaign_gate import verify_learning_packet, PAIR_FIELDS
from protocol import require

owner=ParentBoundGenerationSequenceTests();owner.setUp()
for decisions in (("adopted",)*3,("adopted","no_update","adopted")):
    c=owner.case(decisions)
    raw,pin,gens,receipts,attestations=owner.owner.args(c)
    pair={k:"a"*40 for k in PAIR_FIELDS} # explicit synthetic SOURCE PIN, not execution metadata
    packet=dict(pair=pair,campaign="b"*64,history_hex=raw.hex(),generations=gens,
                receipts=receipts,attestations=attestations,run_plans=c["plans"],contexts=c["contexts"])
    trusted=dict(pair=pair,campaign="b"*64,history=pin,initial_model=c["initial"])
    before=copy.deepcopy(packet)
    result=verify_learning_packet(packet,trusted)
    require(result["original_v3_result"]==owner.verify(c),"ORIGINAL_V3_RESULT")
    require(packet==before and result["physical_installation_accepted"] is False,"IMMUTABILITY_OR_AUTHORITY")
    changed=copy.deepcopy(packet);changed["run_plans"][0]["controls"][0]["artifact"]="f"*64
    try:verify_learning_packet(changed,trusted)
    except ValueError:pass
    else:raise AssertionError("WRONG_PARENT_ACCEPTED")
print("PASS: two existing signed V3 cases and two actual wrong-parent rejections; no physical/independent claim")
