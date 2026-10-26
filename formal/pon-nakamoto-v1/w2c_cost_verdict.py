"""P2 bounded, read-only admission cost verdict. No permission or consensus change.

Conservative *observational* comparison, NOT a security theorem. Unknown
CPU/GPU advantage, omitted sender cost or unmeasured fanout remain UNKNOWN.
All costs in integer nanoseconds; never derive a lower bound from averages.
"""
import json
import math
from pathlib import Path

SCHEMA = "trnm-w2c-empirical-cost-verdict-v1"

def integer(value, label, zero=False):
    if type(value) is not int or value < (0 if zero else 1) or value >= 1 << 63:
        raise ValueError(label)
    return value

def decide(record):
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("SCHEMA")
    trials = record.get("trials")
    if type(trials) is not list or not 1 <= len(trials) <= 128:
        raise ValueError("TRIALS")
    if type(record.get("receiver_count")) is not int or not 1 <= record["receiver_count"] <= 256:
        raise ValueError("RECEIVERS")
    mode=record.get("ticket_scope")
    if mode not in ("receiver-bound", "globally-replayable"):
        raise ValueError("SCOPE")
    reasons=[]
    if record.get("gpu_cpu_speedup_upper_bound") is None:
        reasons.append("GPU_COST_UNKNOWN")
    if record.get("asic_cpu_speedup_upper_bound") is None:
        reasons.append("ASIC_COST_UNKNOWN")
    ratios=[]
    for row in trials:
        if type(row) is not dict:
            raise ValueError("ROW")
        integer(row.get("attempts"),"ATTEMPTS")
        ticket = integer(row.get("actual_ticket_search_cpu_ns"),"TICKET_CPU")
        forge = integer(row.get("full_forgery_build_cpu_ns"),"FORGERY_CPU",True)
        receiver = integer(row.get("complete_receiver_reject_cpu_ns"),"RECEIVER_CPU")
        # Different receiver-bound tickets are paid once per receiver, but
        # the original forged W1 proof/material may be prepared only ONCE.
        # A globally replayable ticket and its source network send may both
        # fan out to receivers through honest peer propagation.
        if row.get("full_send_transport_cpu_ns") is None:
            reasons.append("TRANSPORT_CPU_UNKNOWN")
            transport = None
        else:
            transport = integer(row["full_send_transport_cpu_ns"],"TRANSPORT_CPU",True)
        ratios.append((ticket, forge, transport, receiver))
    for name in ("gpu_cpu_speedup_upper_bound","asic_cpu_speedup_upper_bound"):
        value=record.get(name)
        if value is not None:
            integer(value,name)
            if value>1_000_000:
                raise ValueError("UNSUPPORTED_ACCELERATOR_BOUND")
    if reasons:
        return {"schema":SCHEMA,"status":"UNKNOWN","reasons":sorted(set(reasons)),
                "no_consensus_authority":True,"production_qualified":False}
    # Hardware ratios must be measured upper bounds, not marketing claims.
    advantage=max(1,record["gpu_cpu_speedup_upper_bound"],
                  record["asic_cpu_speedup_upper_bound"])
    # Globally replayable grant: one security search, one fake proof, one
    # initial send can propagate to N verifying nodes. Receiver-bound grants:
    # N distinct search solutions and N sends, but still just ONE fake-proof
    # construction on the same fixed W1 statement. This pessimistically gives
    # the attacker the right to share all legal reusable preparation.
    # Cloned receiver secrets/epochs would invalidate even the N-ticket rule.
    receiver_copies=record["receiver_count"]
    sender_copies=receiver_copies if mode=="receiver-bound" else 1
    denominators=[]
    for ticket, forge, transport, _receiver in ratios:
        sender=(ticket+transport)*sender_copies+forge
        if sender>=1<<63:
            raise ValueError("TOTAL_OVERFLOW")
        denominators.append(sender)
    # Worst *observed* envelope combines the slowest receiver with the
    # cheapest complete sender. This remains an observation, never a minimum
    # attack-cost theorem, and always has production_qualified=false.
    worst_numerator=max(receiver for *_, receiver in ratios)*receiver_copies*advantage
    worst_denominator=min(denominators)
    amplified=worst_numerator>worst_denominator
    return {"schema":SCHEMA,"status":"OBSERVED_AMPLIFICATION" if amplified else "NO_OBSERVED_AMPLIFICATION",
            "cost_ratio_numerator":worst_numerator,
            "cost_ratio_denominator":worst_denominator,
            "receiver_count":receiver_copies,
            "ticket_scope":mode,
            "accelerator_upper_bound_assumed":advantage,
            "qualification_note":"finite measured samples, not a worst-case attack lower bound",
            "no_consensus_authority":True,"production_qualified":False}

def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("input")
    p.add_argument("--out")
    opts=p.parse_args()
    source=Path(opts.input)
    if not source.is_file() or source.stat().st_size>1024*1024:
        raise SystemExit("INPUT_LIMIT")
    data=json.loads(source.read_text(),parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE")))
    outcome=decide(data)
    raw=json.dumps(outcome,sort_keys=True,indent=2)+"\n"
    if opts.out:
        with open(opts.out,"x",encoding="utf-8") as stream: stream.write(raw)
    else: print(raw,end="")

if __name__=="__main__":
    main()
