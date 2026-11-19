"""Independent complete-byte replay for the fifteen finite Work/Paid faults."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import traceback
from .build import need, read_json, source_manifest, write_json, identity
from .primitive_evidence import decoded, raw_identity, same
from .clock_evidence import Capture, hex_bytes
from .paid_faults import profiles, admit_profile, input_case, MARKER, TEST, TRACE_SCHEMA, NATIVE_SCHEMA, ORIGINAL_SCHEMA, SCOPES

RAW_NAMES=("report.json","events.jsonl","stdout.raw","stderr.raw")
def uint(value,bits=64):return type(value) is int and 0<=value<1<<bits
def sint(value):return type(value) is int and -(1<<63)<=value<1<<63
def signed(value):return value-(1<<64) if value>>63 else value

def terminal_binding(ledger,tid,*,native):
    """Retain per-thread exit-stop and any later shared group wait status."""
    entries=ledger["entries"];stopped=ledger["exit_stops"][tid]
    terminal=ledger["roster"][tid]["terminal"]
    own=[e for e in entries.values() if e["tid"]==tid and e["nr"] in (60,231)]
    need(len(own)==1 and uint(own[0]["args"][0],8)
         and same(stopped["status"],own[0]["args"][0]<<8)
         and own[0]["sequence"]<stopped["sequence"]<terminal["sequence"]
         and uint(terminal["exit_code"],8) and terminal["signal"] is None,
         "Paid terminal lacks its exact actual exit syscall and exit-stop")
    if same(terminal["exit_code"],own[0]["args"][0]):return None
    root=ledger["root"];group=[e for e in entries.values() if e["tid"]==root and e["nr"]==231]
    need(native is True and tid!=root and ledger["roster"][tid]["parent"]==root
         and own[0]["nr"]==60 and same(own[0]["args"][0],0)
         and len(group)==1 and uint(group[0]["args"][0],8) and group[0]["args"][0]>0,
         "Paid thread wait status lacks its observed native group exit")
    group=group[0];root_stop=ledger["exit_stops"][root];root_terminal=ledger["roster"][root]["terminal"]
    need(same(group["args"][0],terminal["exit_code"])
         and same(root_stop["status"],terminal["exit_code"]<<8)
         and same(root_terminal["exit_code"],terminal["exit_code"]) and root_terminal["signal"] is None
         and stopped["sequence"]<group["sequence"]<root_stop["sequence"]<terminal["sequence"]
         and root_stop["sequence"]<root_terminal["sequence"],
         "Paid shared wait status differs from the actual parent group exit")
    return {"main_tid":root,"entry":group["sequence"],"exit_stop":root_stop["sequence"],
            "exit_code":terminal["exit_code"]}

def collect(events,stdout,stderr,*,native):
    need(type(events) is list and events,"Complete Paid event ledger required")
    root=events[0].get("tid");need(uint(root,32) and root>0,"Actual Paid root TID required")
    roster={root:{"parent":None,"birth":0}};pending={};entries={};exits={};roles={}
    clocks=[];injections=[];role_history=[];links={};tids={};fallback={};execs=[];writes={1:[],2:[]}
    input_parts=[];terminal=set();exit_stops={}
    entry_fields={"sequence","kind","tid","nr","args","write_bytes_hex","own_thread_link","role_marker_hex",
                  "clock_id","clock_ordinal","role","role_index","role_clock_ordinal","fault",
                  "actual_clone","futex_word_before","role_spawn_ordinal","logical_clone_fallback"}
    exit_fields={"sequence","kind","tid","entry","nr","result","kernel_result_before_injection",
                 "own_thread_link_result_hex","read_bytes_hex","stat_bytes_hex","futex_word_after",
                 "parent_tid_word_after","actual_timespec_hex"}
    for number,row in enumerate(events,1):
        need(type(row) is dict and same(row.get("sequence"),number) and uint(row.get("tid"),32),
             "Paid event sequence/TID exact type differs")
        tid=row["tid"];kind=row.get("kind")
        need(tid in roster and tid not in terminal,"Paid event outside actual born/retired thread")
        if kind=="syscall-entry":
            need(set(row)<=entry_fields and uint(row.get("nr")) and type(row.get("args")) is list
                 and len(row["args"])==6 and all(uint(v) for v in row["args"]) and tid not in pending,
                 "Exact Paid syscall entry/pairing required")
            nr=row["nr"];args=row["args"];pending[tid]=row;entries[number]=row
            if nr==1:
                need(args[2]<=65536 and len(hex_bytes(row.get("write_bytes_hex"),args[2]))==args[2],
                     "Complete actual Paid write bytes required")
            else:need("write_bytes_hex" not in row,"Unbound Paid write capture")
            if nr==228:
                count=sum(c["tid"]==tid for c in clocks)+1
                need(same(row.get("clock_id"),signed(args[0])) and same(row.get("clock_ordinal"),count),
                     "Paid actual clock ID/per-thread ordinal differs")
                if tid in roles:
                    roles[tid]["clock_count"]+=1
                    need(same(row.get("role"),roles[tid]["role"])
                         and same(row.get("role_index"),roles[tid]["index"])
                         and same(row.get("role_clock_ordinal"),roles[tid]["clock_count"]),
                         "Paid actual clock role/ordinal differs")
                else:need(all(k not in row for k in ("role","role_index","role_clock_ordinal")),"Unbound Paid pre-role clock")
            if nr in (56,435):
                actual=row.get("actual_clone");need(type(actual) is dict,"Complete Paid clone argument bytes required")
                if nr==56:
                    expected={"abi":"clone","flags":args[0],"stack":args[1],"parent_tid":args[2],"child_tid":args[3],"tls":args[4]}
                else:
                    raw=hex_bytes(actual.get("argument_hex"));need(64<=len(raw)<=88 and same(len(raw),args[1]),"Paid clone3 extent")
                    words=struct.unpack("<11Q",raw+bytes(88-len(raw)))
                    expected={"abi":"clone3","argument_hex":raw.hex(),"argument_bytes":len(raw),
                        **dict(zip(("flags","pidfd","child_tid","parent_tid","exit_signal","stack","stack_size","tls",
                                    "set_tid","set_tid_size","cgroup"),words))}
                need(same(actual,expected),"Paid clone descriptor differs from captured syscall")
                if tid in roles:
                    is_fallback=nr==56 and fallback.pop(tid,False)
                    if not is_fallback:roles[tid]["spawn_count"]+=1
                    need(row.get("logical_clone_fallback") is is_fallback
                         and same(row.get("role_spawn_ordinal"),roles[tid]["spawn_count"])
                         and same(row.get("role"),roles[tid]["role"])
                         and same(row.get("role_index"),roles[tid]["index"]),"Paid clone ordinal/fallback differs")
            if nr==202:need(args[0]%4==0 and uint(row.get("futex_word_before"),32),"Paid actual futex before word")
        elif kind=="syscall-exit":
            need(set(row)<=exit_fields and tid in pending,"Paid exit without its actual entry")
            entry=pending.pop(tid);nr=entry["nr"];args=entry["args"];result=row.get("result")
            need(same(row.get("entry"),entry["sequence"]) and same(row.get("nr"),nr)
                 and sint(result) and sint(row.get("kernel_result_before_injection")),"Paid syscall result/pair differs")
            exits[entry["sequence"]]=row;fault=entry.get("fault")
            if fault is None:need(result==row["kernel_result_before_injection"],"Unrecorded Paid syscall substitution")
            else:
                need(nr==228 and type(fault) is dict and set(fault)=={
                    "kind","error","invalid_timespec","original_syscall_skipped"}
                     and fault["kind"]=="clock" and type(fault["invalid_timespec"]) is bool
                     and fault["original_syscall_skipped"] is True
                     and ((fault["invalid_timespec"] and fault["error"] is None and result==0)
                          or (not fault["invalid_timespec"] and type(fault["error"]) is int
                              and fault["error"] in (5,22) and result==-fault["error"]))
                     and row["kernel_result_before_injection"]==-38,"Paid actual skipped syscall rule differs")
                injections.append({"tid":tid,"role":entry.get("role"),"role_index":entry.get("role_index"),
                    "clock_id":entry.get("clock_id"),"clock_ordinal":entry.get("role_clock_ordinal"),
                    "spawn_ordinal":entry.get("role_spawn_ordinal"),"entry":entry["sequence"],"rule":fault,
                    "actual_skipped_result":-38,"injected_result":result})
            if nr==1:
                raw=hex_bytes(entry["write_bytes_hex"])
                need(0<=result<=len(raw),"Paid actual write did not complete within captured bytes")
                if args[0] in writes:writes[args[0]].append(raw[:result])
            if "own_thread_link" in entry:
                link=entry["own_thread_link"]
                need(nr in (89,267) and same(link,{"path":"/proc/thread-self",
                     "buffer":args[1] if nr==89 else args[2],"capacity":args[2] if nr==89 else args[3]})
                     and 0<result<=link["capacity"]<=65536
                     and hex_bytes(row.get("own_thread_link_result_hex"),result)==
                         (str(root)+"/task/"+str(tid)).encode(),"Paid actual kernel thread link differs")
                links[tid]=row["sequence"]
            if nr==186:need(result==tid,"Paid gettid differs from actual thread");tids[tid]=row
            if native and nr in (0,17) and result>=0:
                raw=hex_bytes(row.get("read_bytes_hex"),result)
                need(result<=args[2]<=65536,"Paid native read bounds")
                if args[0]==0:
                    need(nr==17 and tid==root and args[3]==0 and not input_parts,
                         "Paid native input must use its one owned offset-zero pread")
                    input_parts.append(raw)
            if native and nr==5 and result==0:hex_bytes(row.get("stat_bytes_hex"),144)
            if nr==202:need(uint(row.get("futex_word_after"),32),"Paid actual futex after word")
            if nr in (56,435) and result>0:
                need(result in roster and roster[result]["clone_entry"]==entry["sequence"],
                     "Paid clone return lacks matching actual birth")
                if entry["actual_clone"]["flags"]&0x100000:
                    need(uint(row.get("parent_tid_word_after"),32) and row["parent_tid_word_after"] in (0,result),
                         "Paid actual parent-settid value")
            if nr==435 and result==-38:fallback[tid]=True
            if nr==228:
                clock={"tid":tid,"ordinal":entry["clock_ordinal"],"clock_id":entry["clock_id"],
                    "entry":entry["sequence"],"exit":row["sequence"],"result":result,
                    "role":entry.get("role"),"role_index":entry.get("role_index"),
                    "role_clock_ordinal":entry.get("role_clock_ordinal"),"injected":fault}
                if result==0:
                    raw=hex_bytes(row.get("actual_timespec_hex"),16);sec,ns=struct.unpack("<qq",raw)
                    if fault is not None and fault["invalid_timespec"]:
                        need((sec,ns)==(0,1_000_000_000),"Paid invalid timespec mutation differs")
                    else:need(sec>=0 and 0<=ns<1_000_000_000,"Invalid successful Paid actual timespec")
                    clock.update(timespec_hex=raw.hex(),seconds=sec,nanoseconds=ns)
                else:need("actual_timespec_hex" not in row,"Failed Paid clock invented output time")
                clocks.append(clock)
        elif kind=="actual-role":
            if native:
                completed=tids.get(tid);need(completed is not None and tid not in roles,"Native Paid role lacked first actual gettid")
                entry=entries[completed["entry"]];role=1 if tid==root else 2
                need(tid==root or roster[tid]["parent"]==root,"Native Paid role is not a direct owned child")
                expected={"sequence":number,"kind":kind,"tid":tid,"role":role,"index":0,
                          "actual_gettid_exit":completed["sequence"]}
            else:
                candidates=[r for r in entries.values() if r["tid"]==tid and "role_marker_hex" in r and r["sequence"] in exits]
                need(candidates,"Original Paid role missing captured marker")
                entry=candidates[-1];completed=exits[entry["sequence"]]
                raw=hex_bytes(entry["role_marker_hex"],32);declared,role,index=struct.unpack("<3Q",raw[8:])
                need(raw[:8]==b"PCROLE01" and declared==tid and role in (1,2,4) and index==0
                     and entry["nr"]==1 and entry["args"][0]==2 and entry["args"][2]==completed["result"]==32
                     and hex_bytes(entry["write_bytes_hex"])==raw and tid in links and links[tid]<entry["sequence"],
                     "Original Paid marker not bound to complete kernel-observed bytes/TID")
                prior=roles.get(tid)
                need((prior is None and role in (1,2)) or (prior is not None and prior["role"]==1 and role==4),
                     "Original Paid role transition differs")
                expected={"sequence":number,"kind":kind,"tid":tid,"role":role,"index":0,
                          "actual_thread_link_exit":links[tid]}
            need(same(row,expected),"Paid role annotation not derived from captured syscall")
            roles[tid]={"role":role,"index":0,"marker_entry":entry["sequence"],"marker_exit":completed["sequence"],
                        "clock_count":0,"spawn_count":0}
            role_history.append(row)
        elif kind=="birth":
            need(set(row)=={"sequence","kind","tid","child","ptrace_event"}
                 and uint(row.get("child"),32) and row["child"]>0 and row["child"] not in roster
                 and type(row.get("ptrace_event")) is int and row["ptrace_event"] in (1,2,3)
                 and tid in pending and pending[tid]["nr"] in (56,435),"Paid actual birth/clone pairing differs")
            entry=pending[tid]
            roster[row["child"]]={"parent":tid,"birth":number,"clone_entry":entry["sequence"],
                                  "child_tid_address":entry["actual_clone"]["child_tid"]}
        elif kind=="exec":
            need(set(row)=={"sequence","kind","tid","actual_executable","auxv"} and tid==root and not execs
                 and type(row["actual_executable"]) is str,"Paid unexpected exec")
            execs.append(row)
        elif kind=="exit-stop":
            need(set(row)=={"sequence","kind","tid","status"} and uint(row.get("status")) and tid not in exit_stops,
                 "Paid exit-stop annotation differs");exit_stops[tid]=row
        elif kind=="terminal":
            need(set(row)=={"sequence","kind","tid","exit_code","signal"} and uint(row.get("exit_code"),8)
                 and row.get("signal") is None and tid in exit_stops,"Paid terminal result/signal differs")
            entry=pending.pop(tid,None)
            need(entry is not None and entry["nr"] in (60,231),
                 "Paid terminal lacks its actual exit syscall")
            roster[tid]["terminal"]=row;terminal.add(tid)
        elif kind=="child-clone-return":
            need(set(row)=={"sequence","kind","tid","result"} and same(row["result"],0)
                 and roster[tid]["parent"] is not None,"Paid unassociated clone return")
        elif kind=="child-initial-stop":
            need(set(row)=={"sequence","kind","tid"} and roster[tid]["parent"] is not None,"Paid unowned child stop")
        else:raise ValueError("Unreviewed Paid event kind: "+str(kind))
    need(not pending and set(roster)==terminal and len(execs)==1,"Paid owned thread lifetime incomplete")
    need(b"".join(writes[1])==stdout and b"".join(writes[2])==stderr,"Paid raw stdout/stderr not equal actual writes")
    ledger={"root":root,"roster":roster,"roles":roles,"role_history":role_history,"entries":entries,"exits":exits,
            "clocks":clocks,"injections":injections,"exec":execs[0],"input":b"".join(input_parts),
            "exit_stops":exit_stops}
    ledger["terminal_groups"]={}
    for tid in roster:
        binding=terminal_binding(ledger,tid,native=native)
        if binding is not None:ledger["terminal_groups"][tid]=binding
    return ledger

def joined_before_output(ledger,shape,first_output,*,native):
    """Bind publication to the actual kernel-cleared child-TID futex.

    waitpid may deliver a worker's terminal notification after the parent is
    stopped at its first write, even though the kernel has already cleared the
    thread ID and completed that parent's join. Notification collection order
    is not an execution-order witness. Keep the complete terminal observation,
    and independently require the real join return before publication.
    """
    worker=shape["worker"]
    if worker is None:return None
    main=shape["main"];child=ledger["roster"][worker]
    need(type(native) is bool and uint(first_output) and first_output>0
         and child["parent"]==main,"Paid join owner/publication identity differs")
    clone=ledger["entries"][child["clone_entry"]]
    actual=clone["actual_clone"];address=child["child_tid_address"]
    need(clone["tid"]==main and clone["nr"] in (56,435)
         and uint(address) and address>0 and address%4==0
         and same(actual["child_tid"],address) and uint(actual["flags"])
         and actual["flags"]&0x310100==0x310100,
         "Paid join lacks its actual shared-thread clear-TID clone")
    exit_calls=[row for row in ledger["entries"].values()
                if row["tid"]==worker and row["nr"] in (60,231)]
    need(len(exit_calls)==1 and exit_calls[0]["nr"]==60 and same(exit_calls[0]["args"][0],0),
         "Paid owner did not execute its own successful thread exit")
    stopped=ledger["exit_stops"][worker];terminal=child["terminal"]
    need(same(stopped["status"],0) and uint(terminal["exit_code"],8)
         and terminal["signal"] is None
         and exit_calls[0]["sequence"]<stopped["sequence"]<terminal["sequence"],
         "Paid owner actual exit-stop/terminal sequence differs")
    joins=[row for row in ledger["entries"].values()
           if row["tid"]==main and row["nr"]==202 and row["args"][0]==address]
    need(joins,"Paid owner has no actual child-TID join syscall")
    # HIA uses shared FUTEX_WAIT; the bound original glibc uses shared
    # FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME with an infinite timeout.
    expected=[address,0 if native else 265,worker,0,0,0 if native else 0xffffffff]
    completed=[]
    for entry in joins:
        returned=ledger["exits"][entry["sequence"]]
        need(same(entry["args"],expected)
             and uint(entry["futex_word_before"],32) and entry["futex_word_before"] in (0,worker)
             and returned["tid"]==main and returned["nr"]==202
             and same(returned["entry"],entry["sequence"])
             and sint(returned["result"]) and returned["result"] in (0,-11,-4)
             and same(returned["kernel_result_before_injection"],returned["result"])
             and entry["sequence"]<returned["sequence"]<first_output,
             "Paid actual child-TID futex invocation/result differs")
        completed.append(returned)
    last=completed[-1]
    need(last["result"] in (0,-11) and same(last["futex_word_after"],0)
         and stopped["sequence"]<last["sequence"],
         "Paid publication lacks a successful kernel-cleared child-TID join")
    group=ledger.get("terminal_groups",{}).get(worker)
    if terminal["exit_code"]!=0:
        need(native is True and group is not None and group["main_tid"]==main
             and same(group["exit_code"],terminal["exit_code"])
             and first_output<group["entry"]<group["exit_stop"]<terminal["sequence"],
             "Paid nonzero thread notification lacks a group exit after joined publication")
    else:need(group is None,"Unbound Paid group wait status")
    return {"child_tid_address":address,"clone_entry":child["clone_entry"],
            "worker_exit_entry":exit_calls[0]["sequence"],"worker_exit_stop":stopped["sequence"],
            "join_entry":joins[-1]["sequence"],"join_exit":last["sequence"],
            "terminal_notification":terminal["sequence"],"first_output":first_output,
            "worker_terminal_exit_code":terminal["exit_code"],"group_exit":group,
            "terminal_notification_followed_output":terminal["sequence"]>first_output}

def native_input(ledger,payload):
    """Replay the actual sealed memfd read: seals, fstat size, one offset-zero pread."""
    need(type(payload) is bytes and len(payload)==49348 and ledger["input"]==payload,
         "Paid native complete input bytes differ")
    selected={}
    for label,nr,command in (("seals",72,1034),("stat",5,None),("read",17,None)):
        rows=[r for r in ledger["entries"].values() if r["nr"]==nr and r["args"][0]==0
              and (command is None or r["args"][1]==command)]
        need(len(rows)==1 and rows[0]["tid"]==ledger["root"],"Paid native exact owned input call roster differs")
        entry=rows[0];result=ledger["exits"][entry["sequence"]];selected[label]=(entry,result)
    seal,seal_result=selected["seals"];stat,stat_result=selected["stat"];read,read_result=selected["read"]
    raw=hex_bytes(stat_result.get("stat_bytes_hex"),144)
    need(same(seal_result["result"],15) and same(stat_result["result"],0)
         and struct.unpack_from("<I",raw,24)[0]&0xf000==0x8000
         and struct.unpack_from("<Q",raw,48)[0]==len(payload)
         and same(read["args"][2:4],[len(payload),0]) and same(read_result["result"],len(payload))
         and hex_bytes(read_result.get("read_bytes_hex"),len(payload))==payload
         and seal_result["sequence"]<stat["sequence"]<stat_result["sequence"]<read["sequence"],
         "Paid native seals/stat/offset/result do not prove the complete immutable input")

def layout(profile):
    name=profile["name"]
    base=[("begin",3),("reserve",1),("work",1),("checkpoint",3),("checkpoint-wall",1),
          ("finish",3),("finish-wall",1),("outer",3),("settle",1)]
    if name=="constructor-clock1-eio":return []
    if name in ("begin-clock3-einval","begin-clock3-invalid","reserve-clock1-eio"):return base[:2]
    if name=="begin-clock3-persistent-eio":return [base[0],base[0],base[1]]
    if name=="begin-clock3-eio-fallback":return [base[0]]+base
    if name=="work-clock1-eio":return base[:3]+[("drop",3),("drop-wall",1),("settle",1)]
    if name in ("live-clock3-einval","live-clock3-invalid"):return base[:4]+base[5:]
    if name=="live-clock3-eio-fallback":return base[:4]+base[3:]
    if name=="live-clock1-eio":return base[:5]
    if name=="final-live-clock3-einval":return base[:6]+base[7:]
    if name=="final-live-clock1-eio":return base[:7]
    return base

def actual_time(row):
    if row["result"]!=0 or row["injected"] is not None and row["injected"]["invalid_timespec"]:return None
    value=row["seconds"]*1_000_000_000+row["nanoseconds"]
    need(uint(value),"Paid clock value exceeds actual u64 range")
    return value

def clock_shape(ledger,profile,*,native,private):
    expected=layout(profile);need([clock for _,clock in expected]==profile["worker_clock_ids"],"Source Paid clock layout changed")
    if not native and not private:expected=[row for row in expected if row[1]==3]
    constructor=[row for row in ledger["role_history"] if row["role"]==1]
    workers=[row for row in ledger["role_history"] if row["role"]==2]
    need(len(constructor)==1 and len(workers)==int(profile["name"]!="constructor-clock1-eio"),
         "Complete actual Paid constructor/owner role roster differs")
    main=constructor[0]["tid"];worker=workers[0]["tid"] if workers else None
    need(main==ledger["root"] if native else ledger["roster"][main]["parent"]==ledger["root"],
         "Paid constructor is not its actual owned task")
    if worker is not None:
        need(ledger["roster"][worker]["parent"]==main,"Paid owner not an actual direct constructor child")
        clone=ledger["entries"][ledger["roster"][worker]["clone_entry"]]["actual_clone"]
        need(clone["flags"]&0x310100==0x310100 and clone["child_tid"]>0 and clone["child_tid"]%4==0,
             "Paid owner lost shared VM/thread and parent/child-clear-TID semantics")
    expected_roles=([1]+([2] if worker else [])) if native else ([1]+([4,2] if worker else []))
    need([r["role"] for r in ledger["role_history"]]==expected_roles
         and len(ledger["roster"])==(1 if native else 2)+int(worker is not None),
         "Paid trace added or omitted an actual thread/role")
    main_calls=[r for r in ledger["clocks"] if r["tid"]==main and r["role"]==1]
    work_calls=[r for r in ledger["clocks"] if r["tid"]==worker and r["role"]==2]
    # Original PaidMutationCpuBudget::new constructs ListenerIntake before its own watermark.
    main_kinds=[("deadline",1),("budget-constructor",1)] if native else [
        ("deadline",1),("intake-constructor",1),("budget-constructor",1)]
    if profile["name"]=="constructor-clock1-eio":main_kinds=main_kinds[:2]
    if not native and not private:main_kinds=[]
    need(len(main_calls)==len(main_kinds) and len(work_calls)==len(expected),
         "Complete current-source Paid clock count differs")
    fault=profile["fault"];wanted=[]
    for rows,kinds,role in ((main_calls,main_kinds,1),(work_calls,expected,2)):
        for ordinal,(row,(kind,clock_id)) in enumerate(zip(rows,kinds,strict=False),1):
            need(same(row["clock_id"],clock_id) and same(row["role_index"],0)
                 and same(row["role_clock_ordinal"],ordinal),"Paid clock ID/order differs from original method")
            selected=fault is not None and role in fault["clock_roles"] and ordinal in fault.get("clock_ordinals",[fault.get("clock_when")])
            if selected:
                rule={"kind":"clock","error":fault.get("clock_error"),"invalid_timespec":fault.get("clock_invalid",False),
                      "original_syscall_skipped":True}
                need(same(row["injected"],rule) and same(row["result"],0 if rule["invalid_timespec"] else -rule["error"]),
                     "Paid fault moved, changed, omitted or retried")
                wanted.append(row["entry"])
            else:need(row["injected"] is None and same(row["result"],0),"Unplanned Paid clock failure/injection")
    need([r["entry"] for r in ledger["injections"]]==wanted
         and len(wanted)==(0 if fault is None else len(fault.get("clock_ordinals",[fault.get("clock_when")]))),
         "Paid complete actual injection roster differs")
    need(all(r["role"] in (None,1,2) for r in ledger["clocks"]),"Unexpected clock after Paid constructor role retired")
    for tid in (main,worker):
        for clock_id in (1,3):
            values=[actual_time(r) for r in ledger["clocks"] if r["tid"]==tid and r["clock_id"]==clock_id
                    and actual_time(r) is not None]
            need(values==sorted(values),"Paid actual same-thread clock rewound")
    selected={kind:actual_time(row) for (kind,_),row in zip(expected,work_calls,strict=True)}
    if main_calls and selected.get("work") is not None:
        need(selected["work"]<actual_time(main_calls[0])+4_000_000_000,
             "Paid fixture renewed or exceeded the earlier original Work deadline")
    return {"main":main,"worker":worker,"calls":work_calls,"labels":expected,"times":selected,
            "constructor":actual_time(main_calls[-1]) if main_calls else None}

def budget_flow(shape,profile):
    """Replay the original standalone reserve/refill/live/residual operations."""
    updated=shape["constructor"];need(updated is not None,"Actual raw Paid constructor timestamp required")
    balance=2_000_000_000;inflight=0;credited=0;discarded=0;booked=0;debited=0;residual=0;settled=0
    times=shape["times"];start=times.get("begin");last=start
    def refill(now):
        nonlocal updated,balance,credited,discarded
        need(now>=updated,"Paid refill watermark rewound")
        offered=(now-updated)*250_000_000//1_000_000_000;updated=now
        after=min(balance+offered,2_000_000_000-inflight*100_000_000)
        credited+=after-balance;discarded+=balance+offered-after;balance=after
    if times.get("reserve") is not None:
        refill(times["reserve"])
        if start is not None:balance-=100_000_000;inflight=1;booked=100_000_000
    for kind in ("checkpoint","finish","drop"):
        cpu=times.get(kind);wall=times.get(kind+"-wall")
        if cpu is not None and wall is not None:
            need(last is not None and cpu>=last,"Paid live sample without its actual begin")
            delta=cpu-last;last=cpu;refill(wall);balance-=delta;debited+=delta
    if times.get("settle") is not None:
        need(inflight==1,"Paid settlement without its original reservation")
        refill(times["settle"]);inflight-=1
        known=profile["name"] in ("normal-zero-target","begin-clock3-eio-fallback","live-clock3-eio-fallback")
        if known:
            residual=times["outer"]-times["finish"];settled=times["outer"]-start
            balance+=100_000_000-residual;booked-=100_000_000
    return {"credit":balance,"updated":updated,"in_flight":inflight,
        "flow":{"initial_credit_ns":"2000000000","credited_refill_ns":credited,"discarded_refill_ns":discarded,
          "booked_reservation_ns":booked,"live_debited_cpu_ns":debited,"settlement_residual_cpu_ns":residual,
          "settled_full_cpu_ns":settled,"settlement_discard_ns":0}}

def native_shape(frame,shape,profile):
    h=frame["header"];paid=frame["paid"];owner=paid["owner"];epoch=paid["epoch"];name=profile["name"]
    constructor=name=="constructor-clock1-eio";worker=shape["worker"];panic=profile["domain"]==4
    need(h["fixture"]==1 and h["host_fixture"]==int(not constructor) and h["main_tid"]==shape["main"]
         and h["worker_tid"]==(worker or 0) and h["joins"]==int(worker is not None)
         and h["domain"]==profile["domain"] and h["code"]==profile["code"]
         and frame["progress"]==[] and frame["product_bytes"]==0
         and h["post_checks"]==(0 if panic else 5) and h["aggregate_samples"]==(0 if panic else 2),
         "Paid native actual lifetime/refusal/after-sampling differs")
    need([paid["global_poison"],paid["request_poison"]]==profile["poison"]
         and epoch[6]==profile["in_flight"],"Paid actual mutex poison/reservation differs")
    if constructor:
        need(h["pre_checks"]==h["worker_host_calls"]==h["alive_clocks"]==h["acquirer_tid"]==0
             and all(h[k]==0 for k in ("parent_dev","parent_ino","parent_uid","cpu_quota","cpu_period",
                                      "memory_limit","pids_limit","boot_bytes")),"Paid constructor failure invented Host authority")
        need(not any(owner+epoch+paid["binding"]+paid["meta"]),"Failed Paid constructor fabricated an account")
        return
    times=shape["times"];begin_refused=name in ("begin-clock3-einval","begin-clock3-persistent-eio","begin-clock3-invalid")
    checkpoints=int(any(k=="checkpoint" for k,_ in shape["labels"]))
    stage=1 if begin_refused or name=="reserve-clock1-eio" else 4 if name=="work-clock1-eio" else 2 if name=="live-clock1-eio" else 3
    sequence=1 if stage==1 else 2 if stage in (2,4) else 3
    expected_binding=[0,stage,sequence,2,checkpoints,3 if panic else 1 if begin_refused else 0,0,0,1,1]
    need(paid["binding"]==expected_binding and paid["meta"]==[0,int(panic),sequence,stage,0,0,0,0],
         "Paid actual method invocation/retirement differs")
    known=[1,1,1,1,1]
    if begin_refused or panic and name!="settlement-clock1-eio":known=[0]*5
    elif name in ("live-clock3-einval","live-clock3-invalid","final-live-clock3-einval"):known=[1,1,1,0,0]
    elif name=="outer-clock3-einval":known=[0,1,0,1,0]
    expected=[0]*64;expected[0]=int.from_bytes(b"PCOWN001","little");expected[2]=int(begin_refused)
    available=name in ("normal-zero-target","begin-clock3-eio-fallback","live-clock3-eio-fallback")
    values=[None if times.get("outer") is None or times.get("begin") is None else times["outer"]-times["begin"],
            0,None if times.get("outer") is None or times.get("begin") is None else times["outer"]-times["begin"],
            None if times.get("finish") is None or times.get("begin") is None else times["finish"]-times["begin"],
            None if times.get("outer") is None or times.get("finish") is None else times["outer"]-times["finish"]]
    for flag,(index,value) in zip(known,zip((4,6,8,10,12),values),strict=True):
        expected[index]=flag;expected[index+1]=value if flag else 0
    expected[19:23]=[int(not available),worker,2,int(panic)]
    need(same(owner,expected),"Paid receipt known/Unknown CPU fields differ from actual clock intervals")
    flow=budget_flow(shape,profile)
    from hia.platform.paid_cpu.native_io import signed as signed_pair
    unavailable=begin_refused or name in ("work-clock1-eio","live-clock3-einval","live-clock3-invalid",
                                         "final-live-clock3-einval","outer-clock3-einval")
    need(epoch[0]==0x3130303055504350 and epoch[1]==int(unavailable)
         and signed_pair(epoch[2],epoch[3])==flow["credit"]
         and epoch[4]*1_000_000_000+epoch[5]==flow["updated"] and epoch[6:10]==[flow["in_flight"],0,0,1]
         and signed_pair(epoch[10],epoch[11])==2_000_000_000
         and epoch[12:19]==[flow["flow"][k] for k in ("credited_refill_ns","discarded_refill_ns",
             "booked_reservation_ns","live_debited_cpu_ns","settlement_residual_cpu_ns","settled_full_cpu_ns","settlement_discard_ns")]
         and epoch[19]==0,"Paid complete native budget/flow differs from actual wall/CPU clocks")

def original_shape(value,shape,profile,frame,*,private):
    from .rust_oracle import settlement, paid_observation_shape
    name=profile["name"];constructor=name=="constructor-clock1-eio";panic=profile["domain"]==4
    common={"kind","constructor_panicked","domain","code","worker_tid","joined","post_checks",
            "actual_original_finite_paid_work_checkpoints","production_fixed_parent_authority",
            "complete_Node_or_paid_checkpoint"}
    fields=common if constructor else common | {"product_hex","progress","work_code","main_tid",
        "worker_panicked","worker_host_calls","worker_checks","before_values","after_values","delta_values",
        "paid","paid_checkpoints","live","begin_error","paid_global"}
    need(type(value) is dict and set(value)==fields and value["kind"]=="paid-work-fault"
         and value["constructor_panicked"] is constructor and same(value["domain"],profile["domain"])
         and same(value["code"],profile["code"]) and value["actual_original_finite_paid_work_checkpoints"] is True
         and value["production_fixed_parent_authority"] is False and value["complete_Node_or_paid_checkpoint"] is False,
         "Original Paid fault observation schema/scope differs")
    if constructor:
        need(value["worker_tid"] is None and value["joined"] is False and same(value["post_checks"],0),
             "Original failed Paid constructor fabricated a worker")
        return
    h=frame["header"];owner=frame["paid"]["owner"]
    need(value["joined"] is True and same(value["main_tid"],shape["main"])
         and same(value["worker_tid"],shape["worker"]) and value["worker_panicked"] is panic
         and value["product_hex"] is None and value["progress"]==[] and same(value["work_code"],h["work_code"])
         and same(value["worker_host_calls"],h["worker_host_calls"])
         and same(value["worker_checks"],h["worker_host_calls"]) and same(value["post_checks"],h["post_checks"])
         and same(value["before_values"],[10,20,3,40,64,2])
         and same(value["after_values"],None if panic else [10,20,3,40,64,2])
         and same(value["delta_values"],None if panic else [0,0,0,0]),
         "Original Paid actual join/Host/progress/result differs")
    begin_refused=name in ("begin-clock3-einval","begin-clock3-persistent-eio","begin-clock3-invalid")
    need(same(value["begin_error"],None if name=="reserve-clock1-eio" else 1 if begin_refused else 0),
         "Original Paid begin result differs from its actual clock")
    paid_observation_shape(value)
    settlement(value,frame)
    times=shape["times"];global_=value["paid_global"]
    unavailable=begin_refused or name in ("work-clock1-eio","live-clock3-einval","live-clock3-invalid",
                                         "final-live-clock3-einval","outer-clock3-einval")
    need(global_["poisoned"] is bool(profile["poison"][0]) and global_["unavailable"] is unavailable
         and same(global_["in_flight"],profile["in_flight"]) and same(global_["termination_reserved_ns"],0)
         and same(global_["verified_completions"],0),"Original Paid global lifecycle differs")
    live=value["live"]
    if begin_refused or name=="reserve-clock1-eio":
        need(live is None,"Original refused begin fabricated a live account")
    else:
        recent=next((times.get(k) for k in ("drop","finish","checkpoint","begin") if times.get(k) is not None),None)
        live_unknown=name in ("live-clock3-einval","live-clock3-invalid","final-live-clock3-einval","settlement-clock1-eio")
        expected={"poisoned":bool(profile["poison"][1]),"unavailable":live_unknown,"refused":False,
                  "charged_ns":recent-times["begin"],"registered_threads":int(name=="live-clock1-eio"),
                  "termination_reserved":False}
        need(same(live,expected),"Original Paid live account differs from actual same-thread clocks/unwind")
    receipt=value["paid"]
    if panic or begin_refused:
        need(receipt is None,"Original Paid panic/refused begin invented a returned settlement")
    else:
        start=times.get("begin");outer=times.get("outer");finish=times.get("finish")
        measured=[None if outer is None else outer-start,0,None if outer is None else outer-start,
                  None if finish is None else finish-start,
                  None if outer is None or finish is None else outer-finish]
        expected={"schema":"service-owner-scoped-thread-cpu-settlement-v1",
                  "spawned_workers":0,"started_workers":0,"finished_workers":0,"known_workers":0,
                  "live_refused":False,"accounting_unavailable":bool(owner[19])}
        for key,index,amount in zip(("owner_cpu_ns","scoped_worker_cpu_ns","total_cpu_ns","live_paid_cpu_ns","residual_cpu_ns"),
                                    (4,6,8,10,12),measured,strict=True):
            expected[key]=amount if owner[index] else None
        need(same(receipt,expected),"Original Paid known/Unknown receipt differs from actual CPU samples")
    if private:
        budget=budget_flow(shape,profile)
        need(global_["credit_ns"]==str(budget["credit"]) and same(global_["flow"],budget["flow"]),
             "Original Paid complete refill/reserve/charge flow differs from actual clocks")
    else:
        flow=global_["flow"]
        charged=times["finish"]-times["begin"];total=times["outer"]-times["begin"];residual=times["outer"]-times["finish"]
        need(flow["initial_credit_ns"]=="2000000000" and flow["booked_reservation_ns"]==0
             and flow["live_debited_cpu_ns"]==charged and flow["settlement_residual_cpu_ns"]==residual
             and flow["settled_full_cpu_ns"]==total and flow["settlement_discard_ns"]==0
             and int(global_["credit_ns"])==2_000_000_000+flow["credited_refill_ns"]-total,
             "Normal-vDSO Paid CPU union/flow conservation differs")

def audit(directory,*,profile,native,private,executable,argv,environment,input_bytes=None,native_frame=None):
    admit_profile(profile)
    need(type(native) is bool and type(private) is bool and (not native or not private)
         and (native or private or profile["fault"] is None),"Exact Paid trace mode required")
    capture=Capture(directory)
    try:
        raw={name:capture.read(name,128<<20) for name in RAW_NAMES}
        report=decoded(raw["report.json"]);events=[decoded(line) for line in raw["events.jsonl"].splitlines()]
        fields={"schema","status","argv","disable_vdso","executable_before","environment","complete_write_capture",
                "clean_environment","native_roles_from_actual_gettid","expected_exit","expected_signal","exit_code","signal",
                "actual_clock_calls","roster","auxv","executable_after","complete_owned_process_reaped","actual_roles",
                "fault","injections","duration_seconds","events","stdout","stderr"}
        need(type(report) is dict and set(report)==fields and report["schema"]==TRACE_SCHEMA and report["status"]=="PASS"
             and same(report["argv"],argv) and same(report["environment"],environment)
             and same(report["executable_before"],executable) and report["executable_after"]=="MATCH"
             and report["complete_write_capture"] is True and report["clean_environment"] is True
             and report["native_roles_from_actual_gettid"] is native
             and report["complete_owned_process_reaped"] is True and report["disable_vdso"] is private
             and same(report["fault"],profile["fault"])
             and same(report["exit_code"],64+profile["domain"] if native else 0)
             and same(report["expected_exit"],report["exit_code"])
             and report["signal"] is report["expected_signal"] is None,
             "Paid complete trace report schema/invocation/lifetime/scope differs")
        duration=report["duration_seconds"]
        need(type(duration) in (int,float) and math.isfinite(duration) and 0<duration<=90,"Paid actual capture duration")
        need(all(same(report[key],raw_identity(raw[name])) for key,name in
                 (("events","events.jsonl"),("stdout","stdout.raw"),("stderr","stderr.raw"))),
             "Paid complete raw stream identity differs")
        if native:
            need(type(argv) is list and len(argv)==1 and re.fullmatch(r"/proc/self/fd/[0-9]+",argv[0])
                 and same(environment,{"PATH":""}),"Exact native Paid fd execution/environment required")
        else:
            need(type(argv) is list and len(argv)==5 and argv[1:]==["--exact",TEST,"--nocapture","--test-threads=1"]
                 and type(environment) is dict and set(environment)=={"PATH","TRNM_HIA_WORK_OWNER_CORPUS"}
                 and environment["PATH"]=="/usr/bin:/bin","Exact original Paid invocation/environment required")
        ledger=collect(events,raw["stdout.raw"],raw["stderr.raw"],native=native)
        need(same({str(k):v for k,v in ledger["roster"].items()},report["roster"])
             and same({str(k):v for k,v in ledger["roles"].items()},report["actual_roles"])
             and same(ledger["clocks"],report["actual_clock_calls"])
             and same(ledger["injections"],report["injections"])
             and same(ledger["exec"]["auxv"],report["auxv"]),"Paid trace summary disconnected from complete events")
        need(ledger["exec"]["actual_executable"]==("/memfd:hia-work-paid-clock (deleted)" if native else argv[0]),
             "Paid actual exec image path differs")
        aux=report["auxv"]
        if private:
            fields={"private_platform_fixture","normal_vdso_behavior_claimed","initial_stack_pointer","argc",
                    "environment_count","AT_SYSINFO_EHDR_before","AT_SYSINFO_EHDR_after","auxv_before_hex","auxv_after_hex","actual_vdso_mapping"}
            need(type(aux) is dict and set(aux)==fields and aux["private_platform_fixture"] is True
                 and aux["normal_vdso_behavior_claimed"] is False and uint(aux["initial_stack_pointer"])
                 and aux["initial_stack_pointer"]%8==0 and same(aux["argc"],len(argv))
                 and same(aux["environment_count"],len(environment)) and uint(aux["AT_SYSINFO_EHDR_before"])
                 and aux["AT_SYSINFO_EHDR_before"]>0 and same(aux["AT_SYSINFO_EHDR_after"],0),
                 "Paid private auxv fixture scope/initial stack differs")
            old=hex_bytes(aux["auxv_before_hex"]);new=hex_bytes(aux["auxv_after_hex"])
            need(len(old)==len(new) and len(old)%16==0 and old,"Paid complete auxv extent")
            before=list(struct.iter_unpack("<QQ",old));after=list(struct.iter_unpack("<QQ",new))
            need(before[-1][0]==after[-1][0]==0 and sum(k==33 for k,_ in before)==1
                 and next(v for k,v in before if k==33)==aux["AT_SYSINFO_EHDR_before"]
                 and after==[(k,0 if k==33 else v) for k,v in before],
                 "Paid auxv changed outside exactly one vDSO word")
            need(type(aux["actual_vdso_mapping"]) is str and aux["actual_vdso_mapping"].endswith("[vdso]")
                 and int(aux["actual_vdso_mapping"].split("-",1)[0],16)==aux["AT_SYSINFO_EHDR_before"],
                 "Paid actual vDSO mapping differs")
        else:need(same(aux,{"private_platform_fixture":False,"auxv_unchanged":True}),"Paid unmodified platform auxv differs")
        shape=clock_shape(ledger,profile,native=native,private=private)
        if native:
            from .native_io import decode
            request=bytes.fromhex(input_case()[0]["request_hex"])
            payload=struct.pack("<8Q",int.from_bytes(b"WOFIX001","little"),0,0,0,0,0,0,0)+request
            need(input_bytes==payload and raw["stderr.raw"]==b"",
                 "Paid native actual sealed input/read or stderr differs")
            native_input(ledger,payload)
            frame=decode(raw["stdout.raw"]);native_shape(frame,shape,profile)
            outputs=[r for r in ledger["entries"].values() if r["nr"]==1 and r["args"][0]==1]
            need(outputs and all(r["tid"]==shape["main"] for r in outputs),"Paid native output producer differs")
            first_output=min(r["sequence"] for r in outputs)
            value={"frame":frame}
        else:
            lines=[line.split(MARKER,1)[1] for line in raw["stdout.raw"].splitlines() if MARKER in line]
            need(len(lines)==1 and b"test result: ok. 1 passed; 0 failed;" in raw["stdout.raw"],
                 "Original Paid exact test/observation did not execute")
            observed=decoded(lines[0]);original_shape(observed,shape,profile,native_frame,private=private)
            outputs=[r for r in ledger["entries"].values() if r["nr"]==1 and r["args"][0]==1
                     and MARKER in hex_bytes(r.get("write_bytes_hex"))]
            need(outputs and all(r["tid"]==shape["main"] for r in outputs),"Original Paid observation producer differs")
            first_output=min(r["sequence"] for r in outputs);value={"observation":observed}
        join=joined_before_output(ledger,shape,first_output,native=native)
        capture.fence()
        return {"schema":"trnm.hia.work-owner-paid-clock-audit.v1","status":"PASS","profile":profile,
                "native":native,"private_no_vdso":private,"raw":{name:raw_identity(data) for name,data in raw.items()},
                "actual_main_tid":shape["main"],"actual_worker_tid":shape["worker"],
                "actual_clock_calls":len(ledger["clocks"]),"actual_injections":ledger["injections"],
                "all_owned_threads_retired":True,"complete_write_bytes_replayed":True,
                "actual_join_before_output":join,**SCOPES,**value}
    finally:capture.close()


def control_specs(native):
    baseline="normal-zero-target" if native else "private-raw-positive"
    rows=[("positive-complete-baseline",baseline,True)]
    rows += [("omitted-injection-"+p["name"],p["name"],False) for p in profiles()[1:]]
    rows += [(name,baseline,False) for name in (
        "wrong-schema","extra-authority","role-ordinal-float","disconnected-cpu-timespec",
        "coherent-cpu-timespec","role-index-bool","event-after-terminal","foreign-executed-image",
        "raw-output-truncated","constructor-clock-omitted",
        "join-address-other-word","join-wait-other-tid","join-word-not-cleared",
        "join-kernel-error","join-private-futex","join-before-word-other-tid",
        "terminal-exit-stop-status","terminal-worker-exit-failure","terminal-unbound-exit-code")]
    rows.append(("positive-restored-fallback","begin-clock3-eio-fallback",True))
    need(len(rows)==36,"Paid reader control source roster changed")
    return rows

def _capture(root):
    capture=Capture(root)
    try:
        raw={name:capture.read(name,128<<20) for name in RAW_NAMES};capture.fence();return raw
    finally:capture.close()

def _context(root,complete,label,native,native_report):
    row=next(row for row in complete["rows"] if row["name"]==label)
    directory=root/label/("ptrace" if native else "")
    raw=_capture(directory);trace=decoded(raw["report.json"])
    context={"profile":row["profile"],"native":native,"private":row["audit"]["private_no_vdso"],
             "executable":complete["image"] if native else complete["executable"],
             "argv":trace["argv"] if native else complete["argv"],
             "environment":{"PATH":""} if native else complete["environment"]}
    if native:
        path=root/label/"stdin.raw";before=identity(path);context["input_bytes"]=path.read_bytes()
        need(same(identity(path),before),"Paid input changed during capture")
    else:
        selected=next(r for r in native_report["rows"] if r["name"]==row["profile"]["name"])
        context["native_frame"]=selected["audit"]["frame"]
    return raw,context

def mutate(raw,name):
    report=decoded(raw["report.json"]);events=[decoded(line) for line in raw["events.jsonl"].splitlines()]
    stdout=raw["stdout.raw"];stderr=raw["stderr.raw"]
    if name.startswith("omitted-injection-"):
        chosen={item["entry"] for item in report["injections"]}
        for row in events:
            if row["kind"]=="syscall-entry" and row["sequence"] in chosen:row.pop("fault")
            if row["kind"]=="syscall-exit" and row["entry"] in chosen:row["kernel_result_before_injection"]=row["result"]
        for row in report["actual_clock_calls"]:
            if row["entry"] in chosen:row["injected"]=None
        report["injections"]=[]
    elif name=="wrong-schema":report["schema"]="trnm.hia.work-owner-paid-clock-trace.v0"
    elif name=="extra-authority":report["production_authority"]=True
    elif name=="role-ordinal-float":
        row=next(e for e in events if e["kind"]=="syscall-entry" and e.get("role")==2 and e["nr"]==228)
        row["role_clock_ordinal"]=float(row["role_clock_ordinal"])
    elif name in ("disconnected-cpu-timespec","coherent-cpu-timespec"):
        row=next(r for r in reversed(report["actual_clock_calls"]) if r["role"]==2 and r["clock_id"]==3 and r["result"]==0)
        timestamp=row["seconds"]*1_000_000_000+row["nanoseconds"]+1
        row["seconds"],row["nanoseconds"]=divmod(timestamp,1_000_000_000)
        row["timespec_hex"]=struct.pack("<qq",row["seconds"],row["nanoseconds"]).hex()
        if name=="coherent-cpu-timespec":
            next(e for e in events if e["sequence"]==row["exit"])["actual_timespec_hex"]=row["timespec_hex"]
    elif name=="role-index-bool":
        next(e for e in events if e["kind"]=="actual-role" and e["role"]==2)["index"]=False
    elif name=="event-after-terminal":
        tid=next(e["tid"] for e in events if e["kind"]=="actual-role" and e["role"]==2)
        events.append({"sequence":len(events)+1,"kind":"syscall-entry","tid":tid,"nr":186,"args":[0]*6})
    elif name=="foreign-executed-image":
        next(e for e in events if e["kind"]=="exec")["actual_executable"]="/foreign/unbound-image"
    elif name=="raw-output-truncated":stdout=stdout[:-1]
    elif name.startswith("terminal-"):
        worker=next(e["tid"] for e in events if e["kind"]=="actual-role" and e["role"]==2)
        own=next(e for e in events if e["kind"]=="syscall-entry" and e["tid"]==worker and e["nr"]==60)
        stopped=next(e for e in events if e["kind"]=="exit-stop" and e["tid"]==worker)
        terminal=next(e for e in events if e["kind"]=="terminal" and e["tid"]==worker)
        if name=="terminal-exit-stop-status":stopped["status"]=256
        elif name=="terminal-worker-exit-failure":
            own["args"][0]=1;stopped["status"]=256;terminal["exit_code"]=1
        elif name=="terminal-unbound-exit-code":
            root=events[0]["tid"]
            code=next(e["exit_code"] for e in events if e["kind"]=="terminal" and e["tid"]==root)
            terminal["exit_code"]=1 if code!=1 else 2
        else:raise ValueError("Unknown Paid terminal mutation")
        report["roster"][str(worker)]["terminal"]=terminal.copy()
    elif name.startswith("join-"):
        worker=next(e["tid"] for e in events if e["kind"]=="actual-role" and e["role"]==2)
        child=report["roster"][str(worker)];main=child["parent"];address=child["child_tid_address"]
        selected=next(e for e in reversed(events) if e["kind"]=="syscall-entry"
                      and e["tid"]==main and e["nr"]==202 and e["args"][0]==address)
        returned=next(e for e in events if e["kind"]=="syscall-exit" and e["entry"]==selected["sequence"])
        if name=="join-address-other-word":selected["args"][0]+=8
        elif name=="join-wait-other-tid":selected["args"][2]=worker+1
        elif name=="join-word-not-cleared":returned["futex_word_after"]=worker
        elif name=="join-kernel-error":returned["result"]=returned["kernel_result_before_injection"]=-4
        elif name=="join-private-futex":selected["args"][1]|=128
        elif name=="join-before-word-other-tid":selected["futex_word_before"]=worker+1
        else:raise ValueError("Unknown Paid join mutation")
    elif name=="constructor-clock-omitted":
        selected=next(r for r in report["actual_clock_calls"] if r["role"]==1 and r["role_clock_ordinal"]==2)
        report["actual_clock_calls"].remove(selected)
    else:raise ValueError("Unknown finite Paid reader mutation")
    raw_events=b"".join((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode() for row in events)
    result={"events.jsonl":raw_events,"stdout.raw":stdout,"stderr.raw":stderr}
    for key,file in (("events","events.jsonl"),("stdout","stdout.raw"),("stderr","stderr.raw")):
        report[key]=raw_identity(result[file])
    result["report.json"]=(json.dumps(report,sort_keys=True,separators=(",",":"))+"\n").encode()
    return {name:result[name] for name in RAW_NAMES}

def reader_controls(root,complete,*,native,native_report=None):
    root=Path(root);out=root/"reader-controls";need(not out.exists(),"Fresh Paid reader controls required");out.mkdir(mode=0o700)
    before=source_manifest();need(same(before,complete["source_inputs"]),"Paid reader controls source differs")
    templates={label:_context(root,complete,label,native,native_report) for _,label,_ in control_specs(native)}
    report={"schema":"trnm.hia.work-owner-paid-reader-controls.v1","status":"FAIL","native":native,
            "source_inputs":before,"source_after":"NOT_RUN","baseline_after":"NOT_RUN","rows":[],
            "actual_native_or_Rust_processes_executed":0,"current_source_runtime_qualification_claimed":False,
            "baseline":{label:{name:raw_identity(data) for name,data in raw.items()} for label,(raw,_) in templates.items()}}
    try:
        for name,label,wanted in control_specs(native):
            original,context=templates[label];raw=original if wanted else mutate(original,name)
            directory=out/name;directory.mkdir(mode=0o700)
            for file,data in raw.items():(directory/file).write_bytes(data)
            accepted=False;failure=None
            try:audit(directory,**context);accepted=True
            except (ValueError,OSError,KeyError,IndexError,StopIteration,TypeError) as error:failure=repr(error)
            row={"name":name,"baseline":label,"status":"PASS" if accepted is wanted else "FAIL",
                 "expected_acceptance":wanted,"actual_acceptance":accepted,"failure":failure,
                 "complete_raw":{file:raw_identity(data) for file,data in raw.items()}}
            report["rows"].append(row);write_json(out/(name+".json"),row)
            print(json.dumps({"paid_raw_reader_control":name,"native":native,"status":row["status"],"failure":failure}),flush=True)
            need(row["status"]=="PASS","Paid raw reader control accepted/refused the wrong complete evidence")
        report.update(status="PASS",count=36,positive=2,negative=34)
    except BaseException as error:report.update(failure=repr(error),traceback=traceback.format_exc())
    finally:
        try:
            need(same(source_manifest(),before),"Paid reader-control source changed")
            for label,(raw,_) in templates.items():
                now=_capture(root/label/("ptrace" if native else ""))
                need(now==raw,"Paid original baseline changed during controls")
            report.update(source_after="MATCH",baseline_after="MATCH")
        except BaseException as error:report.update(status="FAIL",final_fence_failure=repr(error))
        write_json(out/"report.json",report)
    need(report["status"]=="PASS","Paid complete raw reader controls failed")
    return report

def read_controls(root,complete,*,native,native_report=None):
    root=Path(root);directory=root/"reader-controls";report=read_json(directory/"report.json")
    fields={"schema","status","native","source_inputs","source_after","baseline_after","rows",
            "actual_native_or_Rust_processes_executed","current_source_runtime_qualification_claimed",
            "baseline","count","positive","negative"}
    need(type(report) is dict and set(report)==fields and same(report,complete["reader_controls"])
         and report.get("schema")=="trnm.hia.work-owner-paid-reader-controls.v1"
         and report.get("status")=="PASS" and report.get("native") is native
         and report.get("failure") is None and report.get("final_fence_failure") is None
         and report.get("source_after")==report.get("baseline_after")=="MATCH"
         and same(report.get("source_inputs"),complete["source_inputs"])
         and same([report.get(k) for k in ("count","positive","negative","actual_native_or_Rust_processes_executed")],[36,2,34,0])
         and report.get("current_source_runtime_qualification_claimed") is False,"Paid raw-control source/scope/counts differ")
    specs=control_specs(native);rows=report.get("rows")
    need(type(rows) is list and [row.get("name") for row in rows]==[r[0] for r in specs],"Paid exact raw-control roster differs")
    templates={label:_context(root,complete,label,native,native_report) for _,label,_ in specs}
    need(same(report["baseline"],{label:{name:raw_identity(data) for name,data in raw.items()}
                                 for label,(raw,_) in templates.items()}),"Paid raw-control baseline differs")
    expected_files={"report.json"}
    for row,(name,label,wanted) in zip(rows,specs,strict=True):
        expected_files.update((name,name+".json"))
        need(type(row) is dict and set(row)=={"name","baseline","status","expected_acceptance",
             "actual_acceptance","failure","complete_raw"}
             and same(read_json(directory/(name+".json")),row) and row.get("baseline")==label
             and row.get("status")=="PASS" and row.get("expected_acceptance") is wanted
             and row.get("actual_acceptance") is wanted
             and (row.get("failure") is None if wanted else type(row.get("failure")) is str),
             "Paid actual reader-control result type differs")
        raw,context=templates[label];expected=raw if wanted else mutate(raw,name)
        retained=_capture(directory/name)
        need(retained==expected and same(row.get("complete_raw"),{file:raw_identity(data) for file,data in retained.items()}),
             "Paid retained complete mutation bytes differ from the declared operation")
        accepted=False;failure=None
        try:audit(directory/name,**context);accepted=True
        except (ValueError,OSError,KeyError,IndexError,StopIteration,TypeError) as error:failure=repr(error)
        need(accepted is wanted and failure==row["failure"],
             "Paid retained complete mutation changed its reader result/root cause")
    need(set(os.listdir(directory))==expected_files,"Paid reader-control extra or missing evidence")
    return {"count":36,"positive":2,"negative":34,"report":identity(directory/"report.json")}


def read_native(root,report,*,image,source_inputs):
    root=Path(root);fields={"schema","status","source_inputs","source_after","image","request","rows",
        "fault_count","positive_count","actual_original_Rust","reader_controls",*SCOPES}
    need(type(report) is dict and set(report)==fields and report["schema"]==NATIVE_SCHEMA
         and report["status"]=="PASS" and report["source_after"]=="MATCH"
         and same(report["source_inputs"],source_inputs) and same(report["image"],image)
         and same(report["request"],raw_identity(bytes.fromhex(input_case()[0]["request_hex"])))
         and same([report["fault_count"],report["positive_count"]],[15,1])
         and report["actual_original_Rust"] is False and all(report[k] is value for k,value in SCOPES.items()),
         "Complete native Paid qualification source/count/scope differs")
    need(same(read_json(root/"report.json"),report) and type(report["rows"]) is list
         and [r.get("name") for r in report["rows"]]==[p["name"] for p in profiles()],
         "Complete native Paid report/roster differs")
    for row,profile in zip(report["rows"],profiles(),strict=True):
        raw,context=_context(root,report,row["name"],True,None)
        need(same(row["profile"],profile),"Native Paid profile changed")
        actual=audit(root/row["name"]/"ptrace",**context)
        need(same(read_json(root/row["name"]/"ptrace/audit.json"),actual)
             and same(row,{"name":profile["name"],"profile":profile,"status":"PASS","audit":actual}),
             "Complete native Paid row differs from actual raw replay")
    controls=read_controls(root,report,native=True)
    return {"native_paid_clock_processes":16,"native_paid_clock_fault_processes":15,
            "native_paid_clock_positive_processes":1,"native_paid_clock_raw_reader_controls":36,
            "native_paid_clock_raw_positive_controls":2,"native_paid_clock_raw_negative_controls":34,
            "native_paid_clock_report":identity(root/"report.json"),
            "native_paid_clock_reader_report":controls["report"]}

def read_original(root,report,*,native,executable,source_inputs,original_sources,observed):
    root=Path(root);observed=Path(observed)
    fields={"schema","status","source_inputs","source_after","original_sources","binary_after",
            "executable","argv","environment","input","rows","fault_count","positive_count","reader_controls",*SCOPES}
    expected_argv=[str(observed.parent/"original-test-binary"),"--exact",TEST,"--nocapture","--test-threads=1"]
    expected_env={"PATH":"/usr/bin:/bin","TRNM_HIA_WORK_OWNER_CORPUS":str(observed/"case.jsonl")}
    input_bytes=(json.dumps(input_case()[1],sort_keys=True,separators=(",",":"))+"\n").encode()
    need(type(report) is dict and set(report)==fields and report["schema"]==ORIGINAL_SCHEMA
         and report["status"]=="PASS" and report["source_after"]==report["binary_after"]=="MATCH"
         and same(report["source_inputs"],source_inputs) and same(report["original_sources"],original_sources)
         and same(report["executable"],executable) and same(report["argv"],expected_argv)
         and same(report["environment"],expected_env) and same(report["input"],raw_identity(input_bytes))
         and (root/"case.jsonl").read_bytes()==input_bytes
         and same([report["fault_count"],report["positive_count"]],[15,2])
         and all(report[k] is value for k,value in SCOPES.items()),
         "Complete original Paid qualification source/count/invocation/scope differs")
    need(same(read_json(root/"report.json"),report),"Original Paid report disconnected")
    work=[("normal-vdso-positive",False,profiles()[0]),("private-raw-positive",True,profiles()[0])]
    work += [(p["name"],True,p) for p in profiles()[1:]]
    need(type(report["rows"]) is list and [r.get("name") for r in report["rows"]]==[x[0] for x in work],
         "Complete original Paid process roster differs")
    for row,(name,private,profile) in zip(report["rows"],work,strict=True):
        _,context=_context(root,report,name,False,native)
        need(context["private"] is private and same(context["profile"],profile),"Original Paid controlled profile differs")
        actual=audit(root/name,**context)
        need(same(read_json(root/name/"audit.json"),actual)
             and same(row,{"name":name,"profile":profile,"status":"PASS","audit":actual}),
             "Complete original Paid row differs from actual raw replay")
    controls=read_controls(root,report,native=False,native_report=native)
    return {"original_paid_CLOCK_fault_comparison":"PASS","original_paid_clock_processes":17,
            "original_paid_clock_fault_processes":15,"original_paid_clock_positive_processes":2,
            "original_paid_clock_raw_reader_controls":36,"original_paid_clock_raw_positive_controls":2,
            "original_paid_clock_raw_negative_controls":34,
            "original_paid_clock_report":identity(root/"report.json"),
            "original_paid_clock_reader_report":controls["report"]}
