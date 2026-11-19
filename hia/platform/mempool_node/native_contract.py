"""Replay fixed qualification predicates directly from the bound suite sources."""
from pathlib import Path
import ast,struct
from . import safe
from .build import ROOT
UNKNOWN=object()

def fixed_validations(group,repository=ROOT):
 safe.need(group in ("smoke","boundaries","capacity","cross"),"Fixed native validation suite")
 raw=safe.read(repository,"hia/platform/mempool_node/suite_"+group+".py")
 tree=ast.parse(raw);mains=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main"]
 safe.need(len(mains)==1,"One actual suite entry")
 main=mains[0];rows={};seen=set()
 def is_validation(n):
  return isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id=="validate") or (isinstance(n.func,ast.Attribute) and n.func.attr=="validate"))
 def evaluate(n,env):
  if isinstance(n,ast.Constant):return n.value
  if isinstance(n,ast.Name):return env.get(n.id,UNKNOWN)
  if isinstance(n,(ast.List,ast.Tuple)):
   value=[evaluate(x,env) for x in n.elts];return tuple(value) if isinstance(n,ast.Tuple) else value
  if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add):
   left,right=evaluate(n.left,env),evaluate(n.right,env)
   if type(left) is type(right) and type(left) in (str,int,bytes,list,tuple):return left+right
  if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="str" and len(n.args)==1 and not n.keywords:
   value=evaluate(n.args[0],env)
   if type(value) in (str,int):return str(value)
  return UNKNOWN
 def bind(target,value,env):
  if isinstance(target,ast.Name):env[target.id]=value
  elif isinstance(target,(ast.Tuple,ast.List)):
   safe.need(type(value) in (list,tuple) and len(value)==len(target.elts),"Static control loop extent")
   for k,v in zip(target.elts,value,strict=True):bind(k,v,env)
 def capture(call,env):
  safe.need(len(call.args)>=3,"Actual validate call signature")
  name=evaluate(call.args[1],env);safe.need(type(name) is str and name not in rows,"Unique statically bound control")
  spec={"outcome":1,"error":0,"calls":None,"reused":None,"signatures":None}
  for k in call.keywords:
   if k.arg in ("expected","error","calls","reused","signatures"):
    value=evaluate(k.value,env);safe.need(type(value) is int or value is None,"Static expected control value")
    spec["outcome" if k.arg=="expected" else k.arg]=value
  safe.need(type(spec["outcome"]) is int and spec["outcome"] in (1,2,3,4) and type(spec["error"]) is int and spec["error"]>=0,"Actual outcome domain")
  rows[name]=spec;seen.add(call.lineno)
 def walk(block,env):
  for stmt in block:
   value=stmt.value if isinstance(stmt,(ast.Assign,ast.AnnAssign,ast.Expr)) else None
   if is_validation(value):capture(value,env)
   if isinstance(stmt,ast.Assign):
    value=evaluate(stmt.value,env)
    for target in stmt.targets:
     if isinstance(target,ast.Name):bind(target,value,env)
   elif isinstance(stmt,ast.For):
    values=evaluate(stmt.iter,env)
    if type(values) in (list,tuple):
     for value in values:
      child=dict(env);bind(stmt.target,value,child);walk(stmt.body,child)
    else:
     safe.need(not any(is_validation(x) for n in stmt.body for x in ast.walk(n)),"Unbound validation loop")
    walk(stmt.orelse,dict(env))
   elif isinstance(stmt,ast.Try):
    walk(stmt.body,dict(env))
    for handler in stmt.handlers:walk(handler.body,dict(env))
    walk(stmt.orelse,dict(env));walk(stmt.finalbody,dict(env))
   elif isinstance(stmt,ast.If):
    value=evaluate(stmt.test,env)
    if value is True:walk(stmt.body,dict(env))
    elif value is False:walk(stmt.orelse,dict(env))
    else:walk(stmt.body,dict(env));walk(stmt.orelse,dict(env))
   elif isinstance(stmt,(ast.With,ast.AsyncWith)):walk(stmt.body,dict(env))
 walk(main.body,{})
 required={n.lineno for n in ast.walk(main) if is_validation(n)}
 safe.need(seen==required and rows,"All validate call sites were resolved")
 expected={"smoke":13,"boundaries":41,"capacity":4,"cross":5}
 safe.need(len(rows)==expected[group],"Whole fixed validation predicate roster")
 return rows

def validation(control,spec):
 from .suite_smoke import pool_result
 safe.need(type(control) is dict and type(control.get("raw_hex")) is str,"Whole actual validation object")
 raw=bytes.fromhex(control["raw_hex"])
 value=pool_result(raw,2,spec["outcome"],spec["error"])
 safe.need(set(control)==set(value)|{"name","input_hex","progress","elapsed_ns"},"Exact validation record fields")
 for key,item in value.items():safe.need(safe.same(control[key],item),"Validation raw/result differs")
 safe.need(type(control["elapsed_ns"]) is int and 0<control["elapsed_ns"]<=243_000_000_000,"Actual validation elapsed observation")
 h=value["mempool"]["header"]
 for key,index in (("calls",5),("reused",7),("signatures",6)):
  if spec[key] is not None:safe.need(type(spec[key]) is int and h[index]==spec[key],"Fixed "+key+" predicate")
 name=control["name"]
 if name=="actual-funds-error-after-ready":safe.need(h[4]==1 and "prefix" in value,"Ready preceded actual funds refusal")
 if name=="borrowed-ready-does-not-reorder-m06":
  safe.need([int.from_bytes(bytes.fromhex(r["metadata_hex"])[32:40],"little") for r in value["mempool"]["ready"]]==[1,0],"Actual reserved-lane Ready order")
 if name=="full-original-256-record-capacity":
  safe.need(h[4]==256 and len(value["mempool"]["ready"])==256 and value["prefix"]["header"][8]==256,"Whole original 256 Ready/Prefix")
 return value

def nonvalidation(group,control):
 name=control["name"]
 safe.need(control.get("status")=="PASS","Nonvalidation result failed")
 if name=="real-disk-lease-open" or (name.startswith("policy-") and not name.endswith("-exact-base-disk-close")):
  required={"name","status","result"};key="result"
 elif name.endswith("-held-open"):
  required={"name","status","timestamp","workers","pool_open","context_hex"};key="pool_open"
 elif name=="full-capacity-owner-release":
  required={"name","status","process","progress","measured_child_user_seconds","measured_child_system_seconds","maxrss_kib","physical_trace"};key=None
 elif name=="drop-reopen-close-and-no-disk-change" or name.endswith("-exact-base-disk-close"):
  required={"name","status","process","progress"};key=None
 else:raise ValueError("Unknown fixed nonvalidation control")
 safe.need(set(control)==required,"Exact nonvalidation record fields")
 if key:
  from .suite_smoke import pool_result
  error=0
  if name.startswith("policy-"):
   error={"records-zero":31,"records-high":31,"bytes-zero":32,"bytes-high":32,"group-zero":33,"group-high":33,
    "reserve-full":34,"removals-zero":35,"removals-high":35,"miner-zero":36}[name[7:]]
  value=pool_result(bytes.fromhex(control[key]["raw_hex"]),1,2 if error else 1,error)
  safe.need(safe.same(value,control[key]) and value["header"][6]==int(error==0),"Actual policy/open predicate")
 if name=="full-capacity-owner-release":
  safe.need(control["physical_trace"]=="NOT_RUN_IN_THIS_CAPACITY_PROCESS","Capacity trace scope")
  for k in ("measured_child_user_seconds","measured_child_system_seconds"):
   safe.need(type(control[k]) in (int,float) and control[k]>=0,"Actual measured CPU observation")
  safe.need(type(control["maxrss_kib"]) is int and control["maxrss_kib"]>0,"Actual measured memory observation")
