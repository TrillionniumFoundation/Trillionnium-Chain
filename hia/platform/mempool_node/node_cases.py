"""Node-owned disk source histories; no State, root, serial, or Config input."""
import json,struct
from hia.platform.execution_application.cases import wire,public
def histories():
 out=[]
 for index,timestamp in enumerate((None,1,1800000000,9223372036854775807)):
  context_timestamp=None if timestamp is None else min(timestamp+10,9223372036854775807)
  actions=[]
  actions.append({"op":"new","timestamp":context_timestamp,"miner_hex":(bytes([index+1])*32).hex()})
  actions += [{"op":"execute","transactions":tx} for tx in [
   [],[],["short"],["oversize"],["network"],["signature"],["expired"],["unknown-tag"],
   ["nonce-zero"],["fee-zero"],["unfunded"],["unfunded","signature"],["short","network"],
   ["short"]*257,["valid1"],["valid1"],["valid1","network"],["valid1","valid2"],
   [],["valid1","valid2","valid3"]]]
  actions += [{"op":"drop"},{"op":"new","timestamp":context_timestamp,"miner_hex":(bytes([index+5])*32).hex()},
              {"op":"execute","transactions":["valid1"]}]
  out.append({"schema":"trnm.node-checked-prefix-source-history.v1","name":("none" if timestamp is None else str(timestamp)),
              "timestamp":timestamp,"workers":8 if index==3 else 1,"actions":actions})
 return out
def canonical_bytes():return b"".join(json.dumps(r,sort_keys=True,separators=(",",":")).encode()+b"\n" for r in histories())
def transaction(kind,network):
 if kind=="short":return b"PN"
 if kind=="oversize":return b"x"*2049
 kwargs={"network":network}
 nonce={"valid1":1,"valid2":2,"valid3":3}.get(kind,1)
 if kind=="network":kwargs["network"]=bytes([network[0]^1])+network[1:]
 if kind=="expired":kwargs["expiry"]=0
 if kind=="nonce-zero":nonce=0
 if kind=="fee-zero":kwargs["fee"]=0
 if kind=="unfunded":kwargs["index"]=99
 raw=wire(1,public(1)+struct.pack("<Q",7),nonce=nonce,**kwargs)
 if kind=="signature":raw=raw[:-1]+bytes([raw[-1]^1])
 if kind=="unknown-tag":raw=raw[:92]+bytes([255])+raw[93:]
 return raw
