"""Decode exact native bytes; no queue, fairness or reservation model."""
from __future__ import annotations
import struct
from .contract import need

def decode(raw):
    need(len(raw)>=256 and raw[:8]==b"MTOUT001","Malformed native reply")
    words=struct.unpack_from("<32Q",raw);op=words[1]
    need(op<=23 and words[2]<=3 and words[3]<=21 and words[4]<=1,"Malformed reply fields")
    need(words[6]+words[7]==words[8] and words[29]<=1 and words[30]<=1,"Malformed counts")
    need(words[31]==0,"Nonzero reserved reply word")
    need(words[15]>=256+words[11] and words[15]+16*words[14]==len(raw),"Reply extent mismatch")
    need(not any(raw[256+words[11]:words[15]]),"Stale or uninitialized reply gap")
    result={"op":op,"outcome":words[2],"reason":words[3],"present":words[4],
        "handle":words[5],"counts":list(words[6:9]),"streak":words[9],"max_body_bytes":words[10],
        "fresh":[words[29],words[30]],
        "events":[list(struct.unpack_from("<2Q",raw,words[15]+16*i)) for i in range(words[14])]}
    need(all(1<=kind<=16 for kind,value in result["events"]),"Unknown callback observation")
    metadata=op in (5,6,10,11,18) and words[4]
    if metadata:
        result["metadata"]={"digest":raw[128:160].hex(),"signer":raw[160:192].hex(),
            "nonce":words[24],"fee_limit":str(words[25]+(words[26]<<64)),
            "max_gas":words[27],"max_bytes":words[28],"body":raw[256:256+words[11]].hex()}
        need(words[12]<=4 and words[13]==0,"Malformed metadata side fields")
    else:
        need(words[11]==0,"Unexpected body bytes")
        if op in (7,8):
            need(not any(raw[152:232]),"Nonzero reserved headroom bytes")
        else:need(not any(raw[128:232]),"Nonzero reserved metadata bytes")
    if op==12 and words[4]:result["state"]=words[12]
    if op==13:result["binding"]=words[13] if words[4] else None
    if op in (7,8):result["headroom"]=list(words[16:19])
    return result

def parse(raw):
    result=[];cursor=0
    while cursor<len(raw):
        need(len(raw)-cursor>=8,"Truncated native reply prefix")
        size=struct.unpack_from("<Q",raw,cursor)[0];cursor+=8
        need(256<=size<=len(raw)-cursor,"Truncated native reply")
        result.append(decode(raw[cursor:cursor+size]));cursor+=size
    need(cursor==len(raw),"Trailing native bytes")
    return result

def commands_wire(history):
    payload=[]
    for row in history["commands"]:
        raw=bytes.fromhex(row["input"]);payload.extend((struct.pack("<Q",len(raw)),raw))
    return b"".join(payload)

def original_corpus(histories):
    chunks=[struct.pack("<Q",len(histories))]
    for history in histories:
        name=history["name"].encode("ascii")
        chunks.extend((struct.pack("<Q",len(name)),name,struct.pack("<Q",len(history["commands"])),
                       commands_wire(history)))
    return b"".join(chunks)
