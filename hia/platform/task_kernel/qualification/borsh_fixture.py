"""Qualification-only typed fixtures and field spans, never product execution."""
from pathlib import Path
import json
import random
import struct

class Fixtures:
    def __init__(self,seed):
        self.schema={int(k):v for k,v in json.loads(Path(__file__).with_name("type_layout.json").read_text()).items()}
        self.random=random.Random(seed)

    def value(self,kind,mode=0):
        row=self.schema[kind];tag=row["kind"];count=row["count"]
        if tag==0:return b""
        if tag==1:return bytes(count) if mode==0 else (b"\xff"*count if mode==1 else bytes(self.random.randrange(256) for _ in range(count)))
        if tag==2:return bytes([mode%2])
        if tag==3:
            raw=[b"",b"\x00\x7f","正文😀".encode()][mode%3];return struct.pack("<I",len(raw))+raw
        if tag==4:return struct.pack("<I",mode%3)+b"".join(self.value(count,(mode+i)%3) for i in range(mode%3))
        if tag==5:return b"\x00" if mode%2==0 else b"\x01"+self.value(count,mode)
        if tag==6:return b"".join(self.value(k,mode) for k in row["fields"])
        if tag==7:return bytes([mode%count])+self.value(row["fields"][mode%count],mode)
        raise AssertionError(row)

    def end(self,kind,raw,p):
        row=self.schema[kind];tag=row["kind"];count=row["count"]
        if tag==0:return p
        if tag==1:return p+count
        if tag==2:return p+1
        if tag==3:return p+4+struct.unpack_from("<I",raw,p)[0]
        if tag==4:
            n=struct.unpack_from("<I",raw,p)[0];p+=4
            for _ in range(n):p=self.end(count,raw,p)
            return p
        if tag==5:return p+1 if raw[p]==0 else self.end(count,raw,p+1)
        if tag==6:
            for field in row["fields"]:p=self.end(field,raw,p)
            return p
        if tag==7:return self.end(row["fields"][raw[p]],raw,p+1)
        raise AssertionError(row)

    def fields(self,kind,raw,p=0):
        result=[]
        for field in self.schema[kind]["fields"]:
            q=self.end(field,raw,p);result.append((p,q));p=q
        return result

    @staticmethod
    def replace(raw,span,value):return raw[:span[0]]+value+raw[span[1]:]

    def replace_field(self,kind,raw,index,value,p=0):
        return self.replace(raw,self.fields(kind,raw,p)[index],value)
