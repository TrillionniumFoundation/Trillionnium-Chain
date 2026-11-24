"""Test-only exact derivation of the TCV1 validator's non-publishing CFG."""
import hashlib
from pathlib import Path
import re

PRIMARY = Path(__file__).resolve().parents[1]/"src/data_availability/cell_complete_version.hepta"
SOURCE_SHA256 = "5b723faa5ad09f288981bbb5330ec7a27d65f2221b3306d321ba359245f498d6"
IDENTITY = "tcv_validate_for_commitment"


def derive(original: bytes) -> str:
    if hashlib.sha256(original).hexdigest() != SOURCE_SHA256:
        raise ValueError("published canonical TCV1 validator changed")
    start = original.index(b"fn f0(")
    stop = original.index(b"\nend\n",start)
    body = original[start:stop].decode("ascii")
    before,final = body.split("\nblock publish_check(",1)
    publication,failures = final.split("\nblock inner(",1)
    assert "\nblock publish(" in publication and publication.count("\nblock ")==1
    assert before.count("publish_check(")==1
    before,n = re.subn(r"publish_check\(b21_o,b21_w,b21_cnt\)","validated(b21_cnt)",before)
    assert n==1
    before,n = re.subn(r"\bb\d+_o(?::mutbuf)?[,]","",before)
    assert n==44
    assert not re.search(r"\bb\d+_o\b",before)
    assert "\n  ret(" not in before and before.startswith("fn f0(")
    before=before.replace("fn f0(",f"fn {IDENTITY}(",1).replace(" -> (u32) "," -> (u32,u64) ",1)
    failures="block inner("+failures
    failures,n = re.subn(r"(?m)^(  ret\((\w+)\))$",
                       r'  fail_\2_count:u64 = const() {"value":0}'+"\n"+r"  ret(\2,fail_\2_count)",
                       failures)
    assert n==11
    ok = ('block validated(kept_count:u64)\n'
          '  accepted_status:u32 = const() {"value":0}\n'
          '  ret(accepted_status,kept_count)')
    return "\n".join([before,ok,failures,"end",""])
