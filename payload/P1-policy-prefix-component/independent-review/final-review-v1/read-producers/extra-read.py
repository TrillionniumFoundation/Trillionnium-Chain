import os,stat,hashlib,json,re
from pathlib import Path
D=Path('/private/tmp/chain-public-policy-prefix-independent-review-20261114-v1')
def read(p,sha):
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd); assert stat.S_ISREG(a.st_mode) and a.st_nlink==1
        out=[]
        while True:
            b=os.read(fd,1024*1024)
            if not b:break
            out.append(b)
        b=b''.join(out); z=os.fstat(fd); q=os.lstat(p)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        assert key(a)==key(z)==key(q)
        assert hashlib.sha256(b).hexdigest()==sha
        return b
    finally:os.close(fd)
oldb=read(D/'M8--trillionnium--crates--trnm-pon-node--src--ingress--public_v3.rs.original','1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70')
newb=read(D/'candidate-public_v3.rs.reconstructed.original','0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a')
old,new=oldb.decode(),newb.decode()
lines=old.splitlines();newlines=new.splitlines()
t=re.search(r'#\[cfg\(test\)\]\s*\nmod tests \{',old);assert t
test_line=old[:t.start()].count('\n')+1
calls=[]
for i,s in enumerate(lines[:test_line-1]):
    if '.id()' in s:
        start=max(0,i-6);end=min(len(lines),i+7)
        calls.append({'matched_line':i+1,'start':start+1,'end':end,'text':'\n'.join(f'{n+1}: {lines[n]}' for n in range(start,end))})
def block(text,name):
    m=re.search(r'    #\[test\]\s*\n    fn '+re.escape(name)+r'\(',text)
    assert m
    q=text.find('    #[test]',m.end())
    return text[m.start():q if q>=0 else len(text)]
gold='paid_envelope_resource_profile_has_fresh_exact_signed_commitment'
assert block(old,gold)==block(new,gold)
oldtests=re.findall(r'#\[test\]\s*(?:#\[[^\n]*\]\s*)*fn\s+([a-zA-Z0-9_]+)',old)
newtests=re.findall(r'#\[test\]\s*(?:#\[[^\n]*\]\s*)*fn\s+([a-zA-Z0-9_]+)',new)
added=[s for s in newtests if s not in oldtests]
assert added==['cached_policy_id_matches_original_hash_for_public_fields','cached_policy_id_retains_all_six_framed_suffix_parts','cached_policy_id_clones_are_independent_across_callers']
assert all(x in newtests for x in oldtests)
def constructors(s):
    a=s.index('impl PublicPolicy {');b=s.index('    pub fn id(self)',a)
    return s[a:b]
assert constructors(old)==constructors(new)
r={'schema':'trnm-policy-prefix-readonly-callsite-and-test-proof-v1','source_checkpoint':'ed0d35487f2a67239e4d646fd41c2c7acb5cc740','source_original_sha256':hashlib.sha256(oldb).hexdigest(),'candidate_sha256':hashlib.sha256(newb).hexdigest(),'production_test_module_starts_line':test_line,'production_dot_id_contexts':calls,'added_test_names':added,'existing_test_names_preserved':True,'existing_test_name_count':len(oldtests),'new_test_name_count':len(newtests),'test_roster_method':'Textual Rust #[test] declaration extraction, not rustc AST execution','constructor_source_exact_equal':True,'original_golden_control_exact_source_equal':True,'original_golden_control_sha256':hashlib.sha256(block(old,gold).encode()).hexdigest(),'test_or_source_helpers_run':False}
p=D/'production-callsite-and-test-proof.json'
b=(json.dumps(r,indent=2,sort_keys=True)+'\n').encode()
with open(p,'xb') as f:f.write(b)
print(json.dumps({'file':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'production_test_module_starts_line':test_line,'production_dot_id_contexts':calls,'policy_declaration_context':'\n'.join(f'{n+1}: {lines[n]}' for n in range(415,451)),'existing_test_name_count':len(oldtests),'new_test_name_count':len(newtests),'original_golden_unchanged':True},indent=2))
