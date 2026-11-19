"""Reexecute the pinned native compiler on a captured, source-verified closure.

This permits a second Linux host to replay the actual native build without
installing the hosted Hepta authoring package. It neither synthesizes machine
instructions nor substitutes an implementation. Exact source bytes must match
an earlier complete Core-admitted build, and fresh compiler/emitter processes
must reproduce its actual three binary outputs.
"""
from __future__ import annotations
import json,re,struct
from pathlib import Path
from .build import ROOT,HERE,identity,need,capture
from hia.platform.build import run_native,require_success,inspect_executable

class ReplayBuild:
    def __init__(self,output:Path,previous:Path):
        self.output=output.absolute();need(not self.output.exists(),'Fresh native replay output required')
        self.output.mkdir(parents=True,mode=0o700)
        self.previous=previous.resolve(strict=True)
        self.proof=json.loads(capture(self.previous/'build.json'))
        need(self.proof.get('schema')=='trnm.hia.peer-lease-store-build.v1' and self.proof.get('status')=='PASS'
             and self.proof.get('source_inputs_stable') is True and self.proof.get('runtime_host_proxy') is False,
             'A complete actual source-bound native build is mandatory')
        self.manifest=self.proof['source_inputs']
        self.inputs=self.current_inputs()
        for name,raw in self.inputs.items():
            saved=capture(self.previous/'source-snapshot'/name)
            need(saved==raw,'Earlier complete Core-admitted source differs: '+name)
            dest=output/'source-snapshot'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
        self.policy=self.composed()
        need(self.policy==capture(self.previous/'policy-composed.hepta'),'Captured compilation is not exact declared HIA functions')
        self.emitter=self.inputs['hia/platform/peer_lease_store/linux_emitter.hepta']
        binding=json.loads(self.inputs['hia/qualification/compiler-binding.json'])
        lock=json.loads(self.inputs['hia/toolchain.lock.json'])
        need(binding['toolchain_revision']==lock['revision'] and lock['target']=='x86_64-linux-gnu','Compiler source revision/target binding')
        for key,hashkey in (('outer_report','outer_sha256'),('nested_report','compressed_sha256')):
            raw=self.inputs['hia/qualification/'+binding[key]]
            need(identity(raw)['sha256']==binding[hashkey],'Complete prior compiler qualification bytes differ')
        need(json.loads(self.inputs['hia/qualification/'+binding['outer_report']])['status']=='COLD_SELFHOST_REPLAY_PASS','Original native compiler qualification did not pass')
        self.compiler=capture(self.previous/'native-compiler.elf')
        need(identity(self.compiler)==self.proof['compiler'] and identity(self.compiler)['sha256']==binding['compiler_sha256'],
             'Actual native compiler binary is not the exact qualified pin')
        for name,field in (('policy.flat','policy'),('emitter.elf','emitter'),('elf-prefix.raw','prefix'),('owner.elf','executable')):
            raw=capture(self.previous/name);wanted=self.proof[field]
            need(identity(raw)=={k:wanted[k] for k in ('bytes','sha256')},'Prior actual build output changed: '+name)
        self.check()
    def current_inputs(self):
        values={}
        for name,wanted in self.manifest.items():
            need(not Path(name).is_absolute() and Path(name).as_posix()==name and '..' not in Path(name).parts,'Source path escapes')
            raw=capture(ROOT/name);need(identity(raw)==wanted,'Complete live source differs from qualified input: '+name)
            values[name]=raw
        return values
    def composed(self):
        manifest=json.loads(self.inputs['hia/components.json'])
        need(set(manifest)=={'schema','includes'} and manifest['schema']=='trnm.hia.component-includes.v1','Component manifest schema')
        owned={}
        def visit(name,ancestry):
            need(name not in ancestry and '..' not in Path(name).parts and name.startswith(('src/','platform/','storage/'))
                 and name.endswith('.hepta') and not Path(name).is_absolute(),'Canonical/cyclic HIA source')
            if name in owned:return owned[name]
            raw=self.inputs['hia/'+name]
            declarations=re.findall(rb'(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(',raw)
            matches=list(re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)',raw))
            functions={m.group(1).decode():m.group(0) for m in matches}
            need(len(declarations)==len(set(declarations))==len(matches)==len(functions)
                 and set(functions)=={n.decode() for n in declarations},'Ambiguous HIA function boundary')
            names=set(functions)
            for row in manifest['includes'].get(name,[]):
                need(set(row)=={'source','functions'} and row['functions'],'Malformed explicit include')
                dependency=visit(row['source'],(*ancestry,name))
                for selected in row['functions']:
                    need(selected in dependency and selected not in names,'Unknown/duplicate selected HIA function')
                    names.add(selected)
            owned[name]=functions;return functions
        source='platform/peer_lease_store/owner_policy.hepta';visit(source,())
        blocks=[self.inputs['hia/'+source].rstrip()+b'\n']
        for row in manifest['includes'].get(source,[]):
            for name in row['functions']:blocks.append(owned[row['source']][name].rstrip()+b'\n')
        return b''.join(blocks)
    def check(self):
        need(self.current_inputs()==self.inputs,'Live source drift during native replay')
        need(capture(self.previous/'native-compiler.elf')==self.compiler,'Pinned actual compiler changed')
    def build(self):
        self.check();stages=[]
        def stage(executable,payload,label):
            out,row=run_native(executable,payload,self.output,label);stages.append(row);require_success(row);return out
        policy=stage(self.compiler,self.policy,'compile-policy')
        writer=stage(self.compiler,self.emitter,'compile-emitter')
        prefix=stage(writer,struct.pack('<Q',len(policy)),'emit-prefix')
        executable=prefix+policy;profile=inspect_executable(executable)
        for raw,key in ((policy,'policy'),(writer,'emitter'),(prefix,'prefix'),(executable,'executable')):
            need(identity(raw)=={k:self.proof[key][k] for k in ('bytes','sha256')},'Actual fresh native replay differs')
        for name,raw in (('native-compiler.elf',self.compiler),('policy-composed.hepta',self.policy),('policy.flat',policy),
                         ('emitter.elf',writer),('elf-prefix.raw',prefix),('owner.elf',executable)):(self.output/name).write_bytes(raw)
        self.check()
        report={**self.proof,'stages':stages,'executable':identity(executable)|profile,
            'build_profile':'actual-selfhost-replay-of-exact-earlier-Core-admitted-source',
            'hosted_Hepta_authoring_package_loaded_here':False,'actual_native_build_executed_here':True,
            'earlier_build':identity(capture(self.previous/'build.json'))}
        (self.output/'earlier-build.json').write_bytes(capture(self.previous/'build.json'))
        (self.output/'build.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        return executable,report
