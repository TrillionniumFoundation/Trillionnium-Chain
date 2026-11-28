"""Reconstruct every native image from its actual compiler streams and source."""
from __future__ import annotations
import re,struct
from pathlib import Path
from . import safe_io as safe
from .source_graph import REPOSITORY,IMAGE_ORDER,complete_sources,original_manifest,digest,need,identity
COMPILER={'bytes':673903,'sha256':'87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54'}
STAGE_KEYS={'argv','cleanup','cleanup_limit_seconds','cwd','end_monotonic_ns','environment',
 'executable_bytes','executable_sha256','exit_code','input_bytes','input_sha256','output_bytes',
 'output_sha256','stage','start_monotonic_ns','stderr_hex','stderr_sha256','timed_out','wall_limit_seconds'}
BUILD_KEYS={'schema','status','profile','source_inputs','source_set_sha256','original_sources','original_source_set_sha256',
 'composed_sources','core','images','elf_prefix','executable','compiler_sha256','toolchain','compiler_qualification_binding',
 'stages','failure','source_after','elapsed_ns','runtime_host_proxy','original_rust_executed','complete_node','admission_persistence','literal_isa_is_a_separate_trusted_boundary'}
def uint(value):return type(value) is int and value>=0
def check_identity(value):
    need(isinstance(value,dict) and set(value)=={'bytes','sha256'} and uint(value['bytes']) and isinstance(value['sha256'],str) and re.fullmatch('[0-9a-f]{64}',value['sha256']) is not None,'Typed byte identity')
def core_counts(raw):
    lines=raw.splitlines()
    return {'functions':sum(line.startswith(b'fn ') for line in lines),
     'blocks':sum(line.startswith(b'block ') for line in lines),
     'ops':sum(line.startswith(b'  ') and not line.lstrip().startswith((b'branch ',b'jump ',b'ret(')) for line in lines)}
def inspect_elf(raw):
    need(len(raw)>=176,'Complete ELF')
    need(struct.unpack_from('<16sHHIQQQIHHHHHH',raw)==(b'\x7fELF\x02\x01\x01'+bytes(9),2,62,1,0x4000B0,64,0,0,64,56,2,0,0,0),'Actual static x86-64 ELF')
    need(struct.unpack_from('<IIQQQQQQ',raw,64)==(1,5,0,0x400000,0x400000,len(raw),len(raw),4096),'Complete RX image extent')
    need(struct.unpack_from('<IIQQQQQQ',raw,120)==(0x6474E551,6,0,0,0,0,0,16),'Non-executable native stack')
def file_names(report):
    files={'build.json','owner.elf','elf-prefix.raw'}
    for name in (*IMAGE_ORDER,'emitter'):
        files.update((name+'-composed.hepta',name+('.elf' if name=='emitter' else '.flat')))
    for row in report['stages']:
        for item in ('receipt.json','stdin.raw','stdout.raw','stderr.raw'):
            files.add('pinned-native/'+row['stage']+'/'+item)
    files.update('source-snapshot/'+name for name in report['source_inputs'])
    return files
def validate_build(root,profile,repository=REPOSITORY,captured=None):
    root=Path(root).absolute()
    sources,profiles=complete_sources(repository) if captured is None else captured
    original=original_manifest(repository)
    report=safe.load(root,'build.json')
    need(isinstance(report,dict) and set(report)==BUILD_KEYS and report['schema']=='trnm.execution-batch-build.v1','Exact native build fields')
    need(report['status']=='PASS' and report['profile']==profile and profile in profiles,'Complete requested profile build')
    need(report['failure'] is None and safe.same(report['source_after'],{'status':'PASS','errors':[]}),'Build failure/source fence')
    for field,expected in [('source_inputs',sources),('original_sources',original)]:
        need(safe.same(report[field],expected),'Incomplete or changed complete '+field)
        for name,row in report[field].items():check_identity(row)
    need(report['source_set_sha256']==digest(sources) and report['original_source_set_sha256']==digest(original),'Actual source-set digest')
    need(report['runtime_host_proxy'] is False and report['original_rust_executed'] is False and report['complete_node'] is False and report['admission_persistence'] is False and report['literal_isa_is_a_separate_trusted_boundary'] is True,'Native authority scope')
    need(uint(report['elapsed_ns']) and report['elapsed_ns']>0,'Actual total build interval')
    pin=safe.load(repository,'hia/qualification/compiler-binding.json');lock=safe.load(repository,'hia/toolchain.lock.json')
    need(safe.same(report['compiler_qualification_binding'],pin) and safe.same(report['toolchain'],lock) and report['compiler_sha256']==pin['compiler_sha256']==COMPILER['sha256'],'Actual compiler and source qualification pin')
    composed=profiles[profile]
    need(safe.same(report['composed_sources'],{n:identity(raw) for n,raw in composed.items()}),'Complete actual HIA composition')
    need(safe.same(report['core'],{n:core_counts(raw) for n,raw in composed.items()}),'Core/source structural counts')
    for name,row in sources.items():need(identity(safe.read(root,'source-snapshot/'+name))==row,'Captured actual source bytes '+name)
    names=(*IMAGE_ORDER,'emitter');stages=report['stages']
    labels=['compile-'+name for name in names]+['emit-prefix']
    need(isinstance(stages,list) and [row.get('stage') for row in stages]==labels,'Complete ordered compiler/emitter stage roster')
    need(set(report['images'])==set(names),'Exact complete image roster')
    images={name:safe.read(root,name+('.elf' if name=='emitter' else '.flat')) for name in names}
    need(all(images.values()) and safe.same(report['images'],{name:identity(raw) for name,raw in images.items()}),'Actual native image bytes')
    prefix=safe.read(root,'elf-prefix.raw');elf=safe.read(root,'owner.elf')
    need(176<=len(prefix)<=8192 and elf==prefix+b''.join(images[name] for name in IMAGE_ORDER),'Full ordered image concatenation equals ELF')
    need(safe.same(report['elf_prefix'],identity(prefix)) and safe.same(report['executable'],identity(elf)),'Actual prefix/ELF identities')
    inspect_elf(elf);inspect_elf(images['emitter'])
    cwd_parent=None;last_end=0;elapsed_sum=0
    for index,row in enumerate(stages):
        label=labels[index];directory='pinned-native/'+label
        need(isinstance(row,dict) and set(row)==STAGE_KEYS and safe.same(safe.load(root,directory+'/receipt.json'),row),'Exact actual stage receipt')
        need(type(row['exit_code']) is int and row['exit_code']==0 and row['timed_out'] is False and row['cleanup'] is None,'Actual successful stage')
        need(safe.same(row['environment'],{'PATH':''}) and type(row['wall_limit_seconds']) is int and row['wall_limit_seconds']==30 and type(row['cleanup_limit_seconds']) is int and row['cleanup_limit_seconds']==3,'Unchanged native compiler execution envelope')
        need(isinstance(row['argv'],list) and len(row['argv'])==1 and isinstance(row['argv'][0],str) and re.fullmatch(r'/proc/self/fd/[0-9]+',row['argv'][0]) is not None and int(row['argv'][0].rsplit('/',1)[1])>=3,'Actual sealed compiler argv')
        need(isinstance(row['cwd'],str),'Actual stage working directory')
        cwd=Path(row['cwd']);need(cwd.is_absolute() and cwd.name==label and cwd.parent.name=='pinned-native','Actual stage location')
        if cwd_parent is None:cwd_parent=cwd.parent
        need(cwd.parent==cwd_parent,'One actual build lineage')
        need(uint(row['start_monotonic_ns']) and uint(row['end_monotonic_ns']) and last_end<=row['start_monotonic_ns']<=row['end_monotonic_ns'],'Actual sequential stage interval')
        last_end=row['end_monotonic_ns'];elapsed_sum+=row['end_monotonic_ns']-row['start_monotonic_ns']
        if index<len(names):
            name=names[index];payload=composed[name];output=images[name];executable=COMPILER
            need(safe.read(root,name+'-composed.hepta')==payload,'Complete copied HIA input')
        else:payload=struct.pack('<19Q',*(len(images[name]) for name in IMAGE_ORDER));output=prefix;executable=identity(images['emitter'])
        stdin=safe.read(root,directory+'/stdin.raw');stdout=safe.read(root,directory+'/stdout.raw');stderr=safe.read(root,directory+'/stderr.raw')
        need(stdin==payload and stdout==output and stderr==b'','Actual full compiler input/output')
        for prefix_name,value in [('input',identity(stdin)),('output',identity(stdout)),('executable',executable)]:
            declared={'bytes':row[prefix_name+'_bytes'],'sha256':row[prefix_name+'_sha256']};check_identity(declared);need(safe.same(declared,value),'Actual stage byte binding '+prefix_name)
        need(row['stderr_hex']=='' and row['stderr_sha256']==identity(b'')['sha256'],'Actual empty compiler diagnostics')
    need(elapsed_sum<=report['elapsed_ns'],'Actual compiler stages fit build interval')
    expected=file_names(report);need(safe.roster(root)==expected,'Complete exact native build artifact roster')
    return report,elf,{name:identity(safe.read(root,name)) for name in sorted(expected)}

def main():
    import argparse,os
    parser=argparse.ArgumentParser();parser.add_argument('--repository',type=Path,default=REPOSITORY);parser.add_argument('--build',type=Path,required=True);parser.add_argument('--profile',choices=('batch','prefix','scoped'),required=True);args=parser.parse_args()
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    need(Path(__file__).resolve()==args.repository.absolute()/'hia/platform/execution_batch/build_evidence.py','Execute exact repository build admission source')
    r,elf,files=validate_build(args.build,args.profile,args.repository)
    print(__import__('json').dumps({'status':'PASS','profile':args.profile,'source_set_sha256':r['source_set_sha256'],'executable':identity(elf),'files':len(files)}))
if __name__=='__main__':main()
