"""Public admission of one exhaustive, source-defined native qualification part."""
from __future__ import annotations
import lzma
from pathlib import Path
from . import safe_io as safe
from .source_graph import REPOSITORY,complete_sources,original_manifest,bound_corpus,digest,identity,need,check_sources
from .cases import PREFIX_PARTS,selection
from .build_evidence import validate_build
from .process_evidence import batch_process,prefix_process
SCOPE={'internal_default_config':True,'ordinary_account_point_access':None,'runtime_host_proxy':False,
 'complete_node':False,'admission_persistence':False,'persistent_commit':False,'service_deadline_qualified':False,'original_rust':'NOT_RUN'}
def partition(profile,part):
    return {'index':part,'count':1 if profile=='batch' else PREFIX_PARTS,'indices':selection(profile,part)}
def identities(directory,names=None):
    names=safe.roster(directory) if names is None else names
    return {name:identity(safe.read(directory,name)) for name in sorted(names)}
def bounded_xz(raw,expected):
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=16*1024*1024)
    observed=decoder.decompress(raw,max_length=len(expected)+1)
    while not decoder.eof and not decoder.needs_input:
        observed+=decoder.decompress(b'',max_length=len(expected)+1-len(observed))
        need(len(observed)<=len(expected),'Corpus expands past exact source-defined bytes')
    need(decoder.eof and decoder.unused_data==b'' and observed==expected,'Truncated, trailing or changed compressed corpus')
def validate_bundle(repository,bundle,expected_profile=None):
    bundle=Path(bundle).absolute();before=identities(bundle)
    comparison=safe.load(bundle,'native-comparison.json');report=safe.load(bundle,'native-report.json')
    need(isinstance(comparison,dict) and set(comparison)=={'schema','status','profile','partition','build','corpus','cases'} and comparison['schema']=='trnm.execution-batch-native-comparison.v1' and comparison['status']=='PASS','Complete native comparison schema/status')
    profile=comparison['profile'];need(profile in ('batch','prefix') and (expected_profile is None or profile==expected_profile),'Requested native profile')
    part=comparison['partition'];need(isinstance(part,dict) and type(part.get('index')) is int and safe.same(part,partition(profile,part['index'])),'Exact exhaustive native partition')
    captured=complete_sources(repository);build,elf,build_files=validate_build(bundle/'native-build',profile,repository,captured)
    need(safe.same(comparison['build'],build),'One actual image/source lineage')
    original=original_manifest(repository)
    corpus,inputs=bound_corpus(repository,profile);declared=comparison['corpus']
    need(isinstance(declared,dict) and set(declared)=={'raw','compressed','path'} and declared['path']=='corpus.jsonl.xz','Exact source corpus declaration')
    need(safe.same(declared['raw'],identity(corpus)) and safe.read(bundle,'corpus.jsonl')==corpus,'Full source-generated input corpus')
    archived=safe.read(bundle,'corpus.jsonl.xz');need(safe.same(declared['compressed'],identity(archived)),'Actual compressed corpus identity');bounded_xz(archived,corpus)
    expected_report={'schema','status','profile','partition','build','corpus','comparison','histories_total','histories_executed','commands_planned','commands_actual','progress_records','skipped_commands','controls','elapsed_ns','verification','scope'}
    need(isinstance(report,dict) and set(report)==expected_report and report['schema']=='trnm.execution-batch-native-qualification.v1' and report['status']=='PASS','Complete native report')
    need(report['profile']==profile and safe.same(report['partition'],part) and safe.same(report['build'],build) and safe.same(report['corpus'],declared),'Native report/source/corpus lineage')
    need(safe.same(report['comparison'],identity(safe.read(bundle,'native-comparison.json'))),'Complete comparison identity')
    need(safe.same(report['verification'],{'primary_error':None,'cleanup_errors':[],'source_after':{'status':'PASS','errors':[]}}) and safe.same(report['scope'],SCOPE),'Closed native verification and exact authority scope')
    need(type(report['elapsed_ns']) is int and report['elapsed_ns']>0,'Actual qualification interval')
    indices=part['indices'];need(isinstance(comparison['cases'],list) and isinstance(report['controls'],list) and len(comparison['cases'])==len(report['controls'])==len(indices),'Complete actual selected history roster')
    expected_files={'native-comparison.json','native-report.json','corpus.jsonl','corpus.jsonl.xz'}
    expected_files.update('native-build/'+name for name in build_files)
    observed=[];controls=[];commands=0;progress=0;skipped=0;elapsed=0
    for index,record,control in zip(indices,comparison['cases'],report['controls'],strict=True):
        need(isinstance(record,dict) and set(record)=={'index','observation'} and type(record['index']) is int and record['index']==index,'Complete actual history index')
        directory='cases/%04d'%index;case=inputs[index]
        decode=batch_process if profile=='batch' else prefix_process
        actual,summary=decode(bundle/directory,case,build['executable'])
        need(safe.same(record['observation'],actual),'Comparison differs from actual complete source-driven pipe observations')
        expected={'index':index,'status':'PASS',**summary}
        need(safe.same(control,expected),'Complete typed control summary differs')
        commands+=summary['commands'];progress+=summary['progress_records'];skipped+=len(summary['skipped']);elapsed+=summary['elapsed_ns']
        observed.append(record);controls.append(expected)
        expected_files.update(directory+'/'+name for name in safe.roster(bundle/directory))
    planned=sum(len(inputs[index]['commands']) if profile=='prefix' else 1 for index in indices)
    for name,value in [('histories_total',len(inputs)),('histories_executed',len(indices)),('commands_planned',planned),('commands_actual',commands),('progress_records',progress),('skipped_commands',skipped)]:
        need(type(report[name]) is int and report[name]==value,'Actual aggregate '+name)
    need(commands+skipped==planned and elapsed<=report['elapsed_ns'],'Complete methods and actual elapsed intervals')
    need(set(before)==expected_files and safe.roster(bundle)==expected_files and identities(bundle,expected_files)==before,'Missing, extra or changed actual evidence artifact')
    check_sources(captured[0],original,repository)
    return {'comparison':comparison,'report':report,'source_inputs':captured[0],'original_sources':original,'inputs':inputs,'corpus_raw':corpus,'cases':observed,'bundle_artifacts':before,'executable':build['executable']}
def admit_complete(repository,bundles,profile):
    need(profile in ('batch','prefix') and isinstance(bundles,(tuple,list)) and len(bundles)==(1 if profile=='batch' else PREFIX_PARTS),'Complete actual source partitions are required')
    parts=[validate_bundle(repository,path,profile) for path in bundles]
    parts.sort(key=lambda value:value['comparison']['partition']['index'])
    need([value['comparison']['partition']['index'] for value in parts]==list(range(len(parts))),'No missing or duplicate native partition')
    first=parts[0];cases={}
    for part in parts:
        need(safe.same(part['source_inputs'],first['source_inputs']) and safe.same(part['original_sources'],first['original_sources']) and part['corpus_raw']==first['corpus_raw'] and safe.same(part['executable'],first['executable']),'Exact source/corpus/ELF shared across complete partitions')
        for row in part['cases']:
            need(row['index'] not in cases,'Repeated actual history');cases[row['index']]=row['observation']
    need(set(cases)==set(range(len(first['inputs']))),'All original histories executed')
    return {'parts':parts,'source_inputs':first['source_inputs'],'original_sources':first['original_sources'],'inputs':first['inputs'],'corpus_raw':first['corpus_raw'],'cases':[cases[index] for index in range(len(cases))],'executable':first['executable']}
def copy_files(source,destination,names):
    destination=Path(destination);need(not destination.exists(),'Fresh evidence destination')
    destination.mkdir(mode=0o700)
    before=identities(source,names)
    for name in sorted(names):
        raw=safe.read(source,name);need(identity(raw)==before[name],'Evidence changed before copy')
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as out:out.write(raw)
    need(identities(source,names)==before and identities(destination)==before,'Exact copied evidence changed')
    return before

def main():
    import argparse,os
    parser=argparse.ArgumentParser();parser.add_argument('--repository',type=Path,default=REPOSITORY);parser.add_argument('--bundle',type=Path,required=True);parser.add_argument('--profile',choices=('batch','prefix'),required=True);args=parser.parse_args()
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    need(Path(__file__).resolve()==args.repository.absolute()/'hia/platform/execution_batch/bundle.py','Execute the exact repository admission source')
    r=validate_bundle(args.repository,args.bundle,args.profile)
    print(__import__('json').dumps({'status':'PASS','profile':args.profile,'partition':r['comparison']['partition'],'histories':len(r['cases']),'files':len(r['bundle_artifacts'])}))
if __name__=='__main__':main()
