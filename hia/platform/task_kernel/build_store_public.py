"""Build the public TaskStore owner with one frozen shared provider and private HIA continuations."""
from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.task_kernel.build_store_records import StoreRecordsBuild
HERE=Path(__file__).resolve().parent

class StorePublicBuild(StoreRecordsBuild):
    scope=__doc__
    builder_name='build_store_public.py'
    qualification_prefix='store_public'
    root_source=ROOT/'hia/src/task_kernel/store_public.hepta'
    library_name='task-store-native.so'
    extra_emitters=(('owned',HERE/'store_owned.hepta','TKOWN001'),)
    extra_sources=(HERE/'build_store_records.py',HERE/'task_store.h',HERE/'store_public_includes.json',HERE/'qualification/store_public_native.py',
                   HERE/'qualify_store_owned_allocations.py',HERE/'qualification/store_owned_allocator_observer.c',HERE/'qualification/store_owned_allocator_observer.py')
    export_map=HERE/'store_owned.map'
    export_inventory=HERE/'store_owned_exports.json'

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--provider',type=Path,required=True)
    args=parser.parse_args();result=StorePublicBuild(args.output,args.provider).run()
    print(json.dumps({'status':result['status'],'images':len(result['function_sources']),'exports':len(result['public_symbols']),'report':str(args.output/'build.json')}))
