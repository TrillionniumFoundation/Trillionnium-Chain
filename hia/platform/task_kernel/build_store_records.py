"""Build native object/operation persistence with the shared source-fenced Task continuation linker."""
from pathlib import Path
import argparse,json,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from hia.platform.task_kernel.build_store_audit import StoreAuditBuild

class StoreRecordsBuild(StoreAuditBuild):
    scope=__doc__
    builder_name='build_store_records.py'
    qualification_prefix='store_records'
    dispatch_name='records_dispatch.hepta'
    library_name='store-records-native.so'
    additional_units=(('records',10),('progress',11),('bootstrap',12),('verified',13),('policy',14),('grants',15),('budget',16),('task_create',17),('bid',18),('lease',19),('provider_accept',20),('authorize',21),('scope',22),('consume',23),('execution',24),('empty',25),('preview',26),('signature_cache',27))
    image_dependencies={'signature_cache':(ROOT/'hia/src/crypto/ed25519_public_point_cache.hepta',),
                        'progress':(ROOT/'hia/src/task_kernel/store_records.hepta',ROOT/'hia/src/task_kernel/store_markers.hepta'),
                        'bootstrap':(ROOT/'hia/src/task_kernel/store_schema.hepta',),
                        'verified':(ROOT/'hia/src/task_kernel/store_records.hepta',),
                        'budget':(ROOT/'hia/src/task_kernel/store_grants.hepta',),
                        'task_create':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'bid':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'lease':(ROOT/'hia/src/task_kernel/store_objects.hepta',ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'provider_accept':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'authorize':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'scope':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'consume':(ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'execution':(ROOT/'hia/src/task_kernel/store_execution_common.hepta',ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta'),
                        'empty':(ROOT/'hia/src/task_kernel/store_execution_common.hepta',),
                        'preview':(ROOT/'hia/src/task_kernel/store_execution_common.hepta',ROOT/'hia/src/task_kernel/store_command_values.hepta',ROOT/'hia/src/task_kernel/store_grants.hepta')}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--provider',type=Path,required=True)
    args=parser.parse_args();result=StoreRecordsBuild(args.output,args.provider).run()
    print(json.dumps({'status':result['status'],'images':len(result['function_sources']),'report':str(args.output/'build.json')}))
