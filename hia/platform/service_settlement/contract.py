"""One declared contract for the finite native SettlementEngine qualification."""
from pathlib import Path
if not __debug__:raise RuntimeError("Qualification requires assertions enabled")
import hashlib,json,math,os,stat,subprocess
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SCHEMA="trnm.hia.service-settlement-engine.qualification.v1"
READBACK_SCHEMA="trnm.hia.service-settlement-engine.readback.v1"
LIMITS={"qualification_seconds":1200,"native_seconds":240,"generator_seconds":120,"allocator_seconds":240,"original_stage_seconds_max":240,"cleanup_seconds":3,"compiler_seconds":30,"compiler_functions":128,"compiler_ops":8192,"compiler_blocks":1536,"compiler_blocks_per_function":256,"compiler_parameters_per_block":16,"compiler_values_per_function":2048}
FALSE_SCOPES={name:False for name in ("whole_chain_native","whole_package_retired","node_integration_complete","original_service_budget_qualified","cross_target_qualified","production_activation","store_qualified","full_host_dependency_closure_claimed","rust_or_interpreter_fallback")}
COUNTS={"original_registered":137,"original_outer":136,"original_nested_fixture_types":1,"original_nested_phases":2,"doctests":2,"fixtures":320,"operations":2636,"native_calls":16066,"actual_height_calls":1754,"allocator_controls":162,"allocator_failures":136,"allocator_calls":2058,"allocator_frees":1922,"concurrent_threads":8,"concurrent_owners":256,"live_owners":0,"allocator_live":0,"allocator_live_bytes":0,"allocator_bad_frees":0}
UNITS={"control":"hia/src/service_settlement/engine_control.hepta","receipt":"hia/src/service_settlement/receipt_owned.hepta","rollup":"hia/src/service_settlement/rollup.hepta","settle":"hia/src/service_settlement/settle.hepta","values":"hia/src/service_settlement/values.hepta","trust":"hia/src/service_settlement/trust_owned.hepta","emitter":"hia/platform/service_settlement/engine_owned.hepta","arithmetic":"hia/src/service_settlement/arithmetic.hepta"}
EXPORTS=sorted("trnm_settlement_"+n for n in ("engine_new","engine_apply","engine_replay","engine_validate_execution","engine_clone","owned_clone","owned_drop","owned_kind","engine_history_count","error_code","engine_state_copy","error_display","engine_trust","engine_state","engine_state_root","error_message","bytes_view","consumption_receipt_id","consumption_rollup_id","settlement_policy_hash","operation_id"))
COMPILER_SHA256="87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
FIXTURES_SHA256="bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26"
SOURCE_SUPPORT=("AGENTS.md","PROJECT_ID","PROJECT_BOUNDARY.json","config/portability-inventory-v1.json","config/consensus-mainline.json","config/hia-migration-v1.json","hia/qualification/compiler-binding.json","docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md","scripts/project-preflight.sh","scripts/ci/project_boundary.py","scripts/w1_owned_process_collector_v1.py","hia/components.json","hia/tools/toolchain.py","hia/toolchain.lock.json",".github/workflows/hia-native-migration.yml","hia/tools/qualify_additional_owner_ci.py","scripts/ci/test_additional_owner_binding.py")
def canonical(value):
 return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def identity(data):return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def unique(items):
 value={}
 for key,item in items:
  if key in value:raise ValueError("Duplicate JSON key: "+key)
  value[key]=item
 return value
def finite(text):
 value=float(text)
 if not math.isfinite(value):raise ValueError("Nonfinite number")
 return value
def document(data):
 return json.loads(data,object_pairs_hook=unique,parse_float=finite,parse_constant=lambda x:(_ for _ in ()).throw(ValueError("Nonfinite token")))
def file_identity(path):
 path=Path(path);before=path.lstat()
 if not stat.S_ISREG(before.st_mode) or path.is_symlink():raise ValueError("Nonregular source: "+str(path))
 with path.open("rb") as stream:
  current=os.fstat(stream.fileno())
  if (before.st_dev,before.st_ino,before.st_size)!=(current.st_dev,current.st_ino,current.st_size):raise ValueError("Source replaced")
  result={"bytes":before.st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
 after=path.lstat()
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError("Source changed while reading")
 return result
def checked_path(relative):
 if type(relative) is not str or relative.startswith("/") or ".." in Path(relative).parts:raise ValueError("Invalid relative source")
 p=ROOT/relative
 if p.resolve(strict=True)!=p:raise ValueError("Symlinked source path")
 file_identity(p);return p
def source_inputs():
 names=set(SOURCE_SUPPORT)|set(UNITS.values())
 binding=document((ROOT/"hia/qualification/compiler-binding.json").read_bytes())
 for key in ["outer_report","nested_report"]:names.add("hia/qualification/"+binding[key])
 registry=document((ROOT/"hia/components.json").read_bytes())
 if registry.get("schema")!="trnm.hia.component-includes.v1" or set(registry)!={"schema","includes"}:raise ValueError("Unknown component registry")
 for key,rows in registry["includes"].items():
  names.add("hia/"+key)
  for row in rows:
   if set(row)!={"source","functions"}:raise ValueError("Malformed component declaration")
   names.add("hia/"+row["source"])
 for directory in [HERE,ROOT/"hia/src/service_settlement"]:
  for p in directory.rglob("*"):
   if p.is_symlink():raise ValueError("Symlink in canonical owner")
   if p.is_file():
    if "__pycache__" in p.parts:raise ValueError("Unexpected bytecode in source owner")
    names.add(p.relative_to(ROOT).as_posix())
 for p in (ROOT/"trillionnium").rglob("*"):
  if p.is_symlink():raise ValueError("Symlink in original source")
  if p.is_file():names.add(p.relative_to(ROOT).as_posix())
 return {n:file_identity(checked_path(n)) for n in sorted(names)}
def repository():
 def git(*args):return subprocess.check_output(["/usr/bin/git",*args],cwd=ROOT,env={"PATH":"/usr/bin:/bin","GIT_NO_LAZY_FETCH":"1","GIT_TERMINAL_PROMPT":"0"})
 head=git("rev-parse","HEAD").decode().strip();tree=git("rev-parse","HEAD^{tree}").decode().strip()
 branch=git("rev-parse","--abbrev-ref","HEAD").decode().strip()
 status=git("status","--porcelain=v1","-z","--untracked-files=all")
 return {"head":head,"tree":tree,"branch":branch,"repository_clean":not status,"working_status":identity(status)}
def output_directory(path):
 path=Path(path).absolute()
 if path.exists() or path.is_symlink():raise ValueError("Qualification output must be new")
 parent=path.parent.resolve(strict=True)
 if parent==ROOT or ROOT in parent.parents:raise ValueError("Output must be outside repository")
 return parent/path.name
