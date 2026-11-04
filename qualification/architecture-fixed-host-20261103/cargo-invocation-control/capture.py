import sys,os,json,pathlib
p=pathlib.Path(os.environ["RUNNER_CAPTURE"])
p.write_text(json.dumps({"argv":sys.argv[1:],"cwd":os.getcwd(),"cargo_manifest_dir":os.environ.get("CARGO_MANIFEST_DIR"),"ld_library_path":os.environ.get("LD_LIBRARY_PATH")}))
os.execv(sys.argv[1],sys.argv[1:])
