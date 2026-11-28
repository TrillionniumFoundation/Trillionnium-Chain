"""One actual native qualification child: 240 seconds, then 3-second cleanup."""
from pathlib import Path
import hashlib,json,os,signal,subprocess,sys,time
from hia.platform.mempool_node.build import ROOT
from hia.platform.mempool_node.safe import new_output,need
MARKER="TRNM_SNAPSHOT_QUALIFICATION_CHILD"
def identity(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def enter(module,argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if os.environ.pop(MARKER,None)==module:return
    need(args.count("--output")==1,"Exact fresh output argument")
    output=Path(args[args.index("--output")+1]).absolute()
    need(not output.exists() and not output.is_symlink(),"Fresh native output")
    receipt_dir=new_output(output.with_name(output.name+"-execution"),ROOT)
    command=[sys.executable,"-B","-m",module,*args]
    environment=dict(os.environ,PYTHONDONTWRITEBYTECODE="1");environment[MARKER]=module
    start=time.monotonic_ns();process=None;timed=False;cleanup=None;error=None;code=None
    with (receipt_dir/"stdout.raw").open("xb") as stdout,(receipt_dir/"stderr.raw").open("xb") as stderr:
        try:
            process=subprocess.Popen(command,stdout=stdout,stderr=stderr,stdin=subprocess.DEVNULL,env=environment,start_new_session=True)
            try:code=process.wait(timeout=240)
            except subprocess.TimeoutExpired:
                timed=True;clean_start=time.monotonic_ns();os.killpg(process.pid,signal.SIGKILL);code=process.wait(timeout=3)
                cleanup={"signal":"SIGKILL","reaped":True,"elapsed_ns":time.monotonic_ns()-clean_start}
        except BaseException as failure:
            error=repr(failure)
            if process is not None and process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
    raw=(receipt_dir/"stdout.raw").read_bytes();err=(receipt_dir/"stderr.raw").read_bytes()
    report={"status":"PASS" if code==0 and not timed and error is None else "FAIL","module":module,"argv":command,"returncode":code,
            "wall_limit_seconds":240,"cleanup_limit_seconds":3,"timed_out":timed,"cleanup":cleanup,"launch_error":error,
            "stdout":identity(raw),"stderr":identity(err),"elapsed_ns":time.monotonic_ns()-start}
    (receipt_dir/"receipt.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush();sys.stderr.buffer.write(err);sys.stderr.buffer.flush()
    print(json.dumps(report,sort_keys=True),flush=True)
    raise SystemExit(0 if report["status"]=="PASS" else 1)
