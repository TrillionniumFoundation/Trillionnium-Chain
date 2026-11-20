"""Read a complete qualification without changing any qualification file."""
from pathlib import Path
import argparse,json,time,traceback
from .contract import READBACK_SCHEMA,FALSE_SCOPES,canonical,file_identity,output_directory,document
from .qualification.evidence import Evidence
from .qualification.assessment import assessment,verify_controls,summary
def readback(input_path,output):
 output=output_directory(output);source=Path(input_path).resolve(strict=True)
 assert not output.is_relative_to(source),'Independent output must not modify the qualification'
 output.mkdir(mode=0o700);start=time.monotonic_ns()
 report={'schema':READBACK_SCHEMA,'status':'INCOMPLETE',**FALSE_SCOPES,'source_inputs_stable':False,'prior_execution_reused':False}
 try:
  source=Path(input_path).resolve(strict=True);identity=file_identity(source/'report.json')
  e=Evidence(source);q=document((source/'report.json').read_bytes())
  actual=assessment(e);controls=verify_controls(e);summary(q,actual,controls);e.final()
  assert file_identity(source/'report.json')==identity
  report.update(actual,status='PASS',qualification_report_sha256=identity['sha256'],qualification_report=identity,source_inputs_stable=True,prior_execution_reused=False,integrity_controls=controls,elapsed_ns=time.monotonic_ns()-start,**FALSE_SCOPES)
 except BaseException:report.update(status='FAIL',exception=traceback.format_exc(),elapsed_ns=time.monotonic_ns()-start)
 (output/'report.json').write_bytes(canonical(report)+b'\n')
 print(json.dumps(report,sort_keys=True,allow_nan=False),flush=True)
 return 0 if report['status']=='PASS' else 1
def main():
 p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 return readback(a.input,a.output)
if __name__=='__main__':raise SystemExit(main())
