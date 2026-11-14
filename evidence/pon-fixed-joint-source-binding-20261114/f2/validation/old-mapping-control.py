from pathlib import Path
import json,sys,tempfile
root=Path(sys.argv[1])
sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
import joint_consensus_qualification as q
old=q.strict_json((root/'evidence/pon-fixed-joint-source-binding-20261114/historical/joint-consensus-qualification-v1-2bb56596.json').read_bytes())
out=[]
with tempfile.TemporaryDirectory(prefix='joint-old-map-') as directory:
    temp=Path(directory)
    paths=set(q.SOURCE_PATHS)|{q.MANIFEST}|{p for p,_ in q.OBLIGATIONS.values()}
    for p in paths:
        dest=temp/p
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes((root/p).read_bytes())
    for label,code in [('old-revision','REVIEWED_SOURCE'),('old-map-with-current-revision','REVIEWED_SOURCE_MAP')]:
        if label=='old-map-with-current-revision':
            old['reviewed_native_source_commit']=q.REVIEWED_NATIVE_COMMIT
        (temp/q.MANIFEST).write_text(json.dumps(old))
        try:
            q.inspect(temp)
        except q.QualificationError as error:
            assert str(error)==code,(label,str(error))
            out.append({'case':label,'actual_error':str(error),'refused':True})
        else:
            raise AssertionError(label+' unexpectedly accepted')
print(json.dumps({'schema':'joint-old-revision-and-map-refusal-v1','controls':out,'production_reader_used':True,'qualification_granted':False},sort_keys=True))
