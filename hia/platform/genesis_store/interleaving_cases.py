"""Controlled pause-boundary interleavings; no continuous same-UID safety claim."""
from __future__ import annotations
import json,os,struct
from pathlib import Path
from .build import need
from .native_io import request,snapshot,parse_success

def qualify(suite):
    cases=(
      ("replace-pending-after-validation",13,"replace",0,65),
      ("change-pending-content-after-validation",13,"change",0,66),
      ("replace-held-lock-after-gate",1,"lock",0,65),
      ("replace-held-lock-after-create",10,"lock",0,65),
      ("replace-empty-pending-after-create",10,"replace-equal",0,65),
      ("append-empty-pending-after-create",10,"append",0,65),
      ("change-recovery-prefix-after-validation",12,"change",2,66),
      ("extend-recovery-prefix-after-validation",12,"append",2,65),
      ("replace-recovery-prefix-after-validation",12,"replace-equal",2,65),
      ("replace-held-lock-before-rename",13,"lock",0,65),
      ("change-final-before-directory-sync",14,"change",0,71),
      ("replace-final-after-directory-sync",15,"replace-equal",0,65),
      ("change-final-before-cold-open-read",20,"change",0,66),
      ("change-final-before-explicit-read",30,"change",0,66),
      ("replace-held-lock-before-explicit-read",30,"lock",0,65),
    )
    for label,tag,action,mode,expected in cases:
        directory=suite.fixture(label,pending=True,raw=suite.record[:2048]) if mode==2 else suite.fixture(label,lock=False)
        session=suite.process(label,directory,mode=mode,gate=True)
        session.send((request(1) if tag==30 else b"")+request(2))
        changed=False;after_action=None;published_before=None
        try:
            while True:
                try:event=session.gate_event()
                except ValueError as error:
                    if "EOF" not in str(error):raise
                    break
                if event["tag"]==tag and not changed:
                    published_before=event["private_published_flag"]
                    if action=="lock":
                        path=directory/"ng1.owner.lock";replacement=suite.output/(label+"-replacement")
                        replacement.write_bytes(b"");replacement.chmod(0o600);os.replace(replacement,path)
                    else:
                        path=next(p for p in directory.iterdir() if p.name.endswith(".pending") or p.name.endswith(".state"))
                        prior=path.read_bytes();(session.output/"before-controller-mutation.raw").write_bytes(prior)
                        bad=bytearray(prior)
                        if action in ("replace","change"):
                            need(bool(bad),"Control requires an existing prefix");bad[-1]^=1
                        if action in ("replace","replace-equal"):
                            replacement=suite.output/(label+"-replacement")
                            replacement.write_bytes(bad);replacement.chmod(0o600);os.replace(replacement,path)
                        elif action=="append":
                            with path.open("ab",buffering=0) as stream:stream.write(b"x")
                        else:
                            with path.open("r+b",buffering=0) as stream:
                                stream.seek(len(bad)-1);stream.write(bad[-1:])
                    changed=True;after_action=snapshot(directory)
                session.resume()
            process,stdout=session.finish()
            need(changed and not process["timed_out"] and process["exit_code"]==expected,label+": expected cut/refusal absent")
            need(len(stdout)==(256 if tag==30 else 0),label+": unexpected acknowledgement")
            after=snapshot(directory)
            need(after==after_action,label+": owner changed namespace after substitution")
            if tag in (1,10,12,13):
                need(not (directory/suite.final_name).exists(),label+": owner published after failed prerequisite")
            need(process["diagnostic"][3]==int(tag==14),label+": wrong uncertainty")
            suite.add(label,process=process,after_controller_action=after_action,after_refusal=after,
                native_post_action_mutation=False,publication_preceded_controller_action=bool(published_before),
                receipt_bytes=len(stdout),continuous_same_uid_safety_claimed=False)
        finally:suite.cleanup(session)
    # The public capability is the already-open directory descriptor, not an external pathname.
    label="retained-directory-FD-authority"
    directory=suite.fixture(label,lock=False);moved=suite.output/(label+"-renamed")
    session=suite.process(label,directory,gate=True)
    session.send(request(1)+request(2))
    try:
        event=session.advance(1);original=directory.stat()
        directory.rename(moved);directory.mkdir(mode=0o700)
        (directory/"foreign-marker").write_bytes(b"DO-NOT-TOUCH")
        replacement_before=snapshot(directory)
        session.resume()
        while True:
            try:session.gate_event()
            except ValueError as error:
                if "EOF" not in str(error):raise
                break
            session.resume()
        process,stdout=session.finish()
        need(process["exit_code"]==0 and not process["timed_out"],"Retained directory capability lost")
        _,record=parse_success(stdout)
        actual=moved.stat()
        need((original.st_dev,original.st_ino)==(actual.st_dev,actual.st_ino)
             and (moved/suite.final_name).read_bytes()==record==suite.record,
             "Owner wrote to replacement external path")
        need(snapshot(directory)==replacement_before,"Replacement directory was touched")
        suite.add(label,process=process,cut=event,retained_device_inode=[actual.st_dev,actual.st_ino],
            external_replacement_before=replacement_before,external_replacement_after=snapshot(directory),
            external_path_binding_claimed=False)
    finally:suite.cleanup(session)

def descriptor_lifetime(suite):
    directory=suite.fixture("descriptor-lifetime",raw=suite.record)
    before=snapshot(directory)
    session=suite.process("descriptor-lifetime",directory,mode=1)
    counts=[]
    try:
        opened=session.opened()
        for index in range(32):
            session.send(request(1))
            header=session._read(session.process.stdout.fileno(),64)
            need(header[:8]==b"NGREAD01" and struct.unpack_from("<Q",header,8)[0]==len(suite.record),"Repeated actual READ header")
            record=session._read(session.process.stdout.fileno(),len(suite.record))
            need(record==suite.record,"Repeated actual full READ differs")
            counts.append(len(list((Path("/proc")/str(session.process.pid)/"fd").iterdir())))
        session.send(request(2));process,stdout=session.finish()
        need(process["exit_code"]==0 and process["stderr"]["bytes"]==0 and not process["timed_out"],"Repeated READ owner close failed")
        need(len(set(counts))==1,"Retained owner leaked file descriptions on READ")
        need(len(stdout)==256+32*(64+len(suite.record)) and snapshot(directory)==before,"Repeated READ changed data")
        cold,_,record=suite.success("descriptor-lifetime-new-owner",directory,mode=1,workers=2)
        need(record==suite.record,"New owner after CLOSE differs")
        suite.add("32-complete-READs-stable-FDs-and-CLOSE-releases-lock",
            process=process,actual_fd_counts=counts,fresh_owner=cold,namespace_unchanged=True)
    finally:suite.cleanup(session)
