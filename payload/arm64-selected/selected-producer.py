#!/usr/bin/env python3
"""One fixed H5DF ARM64 cost artifact; fixed selected records after actual directory discovery."""
import datetime,hashlib,json,os,re,selectors,stat,struct,subprocess,sys,time,zlib
from pathlib import Path,PurePosixPath
BASE=Path("/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1")
OUT=BASE/"selected-v1"
GH="/opt/homebrew/bin/gh"
REPO="TrillionniumFoundation/Trillionnium-Chain"
ARTIFACT=14124468052
RUN=43621754143
HEAD="5df7ae6f482157c5f7fdcbcd52222117a965053f"
SUBJECT=HEAD
TREE="6be4940d38cc88782657f2684cbefe48866f8b9f"
NAME="cost-arm64-"+HEAD+"-1"
SIZE=9909858
DIGEST="3b093c989b92fb7d657195826ae6faed9e641840dbe8f48c7721aebcf7804d7d"
TAIL=65557
START=SIZE-TAIL
END=SIZE-1
BUDGET=180
TOTAL_BUDGET=900
MAX_GETS=21
SAFE_HEADERS={"content-range","content-length","content-type","accept-ranges","content-encoding"}
SOURCE_LOG=Path("/private/tmp/chain-H5DF-arm64-cross-cost-original-evidence-20261114-v1/job-132528769087-original-log.stdout")
SOURCE_BYTES=184757
SOURCE_SHA="b5f690a2a7cb61c16b6b459e1af5a7ca36430557c99ab51f4c66a7db09b32145"
SELECTORS=[
 "caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct",
 "from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection",
 "four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged",
 "from_zero_service_shares_cpu_with_honest_work_and_reopened_owner",
 "from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline"]
SELECTED=["from-zero-native/manifest.json","from-zero-native/confirmation/report.json",
          "source.json","from-zero-native-host/controller-result.json"]+[
 "from-zero-native/"+n+"/"+suffix for n in SELECTORS for suffix in ("process.json","stdout","stderr")]
def need(ok, message):
    if not ok:
        raise ValueError(message)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def stable_bytes(path, expected_size, expected_sha):
    need(path.is_absolute() and path.resolve(strict=True) == path, "SOURCE_PATH")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected_size, "SOURCE_REGULAR_SIZE")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        need(fingerprint(os.fstat(f.fileno())) == fingerprint(before), "SOURCE_OPEN_IDENTITY")
        raw = f.read(expected_size + 1)
        need(fingerprint(os.fstat(f.fileno())) == fingerprint(before), "SOURCE_FD_CHANGED")
    need(fingerprint(path.lstat()) == fingerprint(before), "SOURCE_PATH_CHANGED")
    need(len(raw) == expected_size and hashlib.sha256(raw).hexdigest() == expected_sha, "SOURCE_SHA")
    return raw

def save(name, raw):
    path = OUT / name
    with path.open("xb") as f:
        f.write(raw)
    need(path.read_bytes() == raw, "OUTPUT_READBACK")
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def save_json(name, value):
    return save(name, (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode())

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out

def parse_json(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))

def parsed_headers(raw):
    """Keep only typed non-sensitive fields. Never persist the original headers."""
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    need(len(lines) <= 128, "HEADER_COUNT")
    match = re.fullmatch(rb"HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([0-9]{3})(?: [\x20-\x7e]*)?", lines[0])
    need(match is not None, "GH_INCLUDE_STATUS_UNRECOGNIZED")
    status = int(match.group(1))
    safe = {}
    for line in lines[1:]:
        if not line:
            continue
        need(not line.startswith((b" ", b"\t")) and b":" in line, "HEADER_FRAMING")
        key, value = line.split(b":", 1)
        need(re.fullmatch(rb"[A-Za-z0-9-]+", key) is not None, "HEADER_KEY")
        key = key.decode("ascii").lower()
        if key not in SAFE_HEADERS:
            continue
        need(key not in safe, "DUPLICATE_SAFE_HEADER")
        value = value.strip()
        need(len(value) <= 128 and all(32 <= c < 127 for c in value), "SAFE_HEADER_VALUE")
        if key == "content-range":
            need(re.fullmatch(rb"bytes [0-9]+-[0-9]+/[0-9]+", value) is not None, "CONTENT_RANGE_FORMAT")
        elif key == "content-length":
            need(re.fullmatch(rb"[0-9]{1,12}", value) is not None, "CONTENT_LENGTH_FORMAT")
        elif key == "content-type":
            need(re.fullmatch(rb"[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+(?:; ?charset=[A-Za-z0-9_-]+)?", value) is not None, "CONTENT_TYPE_FORMAT")
        elif key == "accept-ranges":
            need(value in (b"bytes", b"none"), "ACCEPT_RANGES_FORMAT")
        elif key == "content-encoding":
            need(value in (b"identity", b"gzip", b"br", b"deflate"), "CONTENT_ENCODING_FORMAT")
        safe[key] = value.decode("ascii")
    return status, safe

def capture(label, endpoint, deadline, range_probe=False):
    argv = [GH, "api", "--hostname", "github.com", "--method", "GET"]
    if range_probe:
        argv += ["--include", "--header", f"Range: bytes={START}-{END}"]
    argv += [endpoint]
    env = os.environ.copy()
    env.pop("GH_DEBUG", None)
    env["GH_HOST"] = "github.com"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONOPTIMIZE"] = "0"
    rec = {"label": label, "argv": argv, "method": "GET", "cwd": "/private/tmp",
           "started_at": now(), "finished_at": None, "exit": None, "error": None,
           "per_GET_budget_seconds": BUDGET, "automatic_retry": False,
           "GH_DEBUG_removed": True, "GH_HOST": "github.com",
           "headers_raw_saved": False, "stderr_raw_saved": False,
           "stdout_consumed_bytes": 0, "stderr_consumed_bytes": 0,
           "stdout_eof": False, "stderr_eof": False,
           "http_status": None, "safe_response_headers": {},
           "raw_header_bytes": None, "raw_header_sha256": None}
    body = bytearray()
    headers = bytearray()
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    process = None
    sel = selectors.DefaultSelector()
    try:
        need(time.monotonic() < deadline, "TOTAL_DEADLINE_BEFORE_REQUEST")
        process = subprocess.Popen(argv, cwd="/private/tmp", env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rec["owned_pid"] = process.pid
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, name)
        got_headers = not range_probe
        while sel.get_map():
            need(time.monotonic() < deadline, "PER_GET_180_SECOND_DEADLINE")
            for key, _ in sel.select(min(0.1, max(0.0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 4096)
                name = key.data
                if not chunk:
                    rec[name + "_eof"] = True
                    sel.unregister(key.fileobj)
                    continue
                hashes[name].update(chunk)
                rec[name + "_consumed_bytes"] += len(chunk)
                if name == "stderr":
                    need(rec["stderr_consumed_bytes"] <= 65536, "STDERR_COUNT_BOUND")
                    continue
                if not got_headers:
                    headers.extend(chunk)
                    cuts = [(headers.find(x), x) for x in (b"\r\n\r\n", b"\n\n") if headers.find(x) >= 0]
                    if not cuts:
                        need(len(headers) <= 16384, "HEADER_BYTE_BOUND")
                        continue
                    cut, separator = min(cuts, key=lambda x: x[0])
                    need(cut + len(separator) <= 16384, "HEADER_BYTE_BOUND")
                    original = bytes(headers[:cut])
                    rec["raw_header_bytes"] = cut + len(separator)
                    rec["raw_header_sha256"] = hashlib.sha256(bytes(headers[:cut + len(separator)])).hexdigest()
                    status, safe = parsed_headers(original)
                    rec["http_status"], rec["safe_response_headers"] = status, safe
                    chunk = bytes(headers[cut + len(separator):])
                    headers.clear()
                    if status != 206:
                        raise ValueError("RANGE_UNSUPPORTED_HTTP_STATUS")
                    need(safe.get("content-range") == f"bytes {START}-{END}/{SIZE}", "EXACT_TAIL_CONTENT_RANGE_REQUIRED")
                    need("content-length" not in safe or safe["content-length"] == str(TAIL), "EXACT_TAIL_CONTENT_LENGTH")
                    need(safe.get("content-encoding", "identity") == "identity", "ENCODED_RANGE_REFUSED")
                    got_headers = True
                cap = TAIL if range_probe else 65536
                need(len(body) + len(chunk) <= cap, "BODY_BYTE_BOUND")
                body.extend(chunk)
        rec["exit"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rec["exit"] == 0, "GH_GET_NONZERO")
        if range_probe:
            need(got_headers and rec["http_status"] == 206 and len(body) == TAIL, "COMPLETE_EXACT_TAIL_REQUIRED")
        rec["accepted_body_bytes"] = len(body)
    except Exception as error:
        # All ValueError messages above are fixed codes, never server strings.
        rec["error"] = str(error) if isinstance(error, ValueError) else type(error).__name__
    finally:
        sel.close()
        if process is not None:
            if process.poll() is None:
                rec["terminated_owned_request"] = True
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            rec["exit"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        rec["finished_at"] = now()
        rec["stdout_consumed_sha256"] = hashes["stdout"].hexdigest()
        rec["stderr_consumed_sha256"] = hashes["stderr"].hexdigest()
        rec["complete_transport"] = (rec["error"] is None and rec["exit"] == 0
                                     and rec["stdout_eof"] and rec["stderr_eof"])
        rec["body_retained_bytes"] = len(body) if range_probe and rec["http_status"] == 206 else 0
        rec["step_receipt"] = save_json(label + ".step.json", rec)
    return rec, bytes(body)

def central_directory(tail):
    """Parse only the declared central directory present inside the acquired tail."""
    positions = [i for i in range(max(0, len(tail) - 65557), len(tail) - 21)
                 if tail[i:i + 4] == b"PK\x05\x06" and i + 22 + int.from_bytes(tail[i + 20:i + 22], "little") == len(tail)]
    need(len(positions) == 1, "UNIQUE_TERMINAL_EOCD")
    position = positions[0]
    _, disk, cd_disk, on_disk, count, cd_size, cd_offset, comment_size = struct.unpack_from("<4s4H2IH", tail, position)
    need(disk == 0 and cd_disk == 0 and on_disk == count, "MULTI_DISK_ZIP_REFUSED")
    need(0 < count <= 512 and count != 65535 and cd_size != 0xffffffff and cd_offset != 0xffffffff, "ZIP64_OR_MEMBER_BOUND")
    need(cd_offset + cd_size == START + position, "CENTRAL_DIRECTORY_END")
    need(cd_offset >= START and cd_size <= TAIL, "CENTRAL_DIRECTORY_NOT_FULLY_IN_TAIL")
    cursor = cd_offset - START
    end = cursor + cd_size
    rows, seen = [], set()
    for number in range(count):
        need(cursor + 46 <= end, "CENTRAL_HEADER_BOUND")
        fields = struct.unpack_from("<4s6H3I5H2I", tail, cursor)
        sig, made, version, flags, method, mtime, mdate, crc, compressed, expanded, nlen, xlen, clen, member_disk, iattr, eattr, local_offset = fields
        need(sig == b"PK\x01\x02" and member_disk == 0, "CENTRAL_ENTRY_FRAMING")
        need(0 < nlen <= 1024 and cursor + 46 + nlen + xlen + clen <= end, "CENTRAL_ENTRY_LENGTH")
        need(compressed != 0xffffffff and expanded != 0xffffffff and local_offset != 0xffffffff, "ZIP64_ENTRY_REFUSED")
        need(local_offset < cd_offset and not flags & 0x41, "LOCAL_OFFSET_OR_ENCRYPTION_REFUSED")
        name_bytes = tail[cursor + 46:cursor + 46 + nlen]
        name = name_bytes.decode("utf-8" if flags & 0x800 else "cp437")
        need(not any(ord(c) < 32 or ord(c) == 127 for c in name), "CONTROL_CHARACTER_PATH")
        need("\\" not in name and ":" not in name and "\x00" not in name, "UNSAFE_MEMBER_PATH")
        normalized = name[:-1] if name.endswith("/") else name
        path = PurePosixPath(normalized)
        need(normalized and not path.is_absolute() and path.as_posix() == normalized
             and all(part not in ("", ".", "..") for part in path.parts), "TRAVERSAL_MEMBER_PATH")
        need(normalized not in seen, "DUPLICATE_MEMBER_PATH")
        seen.add(normalized)
        filetype = stat.S_IFMT(eattr >> 16)
        need(filetype in (0, stat.S_IFREG, stat.S_IFDIR), "LINK_OR_SPECIAL_MEMBER_REFUSED")
        is_directory = name.endswith("/") or filetype == stat.S_IFDIR
        rows.append({"index": number, "path": name, "compressed_bytes": compressed,
                     "uncompressed_bytes": expanded, "compression_method": method,
                     "crc32_declared_hex": f"{crc:08x}", "crc32_verified": False,
                     "local_header_offset": local_offset, "flags": flags,
                     "directory": is_directory, "version_needed": version,
                     "small_member_candidate_only": (not is_directory and expanded <= 32 * 1024 * 1024
                                                      and compressed <= 16 * 1024 * 1024 and method in (0, 8))})
        cursor += 46 + nlen + xlen + clen
    need(cursor == end, "CENTRAL_DIRECTORY_COUNT_OR_TRAILING_BYTES")
    return {"schema": "trnm-r1-required-protocol-central-directory-tail-observation-v1",
            "artifact_id": ARTIFACT, "complete_central_directory_in_acquired_tail": True,
            "entries": count, "central_directory_offset": cd_offset,
            "central_directory_bytes": cd_size, "eocd_absolute_offset": START + position,
            "zip_comment_bytes": comment_size, "members": rows,
            "whole_artifact_sha256_verified": False, "all_member_crc_verified": False,
            "member_contents_downloaded_or_executed": False}

def extract_record(row, raw):
    need(len(raw)>=30,"LOCAL_HEADER_BOUND")
    sig,version,flags,method,mtime,mdate,crc,compressed,expanded,nlen,xlen=struct.unpack_from("<4s5H3I2H",raw,0)
    need(sig==b"PK\x03\x04" and 0<nlen<=1024 and xlen<=65535,"LOCAL_HEADER_FRAMING")
    need(flags==row["flags"] and method==row["compression_method"],"LOCAL_CENTRAL_FLAGS_METHOD")
    name=raw[30:30+nlen].decode("utf-8"if flags&0x800 else"cp437")
    need(name==row["path"],"LOCAL_CENTRAL_NAME")
    need(not flags&0x41 and method in(0,8),"LOCAL_ENCRYPTION_OR_METHOD")
    expected_crc=int(row["crc32_declared_hex"],16)
    cs,us=row["compressed_bytes"],row["uncompressed_bytes"]
    need(0<=us<=32*1024*1024 and 0<=cs<=4*1024*1024,"MEMBER_SIZE_BOUND")
    begin=30+nlen+xlen;end=begin+cs
    need(end<=len(raw),"LOCAL_COMPRESSED_BODY_BOUND")
    if flags&8:
        need(crc in(0,expected_crc)and compressed in(0,cs)and expanded in(0,us),"DESCRIPTOR_LOCAL_FIELDS")
    else:
        need((crc,compressed,expanded)==(expected_crc,cs,us),"LOCAL_CENTRAL_SIZES_CRC")
    trailing=raw[end:]
    if flags&8:
        need(trailing in(struct.pack("<3I",expected_crc,cs,us),struct.pack("<4s3I",b"PK\x07\x08",expected_crc,cs,us)),"EXACT_DATA_DESCRIPTOR")
    else:need(not trailing,"LOCAL_RECORD_TRAILING_BYTES")
    compressed_raw=raw[begin:end]
    if method==0:data=compressed_raw
    else:
        dec=zlib.decompressobj(-15);data=dec.decompress(compressed_raw,us+1)
        need(len(data)<=us and dec.eof and not dec.unused_data and not dec.unconsumed_tail,"BOUNDED_DEFLATE_COMPLETE")
        data+=dec.flush()
    need(len(data)==us and zlib.crc32(data)&0xffffffff==expected_crc,"SELECTED_MEMBER_SIZE_CRC")
    return data


SELECTED += ["from-zero-native-host/child-result.json","from-zero-native-host/inside-before.json","from-zero-native-host/inside-after.json","from-zero-native-host/outside-after.json","from-zero-native-host/prepare-build.json","from-zero-native-host/systemd-run.log"]
DIRECTORY_PIN = {"path":"/private/tmp/chain-H5DF-arm64-cross-cost-selected-artifact-20261114-v1/directory-v1/summary.json","bytes":6078,"sha256":"71d2ba7895fd2c00303255fbddcd665de79a861aa96b5e4e5646ad6a478587c3"}
def read_pin(p):
    return stable_bytes(Path(p["path"]),p["bytes"],p["sha256"])
def main():
    global START,END,TAIL
    need(sys.flags.optimize==0,"OPTIMIZATION_FORBIDDEN")
    need(BASE.resolve(strict=True)==BASE,"OUTPUT_PARENT")
    directory=parse_json(read_pin(DIRECTORY_PIN))
    need(directory["status"]=="DIRECTORY_VERIFIED_SELECTED_RECORDS_PENDING" and directory["artifact_id"]==ARTIFACT
         and directory["workflow_head"]==HEAD and directory["run_id"]==RUN and directory["run_attempt"]==1
         and directory["declared_archive_sha256"]==DIGEST and directory["declared_archive_bytes"]==SIZE,"DIRECTORY_IDENTITY")
    need(len(directory["steps"])==2 and all(x["complete_transport"]is True and x["exit"]==0 for x in directory["steps"]),"DIRECTORY_ORIGINAL_GETS")
    deadline=directory["monotonic_deadline"]
    need(directory["monotonic_started"]<=time.monotonic()<deadline,"COMBINED_900_SECOND_DEADLINE")
    OUT.mkdir(mode=0o700)
    result={"schema":"trnm-H5DF-arm64-cost-selected-original-artifact-v1","status":"HOLD","started_at":now(),
      "artifact_id":ARTIFACT,"artifact_name":NAME,"run_id":RUN,"run_attempt":1,"job_id":132528769087,
      "workflow_head":HEAD,"expected_subject":SUBJECT,"expected_tree":TREE,"directory_stage":DIRECTORY_PIN,
      "declared_whole_archive_bytes":SIZE,"declared_whole_archive_sha256":DIGEST,"maximum_combined_GETs":MAX_GETS,
      "combined_budget_seconds":TOTAL_BUDGET,"combined_monotonic_deadline":deadline,"per_GET_max_seconds":BUDGET,
      "steps":[],"errors":[],"whole_artifact_sha256_verified":False,"all_artifact_member_crc_verified":False,
      "automatic_retry":False,"manual_redirect_following":False,"signed_URL_raw_headers_auth_cookies_saved":False,
      "qualification":False,"source_refs_stage_CI_modified":False,"inner_code_or_test_executed":False}
    def request(label,a,b):
        global START,END,TAIL
        need(2+len(result["steps"])<MAX_GETS,"COMBINED_GET_COUNT_BOUND")
        START,END=a,b;TAIL=b-a+1
        step,raw=capture(label,"repos/"+REPO+"/actions/artifacts/"+str(ARTIFACT)+"/zip",min(deadline,time.monotonic()+BUDGET),True)
        result["steps"].append(step)
        print(json.dumps({"label":label,"exit":step["exit"],"http_status":step["http_status"],"complete":step["complete_transport"],"body_bytes":len(raw),"error":step["error"]}),flush=True)
        if step["http_status"]==206 and raw:result[label]=save(label+".body"if step["complete_transport"]else label+".body.partial",raw)
        need(step["complete_transport"],"REQUEST_INCOMPLETE:"+label)
        return raw
    try:
        stable_bytes(SOURCE_LOG,SOURCE_BYTES,SOURCE_SHA)
        cd=parse_json(read_pin(directory["central_directory"]));tail=read_pin(directory["tail"])
        tail_start=SIZE-65557;tail_end=SIZE-1
        need(cd["artifact_id"]==ARTIFACT and cd["entries"]==161 and cd["complete_central_directory_in_acquired_tail"]is True,"ACTUAL_PINNED_COST_CD")
        members=sorted(cd["members"],key=lambda x:x["local_header_offset"])
        need(len({r["local_header_offset"]for r in members})==len(members),"DUPLICATE_LOCAL_OFFSET")
        byname={r["path"]:r for r in members}
        need(len(SELECTED)==25 and len(set(SELECTED))==25,"FIXED_ACTUAL_SELECTED_ROSTER")
        spans=[]
        for name in SELECTED:
            need(name in byname,"SELECTED_MEMBER_ABSENT:"+name)
            row=byname[name];need(not row["directory"]and row["small_member_candidate_only"],"SELECTED_MEMBER_TYPE_BOUND")
            i=members.index(row);start=row["local_header_offset"]
            end=(members[i+1]["local_header_offset"]if i+1<len(members)else cd["central_directory_offset"])-1
            need(0<=start<=end<cd["central_directory_offset"],"RECORD_SPAN")
            need(row["compressed_bytes"]+30<=end-start+1<=row["compressed_bytes"]+30+1024+65535+16,"LOCAL_RECORD_RANGE_BOUND")
            spans.append({"path":name,"start":start,"end":end,"bytes":end-start+1,"row":row,
                          "already_in_tail":start>=tail_start and end<=tail_end})
        need(sum(x["bytes"]for x in spans)<=4*1024*1024,"SELECTED_TOTAL_COMPRESSED_BOUND")
        need(sum(x["row"]["uncompressed_bytes"]for x in spans)<=64*1024*1024,"SELECTED_TOTAL_EXPANDED_BOUND")
        pending=sorted([x for x in spans if not x["already_in_tail"]],key=lambda x:x["start"])
        groups=[]
        for span in pending:
            if groups and groups[-1]["end"]+1==span["start"]:
                groups[-1]["end"]=span["end"];groups[-1]["members"].append(span["path"])
            else:groups.append({"start":span["start"],"end":span["end"],"members":[span["path"]]})
        need(2+len(groups)<=MAX_GETS,"PLANNED_GET_BOUND")
        plan={"selected_paths":SELECTED,"records":spans,"new_range_groups":groups,
              "directory_original_GETs":2,"maximum_combined_GETs":MAX_GETS,"actual_planned_combined_GETs":2+len(groups),
              "combined_original_monotonic_deadline":deadline,
              "selected_record_bytes":sum(x["bytes"]for x in spans),
              "selected_expanded_bytes":sum(x["row"]["uncompressed_bytes"]for x in spans),
              "merge_rule":"Only exactly consecutive selected local records; no intervening unselected record",
              "reused_tail_paths":[x["path"]for x in spans if x["already_in_tail"]],
              "unselected_ELF_SQLite_not_requested":True,"whole_ZIP_not_requested":True}
        result["selected_range_plan"]=save_json("selected-range-plan.json",plan)
        print(json.dumps({"phase":"selected_plan_fixed","selected_members":len(SELECTED),"actual_planned_combined_GETs":2+len(groups),
          "selected_record_bytes":plan["selected_record_bytes"],"selected_expanded_bytes":plan["selected_expanded_bytes"],"plan":result["selected_range_plan"]}),flush=True)
        buffers=[(tail_start,tail_end,tail,"directory-v1/tail")]
        for i,group in enumerate(groups,1):
            label="selected-range-"+str(i).zfill(2)
            data=request(label,group["start"],group["end"])
            buffers.append((group["start"],group["end"],data,label))
        verified=[]
        for span in spans:
            candidates=[v for v in buffers if v[0]<=span["start"]and v[1]>=span["end"]]
            need(candidates,"SELECTED_RANGE_NOT_COVERED")
            a,b,record,label=candidates[0]
            data=extract_record(span["row"],record[span["start"]-a:span["end"]-a+1])
            destination=OUT/"members"/span["path"];destination.parent.mkdir(parents=True,exist_ok=True)
            proof=save("members/"+span["path"],data)
            verified.append({"path":span["path"],"bytes":len(data),"sha256":proof["sha256"],
                "crc32":span["row"]["crc32_declared_hex"],"crc32_verified":True,
                "compressed_bytes":span["row"]["compressed_bytes"],"original":proof,
                "range_source":label,"origin":"https://github.com/"+REPO+"/actions/runs/"+str(RUN)+"/artifacts/"+str(ARTIFACT)+"#"+span["path"]})
        need(len(verified)==25,"EXACT_SELECTED_COMPLETION")
        result["selected_members"]=save_json("selected-member-index.json",{"artifact_id":ARTIFACT,"files":verified,"count":len(verified),"selected_member_crc_sha_verified":True,"whole_artifact_sha256_verified":False,"all_artifact_member_crc_verified":False})
        result["selected_member_crc_sha_verified"]=True
        manifest=parse_json((OUT/"members/from-zero-native/manifest.json").read_bytes())
        result["manifest_outcome"]={k:manifest.get(k)for k in("schema","passed","failures","all_named_tests_passed","format_passed","source_recompiled","execution_finished","production_activation","independent_wan_accepted","work_hardness_accepted")}
        result["manifest_source_identity"]={k:manifest.get(k)for k in("source_before","source_after","binary_sha256_before","binary_sha256_after")}
        result["status"]="SELECTED_ORIGINAL_MEMBERS_VERIFIED"
        read_pin(DIRECTORY_PIN);read_pin(directory["central_directory"]);read_pin(directory["tail"])
        stable_bytes(SOURCE_LOG,SOURCE_BYTES,SOURCE_SHA)
    except Exception as error:
        result["errors"].append(str(error)if isinstance(error,ValueError)else type(error).__name__)
    finally:
        result["finished_at"]=now();result["combined_elapsed_seconds"]=round(time.monotonic()-directory["monotonic_started"],6)
        raw=Path(__file__).read_bytes()
        result["producer"]={"path":str(Path(__file__).resolve()),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        result["actual_new_GETs"]=len(result["steps"]);result["actual_combined_GETs"]=2+len(result["steps"])
        summary=save_json("summary.json",result);files=[]
        for p in sorted(OUT.rglob("*")):
            if p.is_file():
                r=p.read_bytes();files.append({"path":str(p),"bytes":len(r),"sha256":hashlib.sha256(r).hexdigest()})
        index=save_json("EVIDENCE_INDEX.json",{"files":files,"count":len(files),"bytes":sum(x["bytes"]for x in files),"self_excluded":True})
        print(json.dumps({"status":result["status"],"summary":summary,"index":index,"actual_combined_GETs":result["actual_combined_GETs"],
          "manifest_outcome":result.get("manifest_outcome"),"whole_artifact_sha256_verified":False,"qualification":False}),flush=True)
    return 0 if result["status"]=="SELECTED_ORIGINAL_MEMBERS_VERIFIED"else 1
if __name__=="__main__":raise SystemExit(main())
