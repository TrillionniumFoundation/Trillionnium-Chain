from pathlib import Path
import json
SPECS=json.loads("[{\"name\":\"owner\",\"directory\":\"/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-owner-01\",\"manifest_sha\":\"5a5b7d7ef41a5cf4f5429ef420326777706aae54e4bd88eabf83658530b85b3f\",\"expected_commands\":19,\"expected_exit\":{},\"plan\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/owner-plan.json\",\"driver\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/qualify_c6.py\"},{\"name\":\"core-attempt-01\",\"directory\":\"/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-ci-core-01\",\"manifest_sha\":\"6d357aaea2673fa6952dd648d39b0aac38759ce31b5e945d06b9805a84d11b29\",\"expected_commands\":19,\"expected_exit\":{\"14-w1-retained-staged-tests\":1},\"plan\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/ci-core-plan.json\",\"driver\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/qualify_c6.py\"},{\"name\":\"native\",\"directory\":\"/home/qian-qi/work/chain-w1-c6-native-qualification-20261108-ec265b-01\",\"manifest_sha\":\"1a7bec56da77f9d0fc0fc647adb618f705c42f03e7e40c2728773cc55844e352\",\"expected_commands\":10,\"expected_exit\":{}},{\"name\":\"receiver\",\"directory\":\"/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b/exact-receiver-01\",\"manifest_sha\":\"e0109e80fbc0eb48f44fd5d91197d1b68c5476622a1408e8f9c9da8b9b820cdc\",\"expected_commands\":4,\"expected_exit\":{},\"plan\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/receiver-plan.json\",\"driver\":\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b/qualify_receiver_c6.py\"}]")
for spec in SPECS:
    for key in ('directory','plan','driver'):
        if key in spec:spec[key]=Path(spec[key])
TERMINALS=json.loads("{\"owner-terminal.json\":\"{\\n  \\\"at_unix_ms\\\": 1794119876503,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1b9cc0794-12894-16f1\\\",\\n  \\\"launch_nonce\\\": \\\"b840d2ae1ceb340223b8eba9c450e4f5\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 2174,\\n      \\\"stored\\\": 2174\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"core-terminal.json\":\"{\\n  \\\"at_unix_ms\\\": 1794120212556,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 1,\\n  \\\"job_id\\\": \\\"1a1b9c9a486-12894-16e2\\\",\\n  \\\"launch_nonce\\\": \\\"f0e7e323d76f7fbcce1a6594c02e598f\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 2164,\\n      \\\"stored\\\": 2164\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"failed\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"native-terminal.json\":\"{\\n  \\\"at_unix_ms\\\": 1794119876950,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1b9d1f3a4-12894-1714\\\",\\n  \\\"launch_nonce\\\": \\\"d9d05629477cf4ac97b5048a0b94e493\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 3284,\\n      \\\"stored\\\": 3284\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"owner\":\"{\\n  \\\"at_unix_ms\\\": 1794119876503,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1b9cc0794-12894-16f1\\\",\\n  \\\"launch_nonce\\\": \\\"b840d2ae1ceb340223b8eba9c450e4f5\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 2174,\\n      \\\"stored\\\": 2174\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"core-attempt-01\":\"{\\n  \\\"at_unix_ms\\\": 1794120212556,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 1,\\n  \\\"job_id\\\": \\\"1a1b9c9a486-12894-16e2\\\",\\n  \\\"launch_nonce\\\": \\\"f0e7e323d76f7fbcce1a6594c02e598f\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 2164,\\n      \\\"stored\\\": 2164\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"failed\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"native\":\"{\\n  \\\"at_unix_ms\\\": 1794119876950,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1b9d1f3a4-12894-1714\\\",\\n  \\\"launch_nonce\\\": \\\"d9d05629477cf4ac97b5048a0b94e493\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 3284,\\n      \\\"stored\\\": 3284\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\",\"receiver\":\"{\\n  \\\"at_unix_ms\\\": 1794120649209,\\n  \\\"audit_recorded\\\": true,\\n  \\\"automatic_retry\\\": false,\\n  \\\"cancelled\\\": false,\\n  \\\"exit_code\\\": 0,\\n  \\\"job_id\\\": \\\"1a1b9e7a8dc-12894-178e\\\",\\n  \\\"launch_nonce\\\": \\\"155e17c6d4b47a1fbf0a5bf1479e744d\\\",\\n  \\\"log_bytes\\\": {\\n    \\\"stderr\\\": {\\n      \\\"seen\\\": 0,\\n      \\\"stored\\\": 0\\n    },\\n    \\\"stdout\\\": {\\n      \\\"seen\\\": 1394,\\n      \\\"stored\\\": 1394\\n    }\\n  },\\n  \\\"log_errors\\\": {\\n    \\\"stderr\\\": null,\\n    \\\"stdout\\\": null\\n  },\\n  \\\"log_synced\\\": {\\n    \\\"stderr\\\": true,\\n    \\\"stdout\\\": true\\n  },\\n  \\\"log_truncated\\\": {\\n    \\\"stderr\\\": false,\\n    \\\"stdout\\\": false\\n  },\\n  \\\"output_complete\\\": true,\\n  \\\"output_durable\\\": true,\\n  \\\"state\\\": \\\"succeeded\\\",\\n  \\\"terminal_publication_confirmed\\\": true,\\n  \\\"terminal_publication_protocol\\\": 1,\\n  \\\"timed_out\\\": false\\n}\"}")
AUDIT_DRIVER="#!/usr/bin/env python3\n\"\"\"Read-only independent audit of completed C6 qualification records.\nWrites only a new external review directory. Does not run tests, Cargo, Node,\nsource guards or operation drivers. Raw files are included by explicit allowlist.\n\"\"\"\nimport base64, collections, gzip, hashlib, io, json, os, re, stat, tarfile\nfrom pathlib import Path\n\nC6 = \"2bdd252aa6c300b7431b9ee897b254b7953cf562\"\nTREE = \"ac3cb7171c429fa5e12e29ee16839fa6f49f1b81\"\nROOT = Path(\"/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b\")\nTOOLS = Path(\"/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b\")\nMTOOLS = Path(\"/home/qian-qi/work/chain-w1-base62-m12-tools-20261108-ec265b\")\nREPO = Path(\"/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b\")\nDEST = Path(\"/home/qian-qi/work/chain-w1-base62-adversarial-review-20261108-ec265b/completed-components-01\")\nSOURCE_SHA = \"2edd14596053103164150807856703c7fac8d4fd5ade634f8acc7203a35025e4\"\nMAX_FILE = 24*1024*1024\n\ndef digest(b):\n    return hashlib.sha256(b).hexdigest()\n\ndef read_stable(path, max_bytes=MAX_FILE):\n    path = Path(path)\n    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)\n    try:\n        before = os.fstat(fd)\n        assert stat.S_ISREG(before.st_mode), (\"not regular\", str(path))\n        assert before.st_size <= max_bytes, (\"too large\", str(path), before.st_size)\n        chunks = []\n        remaining = max_bytes + 1\n        while remaining:\n            b = os.read(fd, min(1048576, remaining))\n            if not b: break\n            chunks.append(b); remaining -= len(b)\n        data = b\"\".join(chunks)\n        after = os.fstat(fd)\n        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)\n        assert fields(before) == fields(after), (\"mutated while reading\", str(path))\n        assert len(data) == after.st_size and len(data) <= max_bytes\n        return data\n    finally:\n        os.close(fd)\n\ndef jload(b):\n    def pairs(items):\n        out = {}\n        for k,v in items:\n            assert k not in out, (\"duplicate key\", k)\n            out[k] = v\n        return out\n    return json.loads(b.decode(\"utf-8\"), object_pairs_hook=pairs,\n                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))\n\ndef dump(v):\n    return (json.dumps(v, ensure_ascii=False, sort_keys=True, indent=2)+\"\\n\").encode()\n\ndef put(path, data):\n    with path.open(\"xb\") as f:\n        f.write(data)\n\npy_rx = re.compile(r\"^Ran ([0-9]+) tests? in ([^\\n]+)\\n\\n(OK(?: \\([^\\n]*\\))?|FAILED \\([^\\n]*\\))$\", re.M)\nrust_rx = re.compile(r\"^test result: (ok|FAILED)\\. (\\d+) passed; (\\d+) failed; (\\d+) ignored; (\\d+) measured; (\\d+) filtered out; finished in ([^\\n]+)$\", re.M)\n\ndef outcomes(text):\n    py = []\n    runs = re.findall(r\"^Ran ([0-9]+) tests? in \", text, re.M)\n    for m in py_rx.finditer(text):\n        fields = {k:int(v) for k,v in re.findall(r\"([A-Za-z ]+)=(\\d+)\", m[3])}\n        assert not set(fields) - {\"failures\",\"errors\",\"skipped\",\"expected failures\",\"unexpected successes\"}, fields\n        total = int(m[1])\n        failed, errors, skipped = (fields.get(k,0) for k in (\"failures\",\"errors\",\"skipped\"))\n        assert fields.get(\"expected failures\",0) == fields.get(\"unexpected successes\",0) == 0\n        py.append({\"reported_methods\":total, \"passed\":total-failed-errors-skipped,\n                   \"failed\":failed, \"errors\":errors, \"skipped\":skipped, \"terminal\":m[3],\n                   \"reported_duration\":m[2]})\n    assert [str(x[\"reported_methods\"]) for x in py] == runs, (\"unparsed unittest summary\",runs,py)\n    rust=[]\n    for m in rust_rx.finditer(text):\n        rust.append(dict(zip((\"passed\",\"failed\",\"ignored\",\"measured\",\"filtered_out\"),map(int,m.group(2,3,4,5,6))))|{\"terminal\":m[1],\"reported_duration\":m[7]})\n    named = [{\"name\":m[1],\"outcome\":m[2]} for m in re.finditer(r\"^test (\\S+) \\.\\.\\. (ok|FAILED|ignored(?:[^\\n]*))$\",text,re.M)]\n    if rust:\n        assert len(rust)==1\n        counts=collections.Counter(\"ignored\" if x[\"outcome\"].startswith(\"ignored\") else x[\"outcome\"] for x in named)\n        assert [counts[\"ok\"],counts[\"FAILED\"],counts[\"ignored\"]] == [rust[0][\"passed\"],rust[0][\"failed\"],rust[0][\"ignored\"]]\n    return {\"python\":py,\"rust\":rust,\"named_rust\":named}\n\ndef archive_raw(dest, raw, index):\n    out=io.BytesIO()\n    with gzip.GzipFile(fileobj=out,mode=\"wb\",mtime=0) as gz:\n        with tarfile.open(fileobj=gz,mode=\"w\") as tar:\n            for name,data in sorted(raw.items()):\n                assert not name.startswith(\"/\") and \"..\" not in Path(name).parts\n                ti=tarfile.TarInfo(name);ti.size=len(data);ti.mode=0o644;ti.mtime=0\n                tar.addfile(ti,io.BytesIO(data))\n    b=out.getvalue()\n    assert len(b) < MAX_FILE\n    put(dest/\"raw-logs.tar.gz\",b)\n    put(dest/\"raw-output-index.json\",dump(index))\n    return {\"bytes\":len(b),\"sha256\":digest(b),\"members\":len(raw)}\n\ndef audit(name, directory, manifest_sha, expected_commands, expected_exit, plan=None, driver=None):\n    dest=DEST/name;dest.mkdir()\n    raw={};index=[]\n    def add(path, rel=None, pin=None):\n        path=Path(path);data=read_stable(path)\n        if pin:\n            assert digest(data)==pin[\"sha256\"], (\"digest mismatch\",str(path))\n            if \"bytes\" in pin: assert len(data)==pin[\"bytes\"], (\"size mismatch\",str(path))\n        rel=rel or path.name\n        assert rel not in raw, (\"duplicate archive name\",rel)\n        raw[rel]=data;index.append({\"archive_member\":rel,\"original_path\":str(path),\"bytes\":len(data),\"sha256\":digest(data)})\n        return data\n    mb=add(directory/\"manifest.json\",pin={\"sha256\":manifest_sha})\n    m=jload(mb);commands=m[\"commands\"]\n    assert len(commands)==expected_commands\n    assert m.get(\"actual_command_count\",len(commands))==len(commands)\n    source=m.get(\"source\",{\"commit\":m.get(\"source_commit\"),\"tree\":m.get(\"source_tree\")})\n    assert source=={\"commit\":C6,\"tree\":TREE}\n    assert m[\"repo\"]==str(REPO)\n    if driver:\n        db=add(driver,\"provenance/\"+driver.name,{\"sha256\":m[\"driver_sha256\"]})\n        assert len(db)>0\n    if plan:\n        pb=add(plan,\"provenance/\"+plan.name,{\"sha256\":m[\"plan_sha256\"]})\n        p=jload(pb)\n        expanded=[{\"label\":f\"{i:02d}-\"+item[\"label\"],\"argv\":[v.replace(\"@REPO@\",str(REPO)).replace(\"@OUT@\",str(directory)).replace(\"@HEAD@\",C6) for v in item[\"argv\"]],\"cwd\":str(REPO/item.get(\"cwd\",\"\"))} for i,item in enumerate(p[\"commands\"],2)]\n        assert len(expanded)==len(commands)-3\n        for declared,actual in zip(expanded,commands[2:-1]):\n            assert all(actual[k]==declared[k] for k in declared), (\"plan differs\",declared[\"label\"])\n    before=add(directory/\"source-before.json\",pin={\"sha256\":SOURCE_SHA})\n    after=add(directory/\"source-after.json\",pin={\"sha256\":SOURCE_SHA})\n    assert before==after\n    sg=jload(before)\n    assert sg[\"tested_commit\"]==C6 and sg[\"tested_tree\"]==TREE and sg[\"tracked_worktree_verified\"] is True\n    assert sg[\"tests_executed_by_identity_check\"] is False\n    rows=[];py_total=collections.Counter();rust_total=collections.Counter()\n    all_labels=[]\n    for c in commands:\n        label=c[\"label\"];assert label not in all_labels;all_labels.append(label)\n        assert type(c[\"exit\"]) is int\n        assert c[\"exit\"]==expected_exit.get(label,0), (\"unexpected actual exit\",label,c[\"exit\"])\n        if \"started_monotonic_ns\" in c:\n            assert type(c[\"started_monotonic_ns\"]) is int and type(c[\"finished_monotonic_ns\"]) is int\n            assert c[\"finished_monotonic_ns\"]>=c[\"started_monotonic_ns\"]\n        streams={}\n        for stream in (\"stdout\",\"stderr\"):\n            pin=c[stream];path=Path(pin[\"path\"])\n            assert path.parent==directory and path.name==label+\".\"+stream\n            streams[stream]=add(path,pin=pin)\n        combined=(streams[\"stdout\"]+b\"\\n\"+streams[\"stderr\"]).decode(\"utf-8\")\n        o=outcomes(combined)\n        assert c.get(\"python_test_counts\",[x[\"reported_methods\"] for x in o[\"python\"]])==[x[\"reported_methods\"] for x in o[\"python\"]]\n        assert c.get(\"rust_test_outcomes\",[{k:r[k] for k in (\"passed\",\"failed\",\"ignored\")} for r in o[\"rust\"]])==[{k:r[k] for k in (\"passed\",\"failed\",\"ignored\")} for r in o[\"rust\"]]\n        for x in o[\"python\"]:\n            for k in (\"reported_methods\",\"passed\",\"failed\",\"errors\",\"skipped\"):py_total[k]+=x[k]\n        for x in o[\"rust\"]:\n            for k in (\"passed\",\"failed\",\"ignored\"):rust_total[k]+=x[k]\n        rows.append({\"label\":label,\"argv\":c[\"argv\"],\"cwd\":c[\"cwd\"],\"exit\":c[\"exit\"],\"outcomes\":o})\n    assert m.get(\"python_test_methods_reported\",py_total[\"reported_methods\"])==py_total[\"reported_methods\"]\n    assert m.get(\"rust_test_outcomes\",dict(rust_total))=={k:rust_total[k] for k in (\"passed\",\"failed\",\"ignored\")} or (not rust_total and m.get(\"rust_test_outcomes\")=={\"passed\":0,\"failed\":0,\"ignored\":0})\n    extras={}\n    if name==\"owner\":\n        prep=jload(add(ROOT/\"owner-empty-target-preparation-01/preparation.json\",\"provenance/owner-empty-target-preparation.json\",{\"sha256\":\"55f18f4e02646b013dd87e47d7e86291068edc59f85036fe87433c3a831d8fe7\"}))\n        launch=jload(add(ROOT/\"owner-launch-binding.json\",\"provenance/owner-launch-binding.json\",{\"sha256\":\"828ac5d0226a593c96ce67524494a6127346add34c50c9e92c251ff87f6b4aa8\"}))\n        artifact=jload(add(ROOT/\"owner-artifact.json\",\"provenance/owner-artifact.json\",{\"sha256\":\"3ab195ababccc9aa2abfffde5527227f81cc52e6a1d6abe09068d4fb7b79aeed\"}))\n        assert prep[\"target_preexisted\"] is False and prep[\"target_entries\"]==prep[\"target_files\"]==0\n        assert launch[\"empty_observed_before_exec\"] is True and launch[\"preparation_sha256\"]==digest(raw[\"provenance/owner-empty-target-preparation.json\"])\n        assert launch[\"source\"]==C6 and launch[\"target\"]==prep[\"target\"]==m[\"cargo_target\"]\n        assert launch[\"target_inode\"]==prep[\"target_inode\"] and launch[\"target_device\"]==prep[\"target_device\"]\n        assert artifact[\"source_commit\"]==C6 and artifact[\"source_tree\"]==TREE\n        assert artifact[\"qualification_manifest\"][\"sha256\"]==manifest_sha\n        compiler=raw[\"13-owner-no-run-json.stdout\"]\n        assert artifact[\"compiler_artifact_stdout\"][\"sha256\"]==digest(compiler)\n        records=[jload(x) for x in compiler.splitlines() if x]\n        exe=artifact[\"owner_executable\"]\n        selected=[x for x in records if x.get(\"reason\")==\"compiler-artifact\" and x.get(\"executable\")==exe[\"path\"]]\n        assert len(selected)==1\n        a=selected[0]\n        assert a[\"target\"][\"name\"]==\"trnm_pon_node\" and a[\"profile\"][\"test\"] is True\n        assert Path(a[\"manifest_path\"]).is_relative_to(REPO) and Path(a[\"target\"][\"src_path\"]).is_relative_to(REPO)\n        st=Path(exe[\"path\"]).stat()\n        observed={\"bytes\":st.st_size,\"device\":st.st_dev,\"inode\":st.st_ino,\"mtime_ns\":st.st_mtime_ns,\"nlink\":st.st_nlink}\n        assert all(observed[k]==exe[k] for k in observed)\n        extras={\"empty_target_preparation_and_launch_binding_match\":True,\n                \"compiler_artifact_matches_owner_receipt\":True,\"owner_elf_current_stat_matches\":observed,\n                \"owner_elf_sha256_recorded_by_original_receipt\":exe[\"sha256\"],\n                \"owner_elf_sha256_independently_recomputed_in_this_audit\":False,\n                \"limitation\":\"468 MB owner ELF not reread during other qualification I/O; no ELF copied. Original launcher empty-target receipt checked; this is not an independent reproducible build.\"}\n    elif name==\"core-attempt-01\":\n        block=add(directory/\"w1-current-command-block.sh\",pin={\"sha256\":m[\"ci_command_block_sha256\"]})\n        names=[\"cancellation-handoff\",\"coordinator-contract\",\"provider-contract\",\"generation-target\",\"owner-cancellation\",\"source-builder\",\"owned-runtime-reader\",\"kaggle-worker-contract\",\"winner-identity\",\"deployment-evidence-binding\",\"deployment-comparison-audit\",\"owned-process-collector\"]\n        for leaf in names:\n            add(directory/\"ci-receipts\"/\"w1-postwin-contracts\"/(leaf+\".log\"),\"w1-retained/\"+leaf+\".log\")\n        extras={\"staged_original_methods\":32,\"staged_passed\":30,\"staged_failed\":2,\n          \"staged_failure_reason\":\"DEADLINE_EXHAUSTED_BEFORE_SPAWN\",\n          \"output_limit_subcase_after_sigkill_assertion_executed\":False,\n          \"fixture_budgets_seconds\":[0.15,0.2],\n          \"actual_default_termination_grace_seconds\":5,\n          \"failure_cause_attributed_to_host_contention\":False,\n          \"first_attempt_success\":False,\"isolated_followup_not_substituted\":True}\n    elif name==\"native\":\n        decl=jload(add(directory/\"declaration.json\",pin={\"sha256\":\"ad0205296ea144fbdf36fce756db3cad418b94fd873a8e72793468a48393f976\"}))\n        add(Path(decl[\"driver\"][\"path\"]),\"provenance/native-qualify-empty-v3.py\",decl[\"driver\"])\n        prep=jload(add(Path(m[\"target_preparation\"][\"path\"]),\"provenance/native-empty-preparation-03.json\",m[\"target_preparation\"]))\n        assert prep[\"initial_entries\"]==[] and prep[\"copied_artifacts\"] is False\n        assert prep[\"destination\"]==m[\"target\"]\n        binary_bindings={}\n        for role,b in m[\"binaries\"].items():\n            build_data=raw[Path(b[\"build_log\"][\"path\"]).name]\n            records=[jload(x) for x in build_data.splitlines() if x]\n            selected=[x for x in records if x.get(\"reason\")==\"compiler-artifact\" and x.get(\"executable\")==b[\"file\"][\"path\"]]\n            assert len(selected)==1 and selected[0]==b[\"cargo_artifact\"]\n            assert selected[0][\"profile\"][\"test\"] is False\n            data=read_stable(Path(b[\"file\"][\"path\"]))\n            assert len(data)==b[\"file\"][\"bytes\"] and digest(data)==b[\"file\"][\"sha256\"]\n            binary_bindings[role]={\"path\":b[\"file\"][\"path\"],\"bytes\":len(data),\"sha256\":digest(data),\"independently_rehashed\":True,\"copied\":False,\"cargo_fresh\":selected[0][\"fresh\"]}\n        extras={\"binary_bindings\":binary_bindings,\"fresh_target_receipt_matches\":True,\n                \"declared_empty_target_assertion_in_executed_driver\":True,\n                \"registry_cache_and_toolchain_reused\":True,\"independent_cleanroom_build\":False,\n                \"native_historical_243_not_rerun\":True,\"commands\":10,\"preparation_receipt_not_counted_as_command\":True}\n    elif name==\"receiver\":\n        native_manifest=read_stable(Path(m[\"native_build_manifest\"][\"path\"]))\n        assert digest(native_manifest)==m[\"native_build_manifest\"][\"sha256\"]\n        native=jload(native_manifest)\n        c=next(c for c in commands if c[\"label\"]==\"02-real-receiver-controls\")\n        argv=c[\"argv\"]\n        assert argv[argv.index(\"--verifier\")+1]==native[\"binaries\"][\"verifier\"][\"file\"][\"path\"]\n        assert argv[argv.index(\"--verifier-sha256\")+1]==native[\"binaries\"][\"verifier\"][\"file\"][\"sha256\"]\n        extras={\"native_build_binding_matches\":True,\"actual_original_receipt_used\":True,\n                \"new_receipts_generated\":0,\"winning_node_admission_established\":False}\n    terminal_raw=TERMINALS[name]\n    raw[\"durable-job-terminal.json\"]=terminal_raw.encode()\n    index.append({\"archive_member\":\"durable-job-terminal.json\",\"original_path\":\"hepta-runtime authoritative process_status\",\"bytes\":len(raw[\"durable-job-terminal.json\"]),\"sha256\":digest(raw[\"durable-job-terminal.json\"])})\n    t=jload(raw[\"durable-job-terminal.json\"])\n    assert t[\"output_complete\"] is True and t[\"output_durable\"] is True and t[\"timed_out\"] is False\n    assert t[\"exit_code\"]==(1 if name==\"core-attempt-01\" else 0)\n    summary={\"schema\":\"TRNM-W1-C6-INDEPENDENT-COMPONENT-REVIEW1\",\"component\":name,\n             \"source\":{\"commit\":C6,\"tree\":TREE},\"original_manifest_sha256\":manifest_sha,\n             \"actual_command_count\":len(commands),\"actual_nonzero_commands\":[c[\"label\"] for c in commands if c[\"exit\"]!=0],\n             \"source_guards_before_after_exact_equal\":True,\"all_bound_outputs_match\":True,\n             \"python\":dict(py_total),\"rust\":dict(rust_total),\"command_reviews\":rows,\n             \"provenance\":extras,\"durable_job_id\":t[\"job_id\"],\"durable_exit\":t[\"exit_code\"],\n             \"qualifier_claimed_complete\":m[\"qualification_complete\"],\"audit_reran_tests\":False,\n             \"audit_reran_whole_source_guard\":False,\"audit_started_operation\":False,\n             \"new_complete_proofs\":0,\"overall_c6_qualification_complete\":False}\n    put(dest/\"summary.json\",dump(summary))\n    arc=archive_raw(dest,raw,index)\n    files=[]\n    for p in sorted(dest.iterdir()):\n        if p.is_file():\n            b=p.read_bytes();files.append({\"path\":p.name,\"bytes\":len(b),\"sha256\":digest(b)})\n    put(dest/\"manifest.json\",dump({\"schema\":\"TRNM-W1-PUBLIC-COMPONENT-ARCHIVE1\",\"component\":name,\"files\":files,\n        \"scope\":\"explicit raw logs, manifests and safe provenance; no ELF, SQLite, environment dump, state tree or credentials\"}))\n    print(json.dumps({\"component\":name,\"commands\":len(commands),\"python\":dict(py_total),\"rust\":dict(rust_total),\n                      \"manifest_sha256\":digest((dest/\"manifest.json\").read_bytes()),\"raw_archive\":arc}),flush=True)\n    return summary\n\nDEST.parent.mkdir(parents=True,exist_ok=True)\nDEST.mkdir()\nreports=[]\nfor spec in SPECS:\n    reports.append(audit(**spec))\nput(DEST/\"audit-driver.py\",AUDIT_DRIVER)\nput(DEST/\"scope.json\",dump({\"source_commit\":C6,\"source_tree\":TREE,\"completed_components_audited\":[r[\"component\"] for r in reports],\n    \"first_core_attempt_failed\":True,\"overall_qualification_complete\":False,\n    \"pending\":\"backend attempts, sole isolated staged32 followup and later operation audited separately\",\n    \"original_staged_failure_and_unexecuted_subcase_preserved\":True,\n    \"no_tests_or_operations_run_by_audit\":True,\"no_source_worktree_writes\":True}))\nprint(json.dumps({\"external_review_directory\":str(DEST),\"completed\":True,\"overall_c6_qualification_complete\":False}),flush=True)\n".encode()
#!/usr/bin/env python3
"""Read-only independent audit of completed C6 qualification records.
Writes only a new external review directory. Does not run tests, Cargo, Node,
source guards or operation drivers. Raw files are included by explicit allowlist.
"""
import base64, collections, gzip, hashlib, io, json, os, re, stat, tarfile
from pathlib import Path

C6 = "2bdd252aa6c300b7431b9ee897b254b7953cf562"
TREE = "ac3cb7171c429fa5e12e29ee16839fa6f49f1b81"
ROOT = Path("/home/qian-qi/work/chain-w1-base62-validation-20261108-ec265b")
TOOLS = Path("/home/qian-qi/work/chain-w1-base62-integration-tools-20261108-ec265b")
MTOOLS = Path("/home/qian-qi/work/chain-w1-base62-m12-tools-20261108-ec265b")
REPO = Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
DEST = Path("/home/qian-qi/work/chain-w1-base62-adversarial-review-20261108-ec265b/completed-components-01")
SOURCE_SHA = "2edd14596053103164150807856703c7fac8d4fd5ade634f8acc7203a35025e4"
MAX_FILE = 24*1024*1024

def digest(b):
    return hashlib.sha256(b).hexdigest()

def read_stable(path, max_bytes=MAX_FILE):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode), ("not regular", str(path))
        assert before.st_size <= max_bytes, ("too large", str(path), before.st_size)
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            b = os.read(fd, min(1048576, remaining))
            if not b: break
            chunks.append(b); remaining -= len(b)
        data = b"".join(chunks)
        after = os.fstat(fd)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(before) == fields(after), ("mutated while reading", str(path))
        assert len(data) == after.st_size and len(data) <= max_bytes
        return data
    finally:
        os.close(fd)

def jload(b):
    def pairs(items):
        out = {}
        for k,v in items:
            assert k not in out, ("duplicate key", k)
            out[k] = v
        return out
    return json.loads(b.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def dump(v):
    return (json.dumps(v, ensure_ascii=False, sort_keys=True, indent=2)+"\n").encode()

def put(path, data):
    with path.open("xb") as f:
        f.write(data)

py_rx = re.compile(r"^Ran ([0-9]+) tests? in ([^\n]+)\n\n(OK(?: \([^\n]*\))?|FAILED \([^\n]*\))$", re.M)
rust_rx = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([^\n]+)$", re.M)

def outcomes(text):
    py = []
    runs = re.findall(r"^Ran ([0-9]+) tests? in ", text, re.M)
    for m in py_rx.finditer(text):
        fields = {k:int(v) for k,v in re.findall(r"([A-Za-z ]+)=(\d+)", m[3])}
        assert not set(fields) - {"failures","errors","skipped","expected failures","unexpected successes"}, fields
        total = int(m[1])
        failed, errors, skipped = (fields.get(k,0) for k in ("failures","errors","skipped"))
        assert fields.get("expected failures",0) == fields.get("unexpected successes",0) == 0
        py.append({"reported_methods":total, "passed":total-failed-errors-skipped,
                   "failed":failed, "errors":errors, "skipped":skipped, "terminal":m[3],
                   "reported_duration":m[2]})
    assert [str(x["reported_methods"]) for x in py] == runs, ("unparsed unittest summary",runs,py)
    rust=[]
    for m in rust_rx.finditer(text):
        rust.append(dict(zip(("passed","failed","ignored","measured","filtered_out"),map(int,m.group(2,3,4,5,6))))|{"terminal":m[1],"reported_duration":m[7]})
    named = [{"name":m[1],"outcome":m[2]} for m in re.finditer(r"^test (\S+) \.\.\. (ok|FAILED|ignored(?:[^\n]*))$",text,re.M)]
    if rust:
        assert len(rust)==1
        counts=collections.Counter("ignored" if x["outcome"].startswith("ignored") else x["outcome"] for x in named)
        assert [counts["ok"],counts["FAILED"],counts["ignored"]] == [rust[0]["passed"],rust[0]["failed"],rust[0]["ignored"]]
    return {"python":py,"rust":rust,"named_rust":named}

def archive_raw(dest, raw, index):
    out=io.BytesIO()
    with gzip.GzipFile(fileobj=out,mode="wb",mtime=0) as gz:
        with tarfile.open(fileobj=gz,mode="w") as tar:
            for name,data in sorted(raw.items()):
                assert not name.startswith("/") and ".." not in Path(name).parts
                ti=tarfile.TarInfo(name);ti.size=len(data);ti.mode=0o644;ti.mtime=0
                tar.addfile(ti,io.BytesIO(data))
    b=out.getvalue()
    assert len(b) < MAX_FILE
    put(dest/"raw-logs.tar.gz",b)
    put(dest/"raw-output-index.json",dump(index))
    return {"bytes":len(b),"sha256":digest(b),"members":len(raw)}

def audit(name, directory, manifest_sha, expected_commands, expected_exit, plan=None, driver=None):
    dest=DEST/name;dest.mkdir()
    raw={};index=[]
    def add(path, rel=None, pin=None):
        path=Path(path);data=read_stable(path)
        if pin:
            assert digest(data)==pin["sha256"], ("digest mismatch",str(path))
            if "bytes" in pin: assert len(data)==pin["bytes"], ("size mismatch",str(path))
        rel=rel or path.name
        assert rel not in raw, ("duplicate archive name",rel)
        raw[rel]=data;index.append({"archive_member":rel,"original_path":str(path),"bytes":len(data),"sha256":digest(data)})
        return data
    mb=add(directory/"manifest.json",pin={"sha256":manifest_sha})
    m=jload(mb);commands=m["commands"]
    assert len(commands)==expected_commands
    assert m.get("actual_command_count",len(commands))==len(commands)
    source=m.get("source",{"commit":m.get("source_commit"),"tree":m.get("source_tree")})
    assert source=={"commit":C6,"tree":TREE}
    assert m["repo"]==str(REPO)
    if driver:
        db=add(driver,"provenance/"+driver.name,{"sha256":m["driver_sha256"]})
        assert len(db)>0
    if plan:
        pb=add(plan,"provenance/"+plan.name,{"sha256":m["plan_sha256"]})
        p=jload(pb)
        expanded=[{"label":f"{i:02d}-"+item["label"],"argv":[v.replace("@REPO@",str(REPO)).replace("@OUT@",str(directory)).replace("@HEAD@",C6) for v in item["argv"]],"cwd":str(REPO/item.get("cwd",""))} for i,item in enumerate(p["commands"],2)]
        assert len(expanded)==len(commands)-3
        for declared,actual in zip(expanded,commands[2:-1]):
            assert all(actual[k]==declared[k] for k in declared), ("plan differs",declared["label"])
    before=add(directory/"source-before.json",pin={"sha256":SOURCE_SHA})
    after=add(directory/"source-after.json",pin={"sha256":SOURCE_SHA})
    assert before==after
    sg=jload(before)
    assert sg["tested_commit"]==C6 and sg["tested_tree"]==TREE and sg["tracked_worktree_verified"] is True
    assert sg["tests_executed_by_identity_check"] is False
    rows=[];py_total=collections.Counter();rust_total=collections.Counter()
    all_labels=[]
    for c in commands:
        label=c["label"];assert label not in all_labels;all_labels.append(label)
        assert type(c["exit"]) is int
        assert c["exit"]==expected_exit.get(label,0), ("unexpected actual exit",label,c["exit"])
        if "started_monotonic_ns" in c:
            assert type(c["started_monotonic_ns"]) is int and type(c["finished_monotonic_ns"]) is int
            assert c["finished_monotonic_ns"]>=c["started_monotonic_ns"]
        streams={}
        for stream in ("stdout","stderr"):
            pin=c[stream];path=Path(pin["path"])
            assert path.parent==directory and path.name==label+"."+stream
            streams[stream]=add(path,pin=pin)
        combined=(streams["stdout"]+b"\n"+streams["stderr"]).decode("utf-8")
        o=outcomes(combined)
        assert c.get("python_test_counts",[x["reported_methods"] for x in o["python"]])==[x["reported_methods"] for x in o["python"]]
        assert c.get("rust_test_outcomes",[{k:r[k] for k in ("passed","failed","ignored")} for r in o["rust"]])==[{k:r[k] for k in ("passed","failed","ignored")} for r in o["rust"]]
        for x in o["python"]:
            for k in ("reported_methods","passed","failed","errors","skipped"):py_total[k]+=x[k]
        for x in o["rust"]:
            for k in ("passed","failed","ignored"):rust_total[k]+=x[k]
        rows.append({"label":label,"argv":c["argv"],"cwd":c["cwd"],"exit":c["exit"],"outcomes":o})
    assert m.get("python_test_methods_reported",py_total["reported_methods"])==py_total["reported_methods"]
    assert m.get("rust_test_outcomes",dict(rust_total))=={k:rust_total[k] for k in ("passed","failed","ignored")} or (not rust_total and m.get("rust_test_outcomes")=={"passed":0,"failed":0,"ignored":0})
    extras={}
    if name=="owner":
        prep=jload(add(ROOT/"owner-empty-target-preparation-01/preparation.json","provenance/owner-empty-target-preparation.json",{"sha256":"55f18f4e02646b013dd87e47d7e86291068edc59f85036fe87433c3a831d8fe7"}))
        launch=jload(add(ROOT/"owner-launch-binding.json","provenance/owner-launch-binding.json",{"sha256":"828ac5d0226a593c96ce67524494a6127346add34c50c9e92c251ff87f6b4aa8"}))
        artifact=jload(add(ROOT/"owner-artifact.json","provenance/owner-artifact.json",{"sha256":"3ab195ababccc9aa2abfffde5527227f81cc52e6a1d6abe09068d4fb7b79aeed"}))
        assert prep["target_preexisted"] is False and prep["target_entries"]==prep["target_files"]==0
        assert launch["empty_observed_before_exec"] is True and launch["preparation_sha256"]==digest(raw["provenance/owner-empty-target-preparation.json"])
        assert launch["source"]==C6 and launch["target"]==prep["target"]==m["cargo_target"]
        assert launch["target_inode"]==prep["target_inode"] and launch["target_device"]==prep["target_device"]
        assert artifact["source_commit"]==C6 and artifact["source_tree"]==TREE
        assert artifact["qualification_manifest"]["sha256"]==manifest_sha
        compiler=raw["13-owner-no-run-json.stdout"]
        assert artifact["compiler_artifact_stdout"]["sha256"]==digest(compiler)
        records=[jload(x) for x in compiler.splitlines() if x]
        exe=artifact["owner_executable"]
        selected=[x for x in records if x.get("reason")=="compiler-artifact" and x.get("executable")==exe["path"]]
        assert len(selected)==1
        a=selected[0]
        assert a["target"]["name"]=="trnm_pon_node" and a["profile"]["test"] is True
        assert Path(a["manifest_path"]).is_relative_to(REPO) and Path(a["target"]["src_path"]).is_relative_to(REPO)
        st=Path(exe["path"]).stat()
        observed={"bytes":st.st_size,"device":st.st_dev,"inode":st.st_ino,"mtime_ns":st.st_mtime_ns,"nlink":st.st_nlink}
        assert all(observed[k]==exe[k] for k in observed)
        extras={"empty_target_preparation_and_launch_binding_match":True,
                "compiler_artifact_matches_owner_receipt":True,"owner_elf_current_stat_matches":observed,
                "owner_elf_sha256_recorded_by_original_receipt":exe["sha256"],
                "owner_elf_sha256_independently_recomputed_in_this_audit":False,
                "limitation":"468 MB owner ELF not reread during other qualification I/O; no ELF copied. Original launcher empty-target receipt checked; this is not an independent reproducible build."}
    elif name=="core-attempt-01":
        block=add(directory/"w1-current-command-block.sh",pin={"sha256":m["ci_command_block_sha256"]})
        names=["cancellation-handoff","coordinator-contract","provider-contract","generation-target","owner-cancellation","source-builder","owned-runtime-reader","kaggle-worker-contract","winner-identity","deployment-evidence-binding","deployment-comparison-audit","owned-process-collector"]
        for leaf in names:
            add(directory/"ci-receipts"/"w1-postwin-contracts"/(leaf+".log"),"w1-retained/"+leaf+".log")
        extras={"staged_original_methods":32,"staged_passed":30,"staged_failed":2,
          "staged_failure_reason":"DEADLINE_EXHAUSTED_BEFORE_SPAWN",
          "output_limit_subcase_after_sigkill_assertion_executed":False,
          "fixture_budgets_seconds":[0.15,0.2],
          "actual_default_termination_grace_seconds":5,
          "failure_cause_attributed_to_host_contention":False,
          "first_attempt_success":False,"isolated_followup_not_substituted":True}
    elif name=="native":
        decl=jload(add(directory/"declaration.json",pin={"sha256":"ad0205296ea144fbdf36fce756db3cad418b94fd873a8e72793468a48393f976"}))
        add(Path(decl["driver"]["path"]),"provenance/native-qualify-empty-v3.py",decl["driver"])
        prep=jload(add(Path(m["target_preparation"]["path"]),"provenance/native-empty-preparation-03.json",m["target_preparation"]))
        assert prep["initial_entries"]==[] and prep["copied_artifacts"] is False
        assert prep["destination"]==m["target"]
        binary_bindings={}
        for role,b in m["binaries"].items():
            build_data=raw[Path(b["build_log"]["path"]).name]
            records=[jload(x) for x in build_data.splitlines() if x]
            selected=[x for x in records if x.get("reason")=="compiler-artifact" and x.get("executable")==b["file"]["path"]]
            assert len(selected)==1 and selected[0]==b["cargo_artifact"]
            assert selected[0]["profile"]["test"] is False
            data=read_stable(Path(b["file"]["path"]))
            assert len(data)==b["file"]["bytes"] and digest(data)==b["file"]["sha256"]
            binary_bindings[role]={"path":b["file"]["path"],"bytes":len(data),"sha256":digest(data),"independently_rehashed":True,"copied":False,"cargo_fresh":selected[0]["fresh"]}
        extras={"binary_bindings":binary_bindings,"fresh_target_receipt_matches":True,
                "declared_empty_target_assertion_in_executed_driver":True,
                "registry_cache_and_toolchain_reused":True,"independent_cleanroom_build":False,
                "native_historical_243_not_rerun":True,"commands":10,"preparation_receipt_not_counted_as_command":True}
    elif name=="receiver":
        native_manifest=read_stable(Path(m["native_build_manifest"]["path"]))
        assert digest(native_manifest)==m["native_build_manifest"]["sha256"]
        native=jload(native_manifest)
        c=next(c for c in commands if c["label"]=="02-real-receiver-controls")
        argv=c["argv"]
        assert argv[argv.index("--verifier")+1]==native["binaries"]["verifier"]["file"]["path"]
        assert argv[argv.index("--verifier-sha256")+1]==native["binaries"]["verifier"]["file"]["sha256"]
        extras={"native_build_binding_matches":True,"actual_original_receipt_used":True,
                "new_receipts_generated":0,"winning_node_admission_established":False}
    terminal_raw=TERMINALS[name]
    raw["durable-job-terminal.json"]=terminal_raw.encode()
    index.append({"archive_member":"durable-job-terminal.json","original_path":"hepta-runtime authoritative process_status","bytes":len(raw["durable-job-terminal.json"]),"sha256":digest(raw["durable-job-terminal.json"])})
    t=jload(raw["durable-job-terminal.json"])
    assert t["output_complete"] is True and t["output_durable"] is True and t["timed_out"] is False
    assert t["exit_code"]==(1 if name=="core-attempt-01" else 0)
    summary={"schema":"TRNM-W1-C6-INDEPENDENT-COMPONENT-REVIEW1","component":name,
             "source":{"commit":C6,"tree":TREE},"original_manifest_sha256":manifest_sha,
             "actual_command_count":len(commands),"actual_nonzero_commands":[c["label"] for c in commands if c["exit"]!=0],
             "source_guards_before_after_exact_equal":True,"all_bound_outputs_match":True,
             "python":dict(py_total),"rust":dict(rust_total),"command_reviews":rows,
             "provenance":extras,"durable_job_id":t["job_id"],"durable_exit":t["exit_code"],
             "qualifier_claimed_complete":m["qualification_complete"],"audit_reran_tests":False,
             "audit_reran_whole_source_guard":False,"audit_started_operation":False,
             "new_complete_proofs":0,"overall_c6_qualification_complete":False}
    put(dest/"summary.json",dump(summary))
    arc=archive_raw(dest,raw,index)
    files=[]
    for p in sorted(dest.iterdir()):
        if p.is_file():
            b=p.read_bytes();files.append({"path":p.name,"bytes":len(b),"sha256":digest(b)})
    put(dest/"manifest.json",dump({"schema":"TRNM-W1-PUBLIC-COMPONENT-ARCHIVE1","component":name,"files":files,
        "scope":"explicit raw logs, manifests and safe provenance; no ELF, SQLite, environment dump, state tree or credentials"}))
    print(json.dumps({"component":name,"commands":len(commands),"python":dict(py_total),"rust":dict(rust_total),
                      "manifest_sha256":digest((dest/"manifest.json").read_bytes()),"raw_archive":arc}),flush=True)
    return summary

DEST.parent.mkdir(parents=True,exist_ok=True)
DEST.mkdir()
reports=[]
for spec in SPECS:
    reports.append(audit(**spec))
put(DEST/"audit-driver.py",AUDIT_DRIVER)
put(DEST/"scope.json",dump({"source_commit":C6,"source_tree":TREE,"completed_components_audited":[r["component"] for r in reports],
    "first_core_attempt_failed":True,"overall_qualification_complete":False,
    "pending":"backend attempts, sole isolated staged32 followup and later operation audited separately",
    "original_staged_failure_and_unexecuted_subcase_preserved":True,
    "no_tests_or_operations_run_by_audit":True,"no_source_worktree_writes":True}))
print(json.dumps({"external_review_directory":str(DEST),"completed":True,"overall_c6_qualification_complete":False}),flush=True)

