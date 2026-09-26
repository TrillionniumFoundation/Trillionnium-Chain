#!/usr/bin/env python3
import pathlib
import subprocess
import tempfile
import prepare_source_candidate as prepare
import check_source_candidate as check
import build_reproducible_lab_candidate as build
from source_candidate_doc_alias_v1 import LINK_MODE, validate_alias


def main():
    negatives=0
    good={'docs/alias.md':LINK_MODE,'docs/target.md':0o644}
    assert validate_alias('docs/alias.md',b'target.md',good)=='docs/target.md'
    for path,target,modes in [
        ('docs/alias.md',b'/etc/passwd',good),('docs/alias.md',b'../../outside.md',good),
        ('docs/alias.md',b'missing.md',good),('docs/alias.md',b'target.md',{**good,'docs/target.md':LINK_MODE}),
        ('docs/alias.md',b'target.md',{**good,'docs/target.md':0o755}),('docs/alias.md',b'target.md\n',good),
        ('scripts/alias.md',b'../docs/target.md',{**good,'scripts/alias.md':LINK_MODE}),
        ('docs/alias.md',b'folder/target.md',{**good,'docs/folder':LINK_MODE,'docs/folder/target.md':0o644}),
        ('docs/alias.md',b'alias.md',good),('docs/alias.md',b'./target.md',good),
    ]:
        try:validate_alias(path,target,modes)
        except ValueError:negatives+=1
        else:raise AssertionError('unsafe alias accepted')
    with tempfile.TemporaryDirectory() as temporary:
        parent=pathlib.Path(temporary).resolve();repo=parent/'repo';repo.mkdir();(repo/'docs').mkdir();(repo/'trillionnium').mkdir()
        (repo/'trillionnium/Cargo.lock').write_text('version = 4\n');(repo/'docs/target.md').write_text('Bound exact bytes.\n');(repo/'docs/alias.md').symlink_to('target.md')
        def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL)
        git('init');git('config','user.name','candidate-test');git('config','user.email','candidate-test@invalid');git('add','.');git('commit','-qm','tracked docs alias')
        archive=parent/'clean.tar';prepare.prepare(repo,archive,require_clean=True)
        result=check.validate(archive,require_clean=True);assert result['git_tree_oid']==git('rev-parse','HEAD^{tree}').decode().strip()
        extracted=build.extract(archive,parent/'extracted');alias=extracted/'docs/alias.md';assert alias.is_symlink() and alias.read_text()=='Bound exact bytes.\n'
        assert alias.readlink()==pathlib.Path('target.md')
        legacy=parent/'legacy.tar';prepare.prepare(repo,legacy);check.validate(legacy)
        (repo/'docs/untracked.md').symlink_to('target.md')
        try:prepare.prepare(repo,parent/'untracked.tar')
        except (SystemExit,ValueError):negatives+=1
        else:raise AssertionError('untracked alias accepted')
    print(f'source_doc_alias_tests=passed clean_git_tree_reconstructed=true extracted_after_regular_files=true negatives={negatives}')

if __name__=='__main__':main()
