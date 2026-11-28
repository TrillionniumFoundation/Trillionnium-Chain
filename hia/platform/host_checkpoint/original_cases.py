"""Shared private-file corpus; it grants no production fixed-parent authority."""
from __future__ import annotations

import os
from pathlib import Path
import shutil

PARENT = Path('sys/fs/cgroup/trnmponpublic.slice')
LIMITS = {'cpu.max': b'25000 100000\n', 'cpu.max.burst': b'0\n',
          'memory.max': b'2147483648\n', 'memory.swap.max': b'0\n', 'pids.max': b'256\n'}


def write(path: str, data: bytes) -> dict:
    return {'op':'write', 'path':path, 'hex':data.hex()}


def limit(name: str, data: bytes) -> dict:
    return write('parent/'+name,data)


def cases() -> list[dict]:
    rows=[]
    def add(name, *, before=(), after=(), gate=0, mutate=(), initial=0, final=0,
            second=None, chunk=4096, count=1):
        rows.append({'name':name,'before':list(before),'after':list(after),'gate':gate,
                     'mutate':list(mutate),'expected_initial':initial,'expected_final':final,
                     'second_error':second,'chunk':chunk,'count':count})
    add('fresh-normal',count=3)
    for chunk in (1,2,3,7,31,128,129,255,256,257,4096):
        add(f'physical-short-read-{chunk}',chunk=chunk)
    for length in (0,1,255,256,257,4095,4096,4097,65537,131073):
        add(f'complete-boot-{length}',before=[write('boot',b'x'*length)])
    add('boot-long-trim',after=[write('boot',b' '*131073+b'boot-identity\n')])
    add('boot-unicode-trim',after=[write('boot','\u2007\u0085boot-identity\u3000\n'.encode())])
    add('changed-boot',after=[write('boot',b'another-boot')],final=4)
    for name,data in [('invalid',b'\xff'),('long-invalid',b'x'*4097+b'\xc0\x80')]:
        add('boot-'+name,before=[write('boot',data)],initial=3)
    add('boot-missing',before=[{'op':'remove','path':'boot'}],initial=3)
    for name,data,code in (
        ('exact',b'0::/trnmponpublic.slice',0),('lf',b'0::/trnmponpublic.slice\n',0),
        ('crlf',b'0::/trnmponpublic.slice\r\n',0),('child',b'0::/trnmponpublic.slice/child\n',0),
        ('unicode','0::/trnmponpublic.slice/雪\n'.encode(),0),
        ('long',b'0::/trnmponpublic.slice/'+b'x'*131073+b'\n',0),
        ('empty',b'',3),('root',b'0::/\n',3),('wrong',b'0::/other\n',3),
        ('sibling',b'0::/trnmponpublic.slice-other\n',3),
        ('trailing',b'0::/trnmponpublic.slice/\n',3),
        ('double',b'0::/trnmponpublic.slice//a\n',3),
        ('dot',b'0::/trnmponpublic.slice/.\n',3),('dotdot',b'0::/trnmponpublic.slice/..\n',3),
        ('multi',b'0::/trnmponpublic.slice\n0::/other\n',3),
        ('extra-empty',b'0::/trnmponpublic.slice\n\n',3),
        ('invalid-utf8',b'0::/trnmponpublic.slice/\xff',3),('v1',b'1:cpu:/trnmponpublic.slice\n',3)):
        add('membership-'+name,before=[write('membership',data)],initial=code)
    for name,data in LIMITS.items():
        stem=name.replace('.','-');data=data.rstrip(b'\n')
        for size,code in ((128,0),(129,5)):
            add(f'{stem}-{size}',before=[limit(name,data+b' '*(size-len(data)))],initial=code)
        add(stem+'-invalid-utf8',before=[limit(name,b'\xff')],initial=5)
        add(stem+'-invalid-number',before=[limit(name,b'x')],initial=6)
        for op in ('remove','symlink','fifo','directory'):
            add(stem+'-'+op,before=[{'op':op,'path':'parent/'+name}],initial=5)
    cpu=[('ceiling',b'250000 1000000',0),('quota-over',b'250001 1000000',6),
         ('period-over',b'25000 1000001',6),('bandwidth-over',b'25001 100000',6),
         ('zero',b'0 100000',6),('plus',b'+25000 +100000',0),('extra',b'25000 100000 0',6),
         ('overflow',b'18446744073709551616 100000',6),('vt-separator',b'25000\x0b100000',6),
         ('vt-trim',b'\x0b25000 \x0b100000',0),
         ('unicode','\u200725000 \u3000100000\u0085'.encode(),0)]
    for name,data,code in cpu:add('cpu-'+name,before=[limit('cpu.max',data)],initial=code)
    for field,values in (
        ('memory.max',[(b'2147483648',0),(b'2147483649',6),(b'0',6),
                       ('\u0085+1024\u3000'.encode(),0),(b'18446744073709551616',6)]),
        ('pids.max',[(b'1',0),(b'257',6),(b'0',6)]),
        ('cpu.max.burst',[(b'+0',6),(b'00',6),(b'\x0b0\x0b',0)]),
        ('memory.swap.max',[(b'+0',6),(b'00',6),(b'\xc2\x850\xe3\x80\x80',0)])):
        for index,(data,code) in enumerate(values):
            add(f'{field}-edge-{index}',before=[limit(field,data)],initial=code)
    add('controller-missing',before=[{'op':'remove','path':'controllers'}],initial=2)
    add('controller-follow',before=[{'op':'symlink','path':'controllers'}])
    add('parent-not-directory',before=[{'op':'parent-file'}],initial=1)
    add('controller-before-parent-type',before=[{'op':'parent-file'},{'op':'remove','path':'controllers'}],initial=2)
    add('parent-mode',before=[{'op':'chmod','mode':0o770}],initial=1)
    add('search-only-parent',before=[{'op':'chmod','mode':0o111}])
    for index,path in enumerate(('sys','sys/fs','sys/fs/cgroup','parent')):
        action={'op':'symlink','path':path}
        add(f'ancestor-{index}',before=[action],initial=1)
        add(f'ancestor-before-controller-{index}',before=[action,{'op':'remove','path':'controllers'}],initial=1)
    for name,actions,code in (
        ('parent-inode',[{'op':'replace-parent'}],4),
        ('parent-mode',[{'op':'chmod','mode':0o770}],4),
        ('parent-link',[{'op':'symlink','path':'parent'}],4),
        ('membership',[write('membership',b'0::/other')],3),
        ('limits-io-before-parse',[limit('cpu.max',b'bad'),{'op':'remove','path':'parent/pids.max'}],5),
        ('membership-before-limits',[write('membership',b'broken'),{'op':'remove','path':'parent/cpu.max'}],3),
        ('boot-before-parent',[write('boot',b'changed'),{'op':'replace-parent'}],4)):
        add('fresh-'+name,after=actions,final=code)
    for field,data in [('cpu.max',b'20000 100000'),('memory.max',b'1024'),('pids.max',b'255')]:
        add('changed-'+field,after=[limit(field,data)],final=7)
    for data in (b' +25000\t+100000 \r\n',b'025000 0100000'):
        add('equivalent-cpu-'+str(len(data)),after=[limit('cpu.max',data)])
    add('boot-next-check',gate=1,mutate=[write('boot',b'changed')],second=4)
    for gate in (1,2,3):
        add(f'gate-{gate}-inode',gate=gate,mutate=[{'op':'replace-parent'}],final=4)
    add('parse-before-fence',after=[limit('cpu.max',b'bad')],gate=3,
        mutate=[{'op':'replace-parent'}],final=6)
    add('fence-before-changed-limits',after=[limit('memory.max',b'1024')],gate=3,
        mutate=[{'op':'replace-parent'}],final=4)
    add('permissions-final-fence',gate=3,mutate=[{'op':'chmod','mode':0o777}],final=4)
    add('symlink-final-fence',gate=3,mutate=[{'op':'symlink','path':'parent'}],final=4)
    if len({row['name'] for row in rows})!=len(rows):
        raise ValueError('Duplicate original corpus name')
    return rows


def selected(root: Path, path: str) -> Path:
    if path=='parent':return root/PARENT
    if path.startswith('parent/') and path[7:] in LIMITS:return root/PARENT/path[7:]
    if path in ('boot','membership','controllers','sys','sys/fs','sys/fs/cgroup'):
        return root/path
    raise ValueError('Unexpected private fixture path: '+path)


def apply(root: Path, actions: list[dict]) -> None:
    parent=root/PARENT
    for action in actions:
        op=action['op']
        if op=='replace-parent':
            old=parent.with_name(parent.name+'.detached')
            parent.rename(old);shutil.copytree(old,parent);parent.chmod(0o700)
        elif op=='chmod':parent.chmod(action['mode'])
        elif op=='parent-file':shutil.rmtree(parent);parent.write_bytes(b'not directory')
        else:
            path=selected(root,action['path'])
            if op=='write':path.write_bytes(bytes.fromhex(action['hex']))
            elif op=='remove':path.unlink()
            elif op=='symlink':
                target=path.with_name(path.name+'.target');path.rename(target);path.symlink_to(target.name)
            elif op in ('fifo','directory'):
                path.unlink()
                if op=='fifo':os.mkfifo(path,0o600)
                else:path.mkdir()
            else:raise ValueError('Unexpected private fixture action: '+op)
