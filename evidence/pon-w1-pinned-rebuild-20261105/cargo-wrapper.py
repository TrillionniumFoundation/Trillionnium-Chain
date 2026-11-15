#!/usr/bin/env python3
import os,sys
if 'riscv32im-risc0-zkvm-elf' in sys.argv:
    flags = os.environ.get('CARGO_ENCODED_RUSTFLAGS', '').split('\x1f')
    flags += ["--remap-path-prefix=/workspace/shared/w1-home/.cargo=/root/.cargo"]
    os.environ['CARGO_ENCODED_RUSTFLAGS']='\x1f'.join(flags)
os.execv('/workspace/shared/chain-cargo/bin/cargo', ['cargo'] + sys.argv[1:])
