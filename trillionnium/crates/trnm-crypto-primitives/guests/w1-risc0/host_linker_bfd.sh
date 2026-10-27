#!/bin/sh
# Optional explicit HOST-only linker for a deliberately minimal toolchain
# extraction. The real RISC-V guest still links with its official rust-lld.
# No compiler, cryptographic operation or proof check is substituted here.
exec /usr/bin/cc "$@" -fuse-ld=bfd
