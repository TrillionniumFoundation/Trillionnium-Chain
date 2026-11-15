# Test-only pointer observation. It never changes the production prefix or math.
.global observed_kernel
.section .text
observed_kernel:
  push %r12
  mov %rdx,%r12
  call actual_kernel
  lea -1048560(%rsp),%r10
  mov %r10,96(%r12)
  pop %r12
  ret
actual_kernel:
  .incbin "raw.flat"
.section .note.GNU-stack,"",@progbits
