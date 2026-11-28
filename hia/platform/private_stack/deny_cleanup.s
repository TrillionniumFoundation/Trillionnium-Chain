# Test-only launcher: add a restrictive real seccomp rule, then exec the sealed
# captured native response fixture at argv[1]. Never part of a production image.
.global _start
.section .text
_start:
  cmpq $2,(%rsp)
  jne failed
  mov $157,%eax
  mov $38,%edi
  mov $1,%esi
  xor %edx,%edx
  xor %r10d,%r10d
  xor %r8d,%r8d
  syscall
  test %rax,%rax
  jne failed
  mov $157,%eax
  mov $22,%edi
  mov $2,%esi
  lea filter_program(%rip),%rdx
  xor %r10d,%r10d
  xor %r8d,%r8d
  syscall
  test %rax,%rax
  jne failed
  mov 16(%rsp),%rdi
  lea 16(%rsp),%rsi
  xor %edx,%edx
  mov $59,%eax
  syscall
failed:
  mov $60,%eax
  mov $98,%edi
  syscall
.section .rodata
.p2align 3
filter_program:
  .short 4
  .zero 6
  .quad filter_rules
filter_rules:
  .short 0x20
  .byte 0,0
  .long 0
  .short 0x15
  .byte 0,1
  .long 11
  .short 0x06
  .byte 0,0
  .long 0x00050001
  .short 0x06
  .byte 0,0
  .long 0x7fff0000
.section .note.GNU-stack,"",@progbits
