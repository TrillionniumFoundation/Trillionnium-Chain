# Test-only Linux observer. The production adapter is emitted by HIA.
.global _start
.section .text
_start:
  mov $9,%eax
  xor %edi,%edi
  mov $4194304,%esi
  mov $3,%edx
  mov $34,%r10d
  mov $-1,%r8
  xor %r9d,%r9d
  syscall
  cmp $-4095,%rax
  jae failed
  mov %rax,arena(%rip)
  lea 2097152(%rax),%rdi
  mov $131072,%ecx
  movabs $0xa5a5a5a5a5a5a5a5,%rax
  rep stosq
  mov arena(%rip),%rdi
  add $8192,%rdi
  mov $17700,%ecx
  rep stosq
  xor %ebx,%ebx
read_loop:
  xor %eax,%eax
  xor %edi,%edi
  mov arena(%rip),%rsi
  add %rbx,%rsi
  mov $72,%edx
  sub %rbx,%rdx
  syscall
  test %rax,%rax
  jle failed
  add %rax,%rbx
  cmp $72,%rbx
  jb read_loop
  mov arena(%rip),%rax
  mov 64(%rax),%rax
  cmp $4,%rax
  ja failed
  mov %rax,mode(%rip)
  test %rax,%rax
  je invoke
  cmp $4,%rax
  je invoke
  add $8,%eax
  mov %eax,denied_number(%rip)
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
invoke:
  mov arena(%rip),%rdi
  mov $64,%esi
  lea 4096(%rdi),%rdx
  mov $104,%ecx
  lea 8192(%rdi),%r8
  mov $141568,%r9d
  lea 3145728(%rdi),%rsp
  cmpq $4,mode(%rip)
  je invoke_raw
  call guarded_kernel
  jmp returned
invoke_raw:
  mov $96,%ecx
  call raw_kernel
returned:
  mov %rax,result(%rip)
  cmpq $0,mode(%rip)
  je probe_mapping
  cmpq $3,mode(%rip)
  jne emit_report
probe_mapping:
  mov arena(%rip),%rdi
  mov 4192(%rdi),%rdi
  mov $1048576,%esi
  mov arena(%rip),%rdx
  add $1048576,%rdx
  mov $27,%eax
  syscall
  mov %rax,probe_result(%rip)
emit_report:
  lea result(%rip),%rsi
  mov $16,%edx
  call write_all
  mov arena(%rip),%rsi
  add $4096,%rsi
  mov $104,%edx
  call write_all
  mov arena(%rip),%rsi
  add $8192,%rsi
  mov $141600,%edx
  call write_all
  mov arena(%rip),%rsi
  add $2097152,%rsi
  mov $1048576,%edx
  call write_all
  cmpq $3,mode(%rip)
  jne done
  mov arena(%rip),%rsi
  mov 4192(%rsi),%rsi
  mov $1048576,%edx
  call write_all
done:
  mov $60,%eax
  xor %edi,%edi
  syscall
write_all:
  mov $1,%eax
  mov $1,%edi
  syscall
  test %rax,%rax
  jle failed
  add %rax,%rsi
  sub %rax,%rdx
  jne write_all
  ret
failed:
  mov $60,%eax
  mov $2,%edi
  syscall
.p2align 4
guarded_kernel:
  .incbin "guarded-observed.flat"
.p2align 4
raw_kernel:
  .incbin "raw.flat"
.section .data
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
denied_number:
  .long 0
  .short 0x06
  .byte 0,0
  .long 0x00050001
  .short 0x06
  .byte 0,0
  .long 0x7fff0000
.section .bss
.p2align 3
arena: .skip 8
mode: .skip 8
result: .skip 8
probe_result: .skip 8
.section .note.GNU-stack,"",@progbits
