# gap.S: hand made test program, layout comes from mkelfs.py
# symbols come in with --defsym:
#   DATA   = vaddr of the RW segment (8 bytes in the file, 0x3000 in memory)
#   HDR    = vaddr of the header page (first PT_LOAD)
#   EXPECT = (optional, needs USE_EXPECT) address _start must really be at
        .globl _start
        .text
_start:
        .ifdef USE_EXPECT
        lea     0(%rip), %rax
        movabs  $EXPECT, %rbx
        sub     %rbx, %rax
        cmp     $0x100, %rax
        jae     f1
        .endif
        lea     DATA(%rip), %rbx
        movabs  $0x1122334455667788, %rax
        cmp     %rax, (%rbx)
        jne     f2
        cmpq    $0, 8(%rbx)          # rest of the file page (file has 0xAA junk here)
        jne     f3
        cmpq    $0, 0xff8(%rbx)
        jne     f3
        cmpq    $0, 0x1000(%rbx)     # pure anon bss pages
        jne     f4
        cmpq    $0, 0x2ff8(%rbx)
        jne     f4
        movq    $0x1234, 0x10(%rbx)  # writable?
        cmpq    $0x1234, 0x10(%rbx)
        jne     f5
        movq    $0x5678, 0x2ff8(%rbx)
        cmpq    $0x5678, 0x2ff8(%rbx)
        jne     f5
        lea     HDR(%rip), %rcx      # header page is mapped and readable
        cmpl    $0x464c457f, (%rcx)
        jne     f6
        xor     %edi, %edi
        jmp     out
f1:     mov     $1, %edi
        jmp     out
f2:     mov     $2, %edi
        jmp     out
f3:     mov     $3, %edi
        jmp     out
f4:     mov     $4, %edi
        jmp     out
f5:     mov     $5, %edi
        jmp     out
f6:     mov     $6, %edi
out:    mov     $60, %eax
        syscall
