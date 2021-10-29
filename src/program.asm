[bits 64]
global WinMain

section .data

some_text: 
    db 'aaaaaaa', 0
some_var 
    dd 0x12345678
jmp_dd 
    dq jmp_dd_test.jmp_dd_next

section .text


simple_call:

    call .callme
.callme
    ret

jmp_dd_test:
    jmp [rel jmp_dd]
    int3
    int3
    int3
.jmp_dd_next
    ret
    
WinMain:
loop:
    mov ecx, 10
.loop
    dec ecx
    jnz .loop
    ret

simple_cond:
    mov eax, [rel some_var]
    cmp eax, 0x87654321
    jnz .false
.true
    mov eax, 1
    ret
.false
    xor eax, eax
    ret

simple_lea:
    lea rax, [rel some_text]
    ret

simplest:
    nop
    int3
    nop
    int3
    nop
    int3
    nop
    int3
    mov eax, eax
    xor rax, rax
    inc rax
    ret

