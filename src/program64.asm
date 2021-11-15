[bits 64]
global WinMain

section .data

some_text: 
    db 'aaaaaaa', 0
some_var:
    dd 0x12345678
jmp_dd:
    dq jmp_dd_test.jmp_dd_next

section .text

some_var_in_text:
    dd 0x12345678

simple_call:

    call .callme
.callme:
    ret

jmp_dd_test:
    jmp [rel jmp_dd]
    ud2
.jmp_dd_next:
    ret
    
simple_loop:
    mov ecx, 10
.loop:
    dec ecx
    jnz .loop
    ret

simple_cond_in_code:
    mov eax, [rel some_var_in_text]
    cmp eax, 0x12345678
    jnz .false
.true:
    mov eax, 1
    ret
.false:
    ud2
    xor eax, eax
    ret

simple_cond:
    mov eax, [rel some_var]
    cmp eax, 0x12345678
    jnz .false
.true:
    mov eax, 1
    ret
.false:
    ud2
    xor eax, eax
    ret

simple_lea:
    lea rax, [rel some_text]
    mov eax, [rax]
    cmp eax, 'aaaa'
    je .true
    ud2
.true:
    ret

simplest:
    nop
    mov eax, eax
    xor rax, rax
    inc rax
    ret

WinMain:

    call jmp_dd_test

    call simple_loop
    cmp ecx, 0
    jz .simple_loop_ok
    ud2
.simple_loop_ok:

    call simple_cond_in_code
    call simple_cond
    call simple_lea
    call simplest

    xor eax, eax
    ret


