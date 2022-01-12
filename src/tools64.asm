[bits 64]
global save_context

section .data

some_text: 
    db 'aaaaaaa', 0

section .text

save_context:

; rcx points to _CONTEXT
;   +0x078 Rax              : Uint8B
;   +0x080 Rcx              : Uint8B
;   +0x088 Rdx              : Uint8B
;   +0x090 Rbx              : Uint8B
;   +0x098 Rsp              : Uint8B
;   +0x0a0 Rbp              : Uint8B
;   +0x0a8 Rsi              : Uint8B
;   +0x0b0 Rdi              : Uint8B
;   +0x0b8 R8               : Uint8B
;   +0x0c0 R9               : Uint8B
;   +0x0c8 R10              : Uint8B
;   +0x0d0 R11              : Uint8B
;   +0x0d8 R12              : Uint8B
;   +0x0e0 R13              : Uint8B
;   +0x0e8 R14              : Uint8B
;   +0x0f0 R15              : Uint8B
;   +0x0f8 Rip              : Uint8B
    mov [rcx + 0x78], rax
    mov [rcx + 0x80], rcx
    mov [rcx + 0x88], rdx
    mov [rcx + 0x90], rbx

    mov rax, rsp
    add rax, 8
    mov [rcx + 0x98], rax ; rsp
    mov [rcx + 0xa0], rbp
    mov [rcx + 0xa8], rsi
    mov [rcx + 0xb0], rdi
    mov [rcx + 0xb8], r8
    mov [rcx + 0xc0], r9
    mov [rcx + 0xc8], r10
    mov [rcx + 0xd0], r11
    mov [rcx + 0xd8], r12
    mov [rcx + 0xe0], r13
    mov [rcx + 0xe8], r14
    mov [rcx + 0xf0], r15

    mov rax, [rsp]
    mov [rcx + 0xf8], rax ; rip

    ret
