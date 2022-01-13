global WinMain

global FuzzMeNasmSubRegImm
global FuzzMeNasmSubRegReg
global FuzzMeNasmSubMemReg
global FuzzMeNasmSubMemImm
global FuzzMeNasmSubStkReg
global FuzzMeNasmSubRelReg
global FuzzMeNasmSubRegRel

global FuzzMeNasmCmpRegImm
global FuzzMeNasmCmpRegReg
global FuzzMeNasmCmpMemReg
global FuzzMeNasmCmpMemImm
global FuzzMeNasmCmpStkReg
global FuzzMeNasmCmpRelReg
global FuzzMeNasmCmpRegRel

global FuzzMeNasmTestRegReg

section .data

title:  db 'Win64', 0xd, 0xa, 0
msg:    db 'Hello world!', 0

cmpData: db '13371337'

section .text

lret:
 ret

FuzzMeJumps:
  nop
.label1:
  nop
  jmp .label2
  nop
.label3:
  nop
  jmp .label4
  nop
.label2:
  nop
  jnz .label3
  nop
  call lret
  nop
.label4:
  ret

extern crash 

FuzzMeNasmCmpRegImm:

    cmp rdx, 8
    jb .ret
    
    mov rax, [rcx]
    cmp eax, '13371337' ; r32
    jnz .ret

    call crash

.ret:
    ret

FuzzMeNasmCmpRegReg:

    cmp rdx, 8
    jb .ret
    
    mov rcx, [rcx]
    mov rax, '13371337'
    cmp eax, ecx ; r32
    jnz .ret

    xor rax, rax
    mov [rax], al
    ;call crash

.ret:
    ret

FuzzMeNasmCmpMemReg:

    cmp rdx, 8
    jb .ret
    
    mov rcx, [rcx]
    lea rax, [rel cmpData]
    cmp ecx, [rax] ; r32
    jnz .ret

    call crash

.ret:
    ret

FuzzMeNasmCmpMemImm:

    cmp rdx, 8
    jb .ret
    
    cmp qword [rcx], 1; '13371337' ; r32
    jnz .ret

    xor rax, rax
    mov [rax], al
    ;call crash

.ret:
    ret

FuzzMeNasmCmpStkReg:

    cmp rdx, 8
    jb .ret
    
    sub rsp, 0x100

    mov rax, '13371337'
    mov [rsp+0x78], rax
    mov rcx, [rcx]
    cmp ecx, [rsp+0x78] ; r32
    jnz .retStack

    xor rax, rax
    mov [rax], al

.retStack:
    add rsp, 0x100
.ret:
    ret

FuzzMeNasmCmpRelReg:

    cmp rdx, 8
    jb .ret
    
    mov rcx, [rcx]
    cmp [rel cmpData], ecx ; r32
    jnz .ret

    call crash

.ret:
    ret

FuzzMeNasmCmpRegRel:

    cmp rdx, 8
    jb .ret
    
    mov rcx, [rcx]
    cmp ecx, [rel cmpData] ; r32
    jnz .ret

    call crash

.ret:
    ret

FuzzMeNasmSubRegImm:

    cmp rdx, 8
    jb .ret
    
    mov rax, [rcx]
    sub eax, '1337' ; r32
    jnz .ret

    call crash

.ret:
    ret

FuzzMeNasmSubRegReg:
    cmp rdx, 8
    jb .ret
    
    mov rcx, [rcx]
    mov rax, '13371337'
    sub eax, ecx ; r32
    jnz .ret

    call crash
.ret:
    ret

FuzzMeNasmSubMemReg:
FuzzMeNasmSubStkReg:
FuzzMeNasmSubRelReg:

FuzzMeNasmTestRegReg:

    cmp rdx, 4
    jb .ret

    mov rax, [rcx]
    sub eax, '1337'
    test rax, rax
    jnz .ret

    call crash

.ret:
    ret

WinMain:

    cmp [rel msg], al
    cmp  al, [rel msg]
    ;cmp al, rel32 byte ptr [msg]
    int3
    mov rax, 0xffff
    mov rcx, 0xff
    lzcnt rcx, rax

    ret


; nasm -f win64 ..\src\asm\simplest.asm
; IF %ERRORLEVEL% NEQ 0 Exit /B
; link.exe /DLL /ENTRY:WinMain ..\src\asm\simplest.obj
