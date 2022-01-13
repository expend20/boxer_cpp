global WinMain

global @FuzzMeNasmSubRegImm@8
global @FuzzMeNasmSubRegReg@8
global @FuzzMeNasmSubMemReg@8
global @FuzzMeNasmSubMemImm@8
global @FuzzMeNasmSubStkReg@8
global @FuzzMeNasmSubRelReg@8
global @FuzzMeNasmSubRegRel@8

global @FuzzMeNasmCmpRegImm@8
global @FuzzMeNasmCmpRegReg@8
global @FuzzMeNasmCmpMemReg@8
global @FuzzMeNasmCmpMemImm@8
global @FuzzMeNasmCmpStkReg@8
global @FuzzMeNasmCmpRelReg@8
global @FuzzMeNasmCmpRegRel@8

global @FuzzMeNasmTestRegReg@8:

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

extern _crash 

@FuzzMeNasmCmpRegImm@8:

    cmp edx, 8
    jb .ret
    
    mov eax, [ecx]
    cmp eax, '1337' 
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmCmpRegReg@8:

    cmp edx, 8
    jb .ret
    
    mov ecx, [ecx]
    mov eax, '1337'
    cmp eax, ecx ; r32
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmCmpMemReg@8:

    cmp edx, 8
    jb .ret
    
    mov ecx, [ecx]
    lea eax, [cmpData]
    cmp ecx, [eax] ; r32
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmCmpMemImm@8:

    cmp edx, 8
    jb .ret
    
    cmp dword [ecx], '1337'
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmCmpStkReg@8:

    cmp edx, 8
    jb .ret
    
    sub esp, 0x60

    mov eax, '1337'
    mov [esp], eax
    mov ecx, [ecx]
    cmp ecx, [esp]
    jnz .retStack

    call _crash

.retStack:
    add esp, 0x60
.ret:
    ret

@FuzzMeNasmCmpRelReg@8:

    cmp edx, 8
    jb .ret
    
    mov ecx, [ecx]
    cmp [cmpData], ecx ; r32
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmCmpRegRel@8:

    cmp edx, 8
    jb .ret
    
    mov ecx, [ecx]
    cmp ecx, [cmpData] ; r32
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmSubRegImm@8:

    cmp edx, 8
    jb .ret
    
    mov eax, [ecx]
    sub eax, '1337' ; r32
    jnz .ret

    call _crash

.ret:
    ret

@FuzzMeNasmSubRegReg@8:
@FuzzMeNasmSubMemReg@8:
@FuzzMeNasmSubStkReg@8:
@FuzzMeNasmSubRelReg@8:

@FuzzMeNasmTestRegReg@8:

    cmp edx, 4
    jb .ret

    mov eax, [ecx]
    sub eax, '1337'
    test eax, eax
    jnz .ret

    call _crash

.ret:
    ret

WinMain:

    xor eax, eax
    inc eax
    ret


; nasm -f win64 ..\src\asm\simplest.asm
; IF %ERRORLEVEL% NEQ 0 Exit /B
; link.exe /DLL /ENTRY:WinMain ..\src\asm\simplest.obj
