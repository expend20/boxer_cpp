[bits 32]
global @save_context@4

section .data

some_text: 
    db 'aaaaaaa', 0

section .text

@save_context@4:

; ecx points to _CONTEXT
;   +0x000 ContextFlags     : Uint4B
;   +0x004 Dr0              : Uint4B
;   +0x008 Dr1              : Uint4B
;   +0x00c Dr2              : Uint4B
;   +0x010 Dr3              : Uint4B
;   +0x014 Dr6              : Uint4B
;   +0x018 Dr7              : Uint4B
;   +0x01c FloatSave        : _FLOATING_SAVE_AREA
;   +0x08c SegGs            : Uint4B
;   +0x090 SegFs            : Uint4B
;   +0x094 SegEs            : Uint4B
;   +0x098 SegDs            : Uint4B
;   +0x09c Edi              : Uint4B
;   +0x0a0 Esi              : Uint4B
;   +0x0a4 Ebx              : Uint4B
;   +0x0a8 Edx              : Uint4B
;   +0x0ac Ecx              : Uint4B
;   +0x0b0 Eax              : Uint4B
;   +0x0b4 Ebp              : Uint4B
;   +0x0b8 Eip              : Uint4B
;   +0x0bc SegCs            : Uint4B
;   +0x0c0 EFlags           : Uint4B
;   +0x0c4 Esp              : Uint4B
;   +0x0c8 SegSs            : Uint4B
;   +0x0cc ExtendedRegisters : [512] UChar

    mov [ecx + 0xb0], eax
    mov [ecx + 0xac], ecx
    mov [ecx + 0xa8], edx
    mov [ecx + 0xa4], ebx

    mov eax, esp
    add eax, 4
    mov [ecx + 0xc4], eax ; esp
    mov [ecx + 0xb4], ebp
    mov [ecx + 0xa0], esi
    mov [ecx + 0x9c], edi

    mov eax, [esp]
    mov [ecx + 0xb8], eax ; eip

    ret
