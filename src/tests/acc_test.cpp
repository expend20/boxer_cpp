#include <exception>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

extern size_t g_r = 0;
extern size_t get_gr() { return g_r; };
__forceinline  size_t DoNothing(size_t x)
{
    g_r += x;
    return g_r;
}

extern "C" __declspec(dllexport) void __cdecl crash()
{
    // OutputDebugString("blablabla");
    *(size_t *)0 = 0;
}

char oobrHeap(int idx)
{
    char *res = (char *)malloc(0x10);
    return res[idx];
}


extern "C" __declspec(dllexport) void WINAPIV
    FuzzMe1(const char *data, unsigned int len)
{
    static int i = 0;

    // printf("FuzzMe1: %d:%d:%s\n", ++i, len, data);

    if (len < 8)
        return;

    if (data[0] == '1')             // hello();
        if (data[1] == '3')         // hello();
            if (data[2] == '3')     // hello();
                if (data[3] == '7') // hello();
                    if (data[4] == '1')
                        if (data[5] == '3')         // hello();
                            if (data[6] == '3')     // hello();
                                if (data[7] == '7') // hello();
                                                    /*
                                                       if (data[8] == '3')// hello();
                                                       if (data[9] == '7')
                                                       if (data[10] == '3')// hello();
                                                       if (data[11] == '1')// hello();
                                                       if (data[12] == '3')// hello();
                                                       if (data[13] == '3')// hello();
                                                       if (data[14] == '7')
                                                       if (data[15] == '3')// hello();
                                                       if (data[16] == '1')// hello();
                                                       if (data[17] == '3')// hello();
                                                       if (data[18] == '3')// hello();
                                                       if (data[19] == '7')
                                                       */
                                    crash();
}



extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeTimeout(const char *data, unsigned int len)
{
    // printf("FuzzMe1: %d:%d:%s\n", ++i, len, data);

    if (len < 8)
        return;

    if (data[0] == '1')             // hello();
    if (data[1] == '3')         // hello();
    if (data[2] == '3')     // hello();
    if (data[3] == '7') // hello();
    if (data[4] == '1')
    if (data[5] == '3')         // hello();
    if (data[6] == '3')     // hello();
    if (data[7] == '7') {
        crash();
    }
    else {
        // cpu burn
        while(1) {
            static size_t i = 0;
            DoNothing(i * 2);
        }
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMe2_inc(const char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "13371337";
    if (len < 8)
        return;
    for (size_t i = 0; i < 8; i++) {
        if (magic[i] != data[i]) {
            matched = false;
            break;
        }
    }

    if (matched)
        crash();
}

typedef int(__cdecl *t_memcmp)(void const *_Buf1, void const *_Buf2,
                               size_t _Size);
typedef int(__cdecl *t_strcmp)(void const *_Buf1, void const *_Buf2);

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMe3(const char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "13371337133713371337133713371337";

    if (len < 32)
        return;

    t_memcmp proc = memcmp;
    if (!proc(data, magic, 32)) {
        crash();
    }
}

#if _WIN64

extern "C" void FuzzMeNasmCmpRegImm(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpRegReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpMemReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpMemImm(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpStkReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpRelReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmCmpRegRel(const char *data, unsigned int len);

extern "C" void FuzzMeNasmSubRegImm(const char *data, unsigned int len);
extern "C" void FuzzMeNasmSubRegReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmSubMemReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmSubStkReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmSubRelReg(const char *data, unsigned int len);
extern "C" void FuzzMeNasmSubRegRel(const char *data, unsigned int len);

extern "C" void FuzzMeNasmCmpRelReg(const char *data, unsigned int len);

extern "C" void FuzzMeNasmTestRegReg(const char *data, unsigned int len);

#else

extern "C" void __fastcall FuzzMeNasmCmpRegImm(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpRegReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpMemReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpMemImm(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpStkReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpRelReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmCmpRegRel(const char *data, unsigned int len);

extern "C" void __fastcall FuzzMeNasmSubRegImm(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmSubRegReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmSubMemReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmSubStkReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmSubRelReg(const char *data, unsigned int len);
extern "C" void __fastcall FuzzMeNasmSubRegRel(const char *data, unsigned int len);

extern "C" void __fastcall FuzzMeNasmCmpRelReg(const char *data, unsigned int len);

extern "C" void __fastcall FuzzMeNasmTestRegReg(const char *data,
                                             unsigned int len);

#endif

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeSubRegImm(const char *data, unsigned int len)
{
    FuzzMeNasmSubRegImm(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeSubRegReg(const char *data, unsigned int len)
{
    FuzzMeNasmSubRegReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeSubMemReg(const char *data, unsigned int len)
{
    FuzzMeNasmSubMemReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeSubStkReg(const char *data, unsigned int len)
{
    FuzzMeNasmSubStkReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeSubRelReg(const char *data, unsigned int len)
{
    FuzzMeNasmSubRelReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpRegImm(const char *data, unsigned int len)
{
    FuzzMeNasmCmpRegImm(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpRegReg(const char *data, unsigned int len)
{
    FuzzMeNasmCmpRegReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpMemReg(const char *data, unsigned int len)
{
    FuzzMeNasmCmpMemReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpMemImm(const char *data, unsigned int len)
{
    FuzzMeNasmCmpMemImm(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpStkReg(const char *data, unsigned int len)
{
    FuzzMeNasmCmpStkReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpRelReg(const char *data, unsigned int len)
{
    FuzzMeNasmCmpRelReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeCmpRegRel(const char *data, unsigned int len)
{
    FuzzMeNasmCmpRegRel(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeTestRegReg(const char *data, unsigned int len)
{
    FuzzMeNasmTestRegReg(data, len);
    return;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr0(char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "The Magic 1337 strcmp"; // 7133\x00";

    size_t min_sz = len < sizeof(magic) - 1 ? len : sizeof(magic) - 1;
    data[len - 1] = 0;
    t_memcmp proc = (t_memcmp)strcmp;
    if (!proc) {
        MessageBox(0, "no strcmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr1(char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "The Magic 1337 stricmp"; // 7133\x00";

    size_t min_sz = len < sizeof(magic) - 1 ? len : sizeof(magic) - 1;
    data[len - 1] = 0;
    t_memcmp proc = (t_memcmp)stricmp;
    if (!proc) {
        MessageBox(0, "no stricmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr2(char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "The Magic 1337 strnicmp"; // 7133\x00";

    size_t min_sz = len < sizeof(magic) - 1 ? len : sizeof(magic) - 1;
    t_memcmp proc = (t_memcmp)strnicmp;
    if (!proc) {
        MessageBox(0, "no strncmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)){
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr3(char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "The Magic 1337 strncmp"; // 7133\x00";

    size_t min_sz = len < sizeof(magic) - 1 ? len : sizeof(magic) - 1;
    t_memcmp proc = (t_memcmp)strncmp;
    if (!proc) {
        MessageBox(0, "no strncmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr4(char *data, unsigned int len)
{
    bool matched = true;
    wchar_t magic[] = L"1337 wcsni"; // 7133\x00";

    if (len <= sizeof(magic)) return;

    size_t min_sz = len < sizeof(magic) - sizeof(magic[0]) ? 
        len : sizeof(magic) - sizeof(magic[0]);
    min_sz /= 2;
    t_memcmp proc = (t_memcmp)_wcsnicmp;
    if (!proc) {
        MessageBox(0, "no wcsnicmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr5(char *data, unsigned int len)
{
    bool matched = true;
    wchar_t magic[] = L"1337 wcsn"; // 7133\x00";

    size_t min_sz = len < sizeof(magic) - sizeof(magic[0]) ? 
        len : sizeof(magic) - sizeof(magic[0]);
    min_sz /= 2;

    t_memcmp proc = (t_memcmp)wcsncmp;
    if (!proc) {
        MessageBox(0, "no wcsncmp found", 0, 0);
        return;
    }
    if (!proc(magic, data, min_sz)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr6(char *data, unsigned int len)
{
    bool matched = true;
    wchar_t magic[] = L"1337 wcsi"; // 7133\x00";

    if (len <= sizeof(magic)) return;
    if (len % 2) { // align to two byte boundary
        len = len - 1;
    }
    data[len - 1] = 0;
    data[len - 2] = 0;

    t_strcmp proc = (t_strcmp)_wcsicmp;

    if (!proc) {
        MessageBox(0, "no wcsicmp found", 0, 0);
        return;
    }
    if (!proc(magic, data)) {
        crash();
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzStr7(char *data, unsigned int len)
{
    bool matched = true;
    wchar_t magic[] = L"1337 wcs"; // 7133\x00";

    if (len <= sizeof(magic)) return;
    if (len % 2) { // align to two byte boundary
        len = len - 1;
    }
    data[len - 1] = 0;
    data[len - 2] = 0;

    auto proc = (t_strcmp)wcscmp;
    if (!proc) {
        MessageBox(0, "no wcsnicmp found", 0, 0);
        return;
    }
    if (!proc(magic, data)) {
        crash();
    }
}

extern "C" __declspec(dllexport) bool WINAPIV
    FuzzMe4(const char *data, unsigned int len)
{
    bool matched = true;
    if (len < 8) return false;

    // cmp dword ptr [rax], 0x61626364
    if (*(uint32_t *)((size_t)data) == 0x37333331 &&
        *(uint32_t *)((size_t)data + 4) == 0x37333331
        /*
         *(uint32_t*)((size_t)data+8) == 0x6c6B6A69 &&
         *(uint32_t*)((size_t)data+12) == 0x706f6e6d &&
         *(uint32_t*)((size_t)data+16) == 0x74737271
         */
    ) {
        crash();
        return true;
    }
}

extern "C" __declspec(dllexport) bool WINAPIV
    FuzzMe5(const char *data, unsigned int len)
{
    bool matched = true;

    // debug:
    // movzx eax, word ptr [rcx+rax*1+0x1]
    // cmp eax, 0x6162
    //
    // optimized:
    // mov r8d, 0x6162
    // cmp word ptr [rcx+rdx*2], r8w
    if (len < 8)
        return false;

    for (int i = 0; i < 8; i += 4) {
        if (*(uint8_t *)(data + i) != '3' ||
            *(uint8_t *)(data + i + 2) != '7') {
            matched = false;
            break;
        }
    }
    if (matched)
        crash();
    return matched;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMe6(const char *data, unsigned int len)
{
    bool matched = true;

    if (len < 8)
        return;

    // cmp dword ptr [rax], 0x61626364
    if (*(uint32_t *)((size_t)data) == '7331' &&
        *(uint32_t *)((size_t)data + 4) == '7332') {
        crash();
    }

    //if (*(uint32_t *)((size_t)data) == '1111' ||
    //    *(uint32_t *)((size_t)data) == '1211' ||
    //    *(uint32_t *)((size_t)data) == '1311' ||
    //    *(uint32_t *)((size_t)data) == '11l1' ||
    //    *(uint32_t *)((size_t)data) == '1x11' ||
    //    *(uint32_t *)((size_t)data) == '11v1' ||
    //    *(uint32_t *)((size_t)data) == '111p') {
    //    crash();
    //}
}

void markFunc(const char *str) { GetTickCount64(); }

uint32_t seed = 0; // GetTickCount();

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMe7(const char *data, unsigned int len)
{
    size_t res = 0;

    if (len < 8)
        return 0;

    if (!seed) {
        markFunc("unstable2");
        seed = 1;
    }
    if (*(uint32_t *)((size_t)data) == '7331' &&
        *(uint32_t *)((size_t)data + 4) == '7331') {

        crash();
    }
    return res;
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMe8(const char *data, unsigned int len)
{

    size_t count = 0;
    if (len < 8)
        return 0;

    for (size_t i = 0; i < len; i++) {
        char c = data[i];
        switch (c) {
        case '3':
            if ((i >= 1 && i <= 2) || (i >= 5 && i <= 6)) {
                count++;
            }
            break;
        case '1':
            if (i == 0 || i == 4) {
                count++;
            }
            break;
            /*
        case '7':
            if (i == 3 || i == 7) {
                count++;
            }
            break;
        case 'a':
            count -= 1;
            break;
        case 'b':
            count -= 2;
            break;
        case 'c':
            count -= 3;
            break;
               case 'd':
               count -= 4;
               break;
               case 'e':
               count -= 5;
               break;
               case 'f':
               count -= 6;
               break;
               case 'g':
               count -= 7;
               break;
               case 'h':
               count -= 8;
               break;
               case 'i':
               count -= 9;
               break;
               case 'j':
               count -= 10;
               break;
               case 'k':
               count -= 11;
               break;
               case 'l':
               count -= 12;
               break;
               case 'm':
               count -= 13;
               break;
               case 'n':
               count -= 14;
               break;
               case 'o':
               count -= 15;
               break;
               case 'p':
               count -= 16;
               break;
               */
        }
    }

    if (count == 6) {
        crash();
    }

    return count;
}

class TestClass {
  public:
    virtual void foo();
    virtual void bar();
};

class TestClass2 : public TestClass {
  public:
    virtual void foo();
};

void TestClass::bar() { printf("TestClass: bar()\n"); }

void TestClass::foo() { printf("TestClass: foo()\n"); }

void TestClass2::foo()
{
    printf("TestClass2: foo()\n");
    TestClass::foo();
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeVtable(const char *data, unsigned int len)
{
    TestClass *tc = new TestClass2();

    tc->foo();
    tc->bar();

    return 0;
}

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    //__debugbreak();
    printf("[F] in filter.");
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        printf("[F] caught AV as expected.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }
    else {
        printf("[F] didn't catch AV, unexpected.\n");
        return EXCEPTION_CONTINUE_SEARCH;
    };
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeSEH_0(const char *data, unsigned int len)
{

    printf("[0] this is open block 1 ->\n");

    if (*(uint32_t *)((size_t)data) == 0x37333332) {
        *(size_t *)0 = 0;
    }

    __try {

        printf("[1] this is try block 1\n");

        __try {

            printf("[2] this is try block 2\n");
            // if (data[0] == 'Y') printf("[2] first letter is Y\n");
            *(size_t *)0 = 0;
        }
        __finally {

            printf("[2] this is finally block\n termination is ");
            printf(AbnormalTermination() ? "\tabnormal\n" : "\tnormal\n");
        }

        if (data[0] == 'Y')
            printf("[1] first letter is Y\n");
        *(size_t *)0 = 0;
    }

    __except (filter(GetExceptionCode(), GetExceptionInformation())) {

        printf("[E] this is except block\n");
    }

    printf("[0] this is end open block <-\n");
    if (*(uint32_t *)((size_t)data) == 0x37333331) {
        *(size_t *)0 = 0;
    }

    return 0;
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeSEH(const char *data, unsigned int len)
{
    if (len < 8)
        return 0;

    __try {

        if (*(size_t *)data == 0x37333331) {
            crash();
            //*(size_t *)0x123 = 0x321;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("in exception execute handler");
        if (*(size_t *)&data[4] == 0x37333332) {
            crash();
        }
    }
    return 0;
}

struct MyException : public std::exception {
    const char *what() const throw() { return "C++ Exception"; }
};

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeCPPEH(const char *data, unsigned int len)
{
    try {
        //printf("Throwing CPPEH ...\n");
        DoNothing(1);
        throw MyException();
        DoNothing(2);
    }
    catch (MyException &e) {
        //printf("In CPPEH handler\n");
        DoNothing(3);
    }

    //printf("The end of the function\n");
    if (*(size_t *)data == 0x37333331) {
        crash();
    }
    return 1;
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeDWORD(const char *data, unsigned int len)
{
    DWORD d = 0;
    if (len < 8)
        return 0;

    if (*(uint32_t *)((size_t)data) > 0xefffffff) {
        d++;
        // OutputDebugStringA("~");
        if (*(uint32_t *)((size_t)data + 4) > 0xefffffff) {
            d++;
            // OutputDebugStringA("~");
            crash();
        }
    }
    return d;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeStack(const char *data, unsigned int len)
{
    if (len < 8)
        return;

    char stackBuf[MAX_PATH] = {0};
    memcpy(stackBuf, data, len > MAX_PATH ? MAX_PATH : len);

    if (*(uint32_t *)stackBuf == '7331' &&
        *(uint16_t *)&stackBuf[4] == 0x1337 &&
        *(uint16_t *)&stackBuf[6] == 0xBEEF
        ) {
        crash();
    }
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeStackOverflow(const char *data, unsigned int len)
{

    char sdata[1024];
    memset(sdata, 0, sizeof(sdata));
    memcpy(sdata, data, sizeof(sdata) < len ? sizeof(sdata) : len);

    if (len >= 8 
            && *(uint8_t *)(data + 0) == '1'
            && *(uint8_t *)(data + 1) == '3'
            && *(uint8_t *)(data + 2) == '3'
            && *(uint8_t *)(data + 3) == '7'
            ) {
        return FuzzMeStackOverflow(sdata, len);
    }
    return 0;
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeOOBR(const char *data, unsigned int len)
{

    char sdata[1024];
    memset(sdata, 0, sizeof(sdata));
    memcpy(sdata, data, sizeof(sdata) < len ? sizeof(sdata) : len);

    if (len >= 8 
            && *(uint8_t *)(data + 0) == '1'
            && *(uint8_t *)(data + 1) == '3'
            && *(uint8_t *)(data + 2) == '3'
            && *(uint8_t *)(data + 3) == '7'
            ) {
        auto ptr = (char*)malloc(0x10);
        auto x = ptr[0x10];
        return (size_t)x;
    }
    return 0;
}

// _chkstk
// https://docs.microsoft.com/en-us/windows/win32/devnotes/-win32-chkstk
// Called by the compiler when you have more than one page of local variables
// in your function. ... for x64 compilers it is 8K.
//
extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeStackChkstk(const char *data, unsigned int len)
{

    char sdata[1024 * 9];
    memset(sdata, 0, sizeof(sdata));
    memcpy(sdata, data, len);
    if (len < 8) return 0;

    if (*(uint32_t *)data == '1337') {
        return 1 + FuzzMeStackChkstk(sdata, len);
    }
    return 0;
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeHeapCorruption(const char *data, unsigned int len)
{

    if (len < 8) return;
    auto data2 = malloc(0x100);
    if (*(uint32_t *)data == '1337') {
        memset(data2, 0, 0x2000);
    }
    free(data2);
}

typedef struct _MY_PATTERN {
    const char *pattern;
    size_t offset;
    size_t size;
} MY_PATTERN;

typedef struct _MY_PATTERNS {
    const MY_PATTERN *patterns;
    size_t size;
} MY_PATTERNS;

bool mymemcmp(const char *data0, const char *data1, size_t sz)
{
    for (size_t i = 0; i < sz; i++) {
        if (data0[i] != data1[i])
            return true;
    }

    return false;
}
extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeMyMemcmp(const char *data, unsigned int len)
{

    if (len < 8)
        return;

    if (!mymemcmp("1337", data, 4) &&
            !mymemcmp("beef", data + 4, 4)) {
        *(char*)0 = 0;
    }
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMePatternMatch_idx(const char *data, unsigned int len)
{

    static MY_PATTERN pat0[] = {{"XB00", 0, 4}, {"00CD", 4, 4}};
    static MY_PATTERN pat1[] = {{"1003", 8, 4}, {"3007", 12, 4}};
    //static MY_PATTERN pat2[] = {{"1300", 0, 4}, {"0037", 4, 4}};
    //static MY_PATTERN pat3[] = {{"0013", 0, 4}, {"3700", 4, 4}};
    static uint8_t matched = 0;

    if (len < 8)
        return -1;

    static MY_PATTERNS patterns0[] = {
        {pat0, 2}, {pat1, 2}, 
        //{pat2, 2}, {pat3, 2}
    };

    size_t res = -1;
    size_t i;
    size_t j;
    for (i = 0; i < sizeof(patterns0) / sizeof(patterns0[0]); i++) {

        res = i;
        for (j = 0; j < patterns0[i].size; j++) {

            // printf("checking %d %d\n", i, j);

            auto tgtPtr = patterns0[i].patterns[j].pattern;
            size_t tgtOffset = patterns0[i].patterns[j].offset;
            size_t tgtSize = patterns0[i].patterns[j].size;

            // if (tgtOffset + tgtSize > len) {
            //    //printf("bounds not matched %d, %d\n", tgtOffset + tgtSize,
            //    len); return -1;
            //}

            if (mymemcmp(&data[tgtOffset], tgtPtr, tgtSize)) {
                res = -1;
                break;
            }
        }
        if (j == patterns0[i].size) {
            matched |= (1 << i);
        }
    }

    if (matched == 0x3)
        crash();
    return res;
}


extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeBigStr(const char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "133713371337133713371337133713371337";
    // if (len != 8) printf("len = %d\n", len);

    for (size_t i = 0; i < sizeof(magic); i++) {

        if (i == len) {
            break;
        }

        if (magic[i] != data[i]) {
            matched = false;
            break;
        }
    }

    if (matched)
        crash();
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeNotSoBigStr(const char *data, unsigned int len)
{
    bool matched = true;
    char magic[] = "aaaaaaaaaaaaaaaaaaaa";
    if (len > sizeof(magic)) return;

    for (size_t i = 0; i < sizeof(magic); i++) {

        if (i == len) {
            break;
        }

        if (magic[i] != data[i]) {
            matched = false;
            break;
        }
    }

    if (matched)
        crash();
}

#pragma pack(push,1)
    typedef struct _CHUNK {
        uint8_t name;
        uint8_t size;
    } CHUNK;
#pragma pack(pop)

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeWithoutSymbolic(const char *data, size_t len)
{
    uint8_t expectedChunkNames[] = {'a', 'b', 'c'};
    uint8_t expectedChunkSizes[] = {2, 3, 4};
    uint8_t actualChunkSizes[] = {0, 0, 0};
    size_t validChunks = 0;

    auto ptr = (CHUNK*)data;

    while((size_t)ptr + sizeof(CHUNK) < (size_t)data + len) {
        for (size_t i = 0; i < 3; i++) {
            if (ptr->name == expectedChunkNames[i]) {
                actualChunkSizes[i] = ptr->size;
                validChunks += 1;
            }
        }

        if (!ptr->size) break;
        ptr = (CHUNK*)((size_t)ptr + ptr->size);
    }
    
    if (validChunks == 3) {
        size_t i = 0;
        for (; i < 3; i++) {
            if (actualChunkSizes[i] != expectedChunkSizes[i]) {
                break;
            }
        }
        if (i == 3) 
            *(size_t*)0 = 0;
    }
}

extern "C" __declspec(dllexport) void WINAPIV
    FuzzMeAvoid(const char *data, size_t len)
{
    // Several solutions for this one, to test find/avoid feautre
    size_t expectedChunks1[] = {'foo_', 'bar_'};
    size_t expectedChunks2[] = {'baz_', 'qux_'};

    if (len < 8)
        return;

    if (*(uint32_t *)((size_t)data + 4*0) == 'foo_' 
        && *(uint32_t *)((size_t)data + 4*1) == 'bar_') {
        *(char*)0 = 0;
    }

    if (*(uint32_t *)((size_t)data + 4*0) == 'baz_' 
        && *(uint32_t *)((size_t)data + 4*1) == 'qux_') {
        *(char*)0 = 0;
    }

    return;
}

extern "C" __declspec(dllexport) size_t WINAPIV
    FuzzMeTestImm(const char *data, size_t len)
{
    if (len < 8)
        return 0;

    size_t r = 0;
    if (data[0] == (char)0xfe) {
        if (!(*(uint32_t*)&data[0] & 0x100)) {
            r++;
            if (!(*(uint32_t*)&data[0] & 0x10100)) {
                r++;
                *(char*)0 = 0;
            }
        }
    }
    return r;
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason,
                    _In_ LPVOID lpvReserved)
{

    if (fdwReason == DLL_PROCESS_ATTACH) {
        OutputDebugStringA("AccTest: loaded");
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        OutputDebugStringA("AccTest: unloaded");
    }
    return TRUE;
}

