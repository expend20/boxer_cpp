#include "tools.h"
#include "common.h"
#include "say.h"

#include <map>

#include <DbgHelp.h>

namespace tools {

    void write_minidump(const char* path, HANDLE proc, DWORD pid) 
    {
        auto hfile = CreateFileA(path,
               GENERIC_READ | GENERIC_WRITE,
               FILE_SHARE_READ | FILE_SHARE_WRITE,
               NULL,
               CREATE_ALWAYS,
               0,
               0);
        ASSERT(hfile != INVALID_HANDLE_VALUE);
        auto r = MiniDumpWriteDump(proc, 
                pid,
                hfile,
                MINIDUMP_TYPE::MiniDumpWithFullMemory,
                NULL,
                NULL,
                NULL);
        ASSERT(r);
        CloseHandle(hfile);
    }

    void write_minidump(const char* path, 
            PROCESS_INFORMATION* pi,
            EXCEPTION_RECORD* ex_rec) 
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        auto b = GetThreadContext(pi->hThread, &ctx);
        ASSERT(b);

        auto hfile = CreateFileA(path,
               GENERIC_READ | GENERIC_WRITE,
               FILE_SHARE_READ | FILE_SHARE_WRITE,
               NULL,
               CREATE_ALWAYS,
               0,
               0);
        ASSERT(hfile != INVALID_HANDLE_VALUE);

        EXCEPTION_POINTERS ex_poi;
        ex_poi.ExceptionRecord = ex_rec;
        ex_poi.ContextRecord = &ctx;

        MINIDUMP_EXCEPTION_INFORMATION ex_info;
        ex_info.ExceptionPointers = &ex_poi;
        ex_info.ThreadId = pi->dwThreadId;
        ex_info.ClientPointers = true;
        auto r = MiniDumpWriteDump(pi->hProcess, 
                pi->dwProcessId,
                hfile,
                MINIDUMP_TYPE::MiniDumpWithFullMemory,
                NULL,//&ex_info,
                NULL,
                NULL);
        ASSERT(r);
        CloseHandle(hfile);

    }


    size_t alloc_after_pe_image(
            HANDLE proc,
            size_t module_end, 
            size_t data_size,
            DWORD permissions) 
    {
        SAY_DEBUG("Allocating 0x%x bytes just after %p in process %d\n",
               data_size, module_end, proc);
        size_t new_alloc = 0;
        for (size_t ptr = module_end; ptr <= module_end + 0x80000000;
                ptr += 0x1000) {
            //SAY_DEBUG("Trying addr %p...\n", ptr);
            new_alloc = (size_t)VirtualAllocEx(
                    proc,
                    (void*)ptr, 
                    data_size,
                    MEM_COMMIT | MEM_RESERVE, 
                    permissions);
            if (!new_alloc) {
                //SAY_WARN("Can't alloc at %p, %s\n", 
                //        ptr, helper::getLastErrorAsString().c_str());
                continue;
            } else {
                SAY_DEBUG("Memory near module is allocated at %p:%x, requested "
                        "from %p (diff = %p)\n",
                        ptr, data_size, module_end, ptr - module_end);
                break;
            }
        }
        return new_alloc;
    }

    std::string get_path_by_handle(HANDLE handle) 
    {
        char mod_name[MAX_PATH];
        auto max_chars = GetFinalPathNameByHandleA(
                handle, 
                mod_name, 
                sizeof(mod_name), 
                0);
        if (!max_chars) SAY_FATAL("Can't get file path by handle %x", handle);
        std::string s = mod_name;
        return s;
    };

    std::string get_path_by_mod_name(const char* path, size_t max_chars) 
    {
        size_t i;
        for (i = max_chars; i != 0; i--) {
            if (path[i - 1] == '\\') break;
        }
        std::string s = &path[i];
        return s;
    };

    std::string get_mod_name_by_handle(HANDLE handle) 
    {
        auto path = get_path_by_handle(handle);
        auto s = get_path_by_mod_name(path.c_str(), path.size());
        return s;
    }

    std::string get_exception_name(DWORD code) {
        static std::map<DWORD, const char*> codes;
        if (!codes.size()) {
            codes[0x00000000L] = "STATUS_WAIT_0";
            codes[0x00000080L] = "STATUS_ABANDONED_WAIT_0";
            codes[0x000000C0L] = "STATUS_USER_APC";
            codes[0x00000102L] = "STATUS_TIMEOUT";
            codes[0x00000103L] = "STATUS_PENDING";
            codes[0x00010001L] = "DBG_EXCEPTION_HANDLED";
            codes[0x00010002L] = "DBG_CONTINUE";
            codes[0x40000005L] = "STATUS_SEGMENT_NOTIFICATION";
            codes[0x40000015L] = "STATUS_FATAL_APP_EXIT";
            codes[0x40010001L] = "DBG_REPLY_LATER";
            codes[0x40010003L] = "DBG_TERMINATE_THREAD";
            codes[0x40010004L] = "DBG_TERMINATE_PROCESS";
            codes[0x40010005L] = "DBG_CONTROL_C";
            codes[0x40010006L] = "DBG_PRINTEXCEPTION_C";
            codes[0x40010007L] = "DBG_RIPEXCEPTION";
            codes[0x40010008L] = "DBG_CONTROL_BREAK";
            codes[0x40010009L] = "DBG_COMMAND_EXCEPTION";
            codes[0x4001000AL] = "DBG_PRINTEXCEPTION_WIDE_C";
            codes[0x80000001L] = "STATUS_GUARD_PAGE_VIOLATION";
            codes[0x80000002L] = "STATUS_DATATYPE_MISALIGNMENT";
            codes[0x80000003L] = "STATUS_BREAKPOINT";
            codes[0x80000004L] = "STATUS_SINGLE_STEP";
            codes[0x80000026L] = "STATUS_LONGJUMP";
            codes[0x80000029L] = "STATUS_UNWIND_CONSOLIDATE";
            codes[0x80010001L] = "DBG_EXCEPTION_NOT_HANDLED";
            codes[0xC0000005L] = "STATUS_ACCESS_VIOLATION";
            codes[0xC0000006L] = "STATUS_IN_PAGE_ERROR";
            codes[0xC0000008L] = "STATUS_INVALID_HANDLE";
            codes[0xC000000DL] = "STATUS_INVALID_PARAMETER";
            codes[0xC0000017L] = "STATUS_NO_MEMORY";
            codes[0xC000001DL] = "STATUS_ILLEGAL_INSTRUCTION";
            codes[0xC0000025L] = "STATUS_NONCONTINUABLE_EXCEPTION";
            codes[0xC0000026L] = "STATUS_INVALID_DISPOSITION";
            codes[0xC000008CL] = "STATUS_ARRAY_BOUNDS_EXCEEDED";
            codes[0xC000008DL] = "STATUS_FLOAT_DENORMAL_OPERAND";
            codes[0xC000008EL] = "STATUS_FLOAT_DIVIDE_BY_ZERO";
            codes[0xC000008FL] = "STATUS_FLOAT_INEXACT_RESULT";
            codes[0xC0000090L] = "STATUS_FLOAT_INVALID_OPERATION";
            codes[0xC0000091L] = "STATUS_FLOAT_OVERFLOW";
            codes[0xC0000092L] = "STATUS_FLOAT_STACK_CHECK";
            codes[0xC0000093L] = "STATUS_FLOAT_UNDERFLOW";
            codes[0xC0000094L] = "STATUS_INTEGER_DIVIDE_BY_ZERO";
            codes[0xC0000095L] = "STATUS_INTEGER_OVERFLOW";
            codes[0xC0000096L] = "STATUS_PRIVILEGED_INSTRUCTION";
            codes[0xC00000FDL] = "STATUS_STACK_OVERFLOW";
            codes[0xC0000135L] = "STATUS_DLL_NOT_FOUND";
            codes[0xC0000138L] = "STATUS_ORDINAL_NOT_FOUND";
            codes[0xC0000139L] = "STATUS_ENTRYPOINT_NOT_FOUND";
            codes[0xC000013AL] = "STATUS_CONTROL_C_EXIT";
            codes[0xC0000142L] = "STATUS_DLL_INIT_FAILED";
            codes[0xC00002B4L] = "STATUS_FLOAT_MULTIPLE_FAULTS";
            codes[0xC00002B5L] = "STATUS_FLOAT_MULTIPLE_TRAPS";
            codes[0xC00002C9L] = "STATUS_REG_NAT_CONSUMPTION";
            codes[0xC0000374L] = "STATUS_HEAP_CORRUPTION";
            codes[0xC0000409L] = "STATUS_STACK_BUFFER_OVERRUN";
            codes[0xC0000417L] = "STATUS_INVALID_CRUNTIME_PARAMETER";
            codes[0xC0000420L] = "STATUS_ASSERTION_FAILURE";
            codes[0xC00004A2L] = "STATUS_ENCLAVE_VIOLATION";
            codes[0xC0000515L] = "STATUS_INTERRUPTED";
            codes[0xC0000516L] = "STATUS_THREAD_NOT_RUNNING";
            codes[0xC0000718L] = "STATUS_ALREADY_REGISTERED";
            codes[0xC015000FL] = "STATUS_SXS_EARLY_DEACTIVATION";
            codes[0xC0150010L] = "STATUS_SXS_INVALID_DEACTIVATION";
        }
        auto findRes = codes.find(code);
        if (findRes == codes.end()) {
            return "Unknown exception";
        } else {
            return findRes->second;
        }
    }

    void update_thread_rip(HANDLE thread, size_t pc)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        auto b = GetThreadContext(thread, &ctx);
        if (!b) {
            SAY_INFO("Can't get threads context handle: %x, err: %s\n",
                    thread, helper::getLastErrorAsString().c_str());
        }
        ASSERT(b);

#ifdef _WIN64
        //SAY_DEBUG("Thread's current rip = %p (set to %p), rcx = %p, rdx = %p\n", 
        //        ctx.Rip, pc, ctx.Rcx, ctx.Rdx);
        ctx.Rip = pc;
#else
        //SAY_DEBUG("Thread's current eip = %p (set to %p), ecx = %p, edx = %p\n", 
        //        ctx.Eip, pc, ctx.Ecx, ctx.Edx);
        ctx.Eip = pc;
#endif
        b = SetThreadContext(thread, &ctx);
        ASSERT(b);
    }

    void update_thread_set_trap(HANDLE thread)
    {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        auto b = GetThreadContext(thread, &ctx);
        ASSERT(b);

        ctx.EFlags |= 0x100;
        b = SetThreadContext(thread, &ctx);
        ASSERT(b);
    }

};

