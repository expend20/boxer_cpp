#include "pe.h"
#include "say.h"

#include <ehdata.h>

#ifdef _WIN64
std::vector<pehelper::runtime_function>* pehelper::pe::get_runtime_functions(){
    return &m_exception_funcs;
}

pehelper::runtime_function* pehelper::pe::get_runtime_function(size_t rip){
    for (size_t i = 0; i < m_exception_funcs.size(); i++) {
        //SAY_DEBUG("%p %p", m_exceptionFuncs[i].begin, m_exceptionFuncs[i].end);
        if (rip >= m_exception_funcs[i].begin &&
                rip < m_exception_funcs[i].end) {
            return &m_exception_funcs[i];
        }
    }
    return 0;
}

pehelper::runtime_function_united* pehelper::pe::get_runtime_function_united(
        size_t rip){
    for (size_t i = 0; i < m_exception_united_funcs.size(); i++) {
        if (rip >= m_exception_united_funcs[i].begin &&
                rip < m_exception_united_funcs[i].end) {
            return &m_exception_united_funcs[i];
        }
    }
    return 0;
}
#endif

void pehelper::pe::extract_imports(){
    auto nt = get_nt_headers();
    ASSERT(nt);

    auto impRemote = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        .VirtualAddress;
    auto impSize = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        .Size;

    // TODO: delay import, bound import

    if (!impRemote || !impSize) {
        SAY_WARN("can't extract import data (no import directory entry)\n");
        return;
    }

    // We assume import is located in .rdata
    auto sect = get_section(".rdata");
    ASSERT(sect);
    auto imp = (IMAGE_IMPORT_DESCRIPTOR*)sect->data.get_mem_by_addr(
            m_remote_addr + (size_t)impRemote);
    // if it's not in .rdata let's try .idata
    if (!imp) {
        sect = get_section(".idata");
        ASSERT(sect);
        imp = (IMAGE_IMPORT_DESCRIPTOR*)sect->data.get_mem_by_addr(
                m_remote_addr + (size_t)impRemote);
        if (!imp) {
            SAY_FATAL("Can't locate IMAGE_IMPORT_DESCRIPTOR in .rdata and "
                    ".idata\n");
        }
    }

    m_import.clear();
    size_t impBegin = (size_t)imp;
    while(1) {
        char* dllName = (char*)sect->data.get_mem_by_addr(
                imp->Name + m_remote_addr);
#ifdef _WIN64
        auto origFirstThunk = (IMAGE_THUNK_DATA64*)sect->data.get_mem_by_addr(
                imp->OriginalFirstThunk + m_remote_addr);
        auto firstThunk = (IMAGE_THUNK_DATA64*)sect->data.get_mem_by_addr(
                imp->FirstThunk + m_remote_addr);
#else
        auto origFirstThunk = (IMAGE_THUNK_DATA32*)sect->data.get_mem_by_addr(
                imp->OriginalFirstThunk + m_remote_addr);
        auto firstThunk = (IMAGE_THUNK_DATA32*)sect->data.get_mem_by_addr(
                imp->FirstThunk + m_remote_addr);
#endif

        SAY_DEBUG("dumping import from %s:", dllName);

        import_module mod;
        mod.name = dllName;

        while (origFirstThunk->u1.Ordinal) {

            if (!IMAGE_SNAP_BY_ORDINAL64(origFirstThunk->u1.Ordinal)) {

                size_t remoteAddr = origFirstThunk->u1.Function + m_remote_addr;
                auto origFirstThunkData = (IMAGE_IMPORT_BY_NAME*)
                    sect->data.get_mem_by_addr(remoteAddr);

                auto firstThunkData = (size_t)firstThunk->u1.Function;

                import_function impFunc;
                impFunc.name = origFirstThunkData->Name;
                impFunc.externAddr = (size_t)sect->data.get_tgt_by_local(
                        (size_t)firstThunk);

                SAY_DEBUG("%p %s", impFunc.externAddr, impFunc.name.c_str());
                mod.funcs.push_back(impFunc);

            } else {
                SAY_ERROR("Import by ordinal %x", origFirstThunk->u1.Ordinal);
                // TODO:
            }

            origFirstThunk++;
            firstThunk++;
        }

        m_import.push_back(mod);

        imp++;
        if (!imp->OriginalFirstThunk ||
                ((size_t)imp >= (size_t)(impBegin + impSize))) {
            break;
        }
    }

}

#ifdef _WIN64
void pehelper::pe::extract_exception_directory(){

    // TODO: example of using RtlLookupFunction Entry
    // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    /*
       {
       uint8_t buf[0x1000];
       memset(buf, 0x41, sizeof(buf));
       PUNWIND_HISTORY_TABLE historyTable = (PUNWIND_HISTORY_TABLE)buf;
       historyTable->Count = 0;
       historyTable->LowAddress = -1;
       historyTable->HighAddress = 0;
     *(uint32_t *)&historyTable->LocalHint = 0x1000000;
     size_t imBase = 0;

     auto runtimeFunc = RtlLookupFunctionEntry(
     (size_t)m_modPe.getRemoteAddr() + 0x30F0,
     &imBase, historyTable); // history table can be zero
     SAY_INFO("rf = %p", (size_t)runtimeFunc);

     }
     */
    // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

    auto nt = get_nt_headers();
    ASSERT(nt);

    size_t run_func_remote = ((size_t) nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress + get_remote_addr());
    auto run_func_size = nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (!run_func_size) {
        SAY_WARN("can't extract exception data (no exception directory entry)"
                "\n");
        return;
    }

    // We assume here that RUNTIME_FUNCIONs can be only located in .pdata
    auto pdata = get_section(run_func_remote);
    ASSERT(pdata->name == ".pdata");

    // Let's enumerate root structure
    RUNTIME_FUNCTION* ptr = (RUNTIME_FUNCTION*)
        pdata->data.get_mem_by_addr(run_func_remote);
    auto endPtr = (size_t)ptr + run_func_size;

    // We assume here that RUNTIME_FUNCSTION* data is pointing to .rdata section
    auto rdata = get_section(".rdata");
    ASSERT(rdata);

    // We assume here that RUNTIME_FUNCSTIONs are poiting to .text section
    auto text = get_section(".text");
    ASSERT(text);

    m_exception_funcs.clear();
    m_exception_united_funcs.clear();

    size_t prev_end = 0;
    size_t uni_start = 0;
    while((size_t)ptr < endPtr) {
        runtime_function rf = {0};

        rf.begin = ptr->BeginAddress + get_remote_addr();
        rf.end = ptr->EndAddress + get_remote_addr();
        rf.data = ptr->UnwindData + get_remote_addr();
        rf.rtPtr = pdata->data.get_tgt_by_local((size_t)ptr);

        if (prev_end != rf.begin) {
            if (uni_start) {
                runtime_function_united rfu;
                rfu.begin = uni_start;
                rfu.end = prev_end;
                m_exception_united_funcs.push_back(rfu);

            }
            uni_start = rf.begin;
        }

        auto ui = (UNWIND_INFO*)rdata->data.get_mem_by_addr(rf.data);
        /* Flags values:

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

*/
        if (ui->Flags & 1) {
            auto idx = ui->CountOfCodes;
            // Mind alignment
            if (idx & 1) idx += 1;
            size_t handlerDataLocal = (size_t)&ui->UnwindCode[idx];
            size_t handlerDataRemote = rdata->data.get_tgt_by_local(handlerDataLocal);
            size_t handlerCallback = (size_t)(*(uint32_t*)handlerDataLocal +
                    get_remote_addr());
            rf.handlerData = handlerDataRemote;
            rf.handlerCallback = handlerCallback;
        }

        //std::string fName = "";
        //if (GetOpts()->resolveSymbols){
        //  DWORD64 disp = 0;
        //  std::string name = helper::symbolByPtr(m_process, rf.begin, m_remoteAddr,
        //      m_moduleSize, &disp);
        //  if (!disp) fName = name;
        //}

        //if (GetOpts()->traceBB) {
        //  SAY_DEBUG("runtime function found, begin %p, end %p %s", rf.begin, rf.end,
        //      fName.c_str());
        //}
        m_exception_funcs.push_back(rf);

        prev_end = rf.end;
        ptr++;
    }

    runtime_function_united rfu;
    rfu.begin = uni_start;
    rfu.end = prev_end;
    m_exception_united_funcs.push_back(rfu);
}
#endif // _WIN64

size_t   pehelper::pe::get_section_count(){
    return m_sections.size();
}

pehelper::section*  pehelper::pe::get_section_by_idx(size_t idx){
    if (idx < m_sections.size()) {
        return &m_sections[idx];
    }
    else {
        return 0;
    }
}

pehelper::section* pehelper::pe::get_section(size_t addr){
    for( auto el = m_sections.begin(); el != m_sections.end(); el++){
        size_t sectBegin = m_remote_addr + el->sect_head.VirtualAddress;
        size_t sectEnd   = sectBegin + el->sect_head.Misc.VirtualSize;
        if (addr >= sectBegin && addr < sectEnd) {
            return &(*el);
        }
    }
    return 0;
}

pehelper::section* pehelper::pe::get_section(std::string name){
    for( auto el = m_sections.begin(); el != m_sections.end(); el++){
        if (!_stricmp(el->name.c_str(), name.c_str())) {
            return &(*el);
        }
    }
    SAY_WARN("Section %s not found\n", name.c_str());
    return 0;
}

void pehelper::pe::extract_sections() {

    /*
     * Let's enumerate sections and fill the data
     */
    auto dos = (IMAGE_DOS_HEADER*)m_img_header.addr_loc_old();
    ASSERT(dos->e_magic == IMAGE_DOS_SIGNATURE);

#ifdef _WIN64
    auto pe = (IMAGE_NT_HEADERS64*)((size_t)dos + dos->e_lfanew);
    ASSERT(pe->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
#else 
    auto pe = (IMAGE_NT_HEADERS*)((size_t)dos + dos->e_lfanew);
    ASSERT(pe->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
#endif 
    ASSERT(pe->Signature == IMAGE_NT_SIGNATURE);

    auto sect = (IMAGE_SECTION_HEADER*)((size_t)pe + sizeof(pe->Signature) +
            sizeof(pe->FileHeader) + pe->FileHeader.SizeOfOptionalHeader);
    m_nt_headers = pe;

    while( sect->VirtualAddress ) {

        SAY_DEBUG("sect: %8s %08x %08x %08x %08x %08x\n", sect->Name,
                sect->VirtualAddress, sect->Misc.VirtualSize,
                sect->PointerToRelocations, sect->SizeOfRawData,
                sect->Characteristics);

        pehelper::section s;
        s.data = mem_tool(m_process, m_remote_addr + sect->VirtualAddress,
                sect->SizeOfRawData);
        memcpy(&s.sect_head, sect, sizeof(*sect));
        char name[9] = {0};
        memcpy(name, sect->Name, sizeof(sect->Name));
        s.name = name;
        s.mod_base = m_remote_addr;

        m_sections.push_back(s);

        sect++;
    }

    return;
}

pehelper::pe::pe(HANDLE process, size_t data) {

    ASSERT(process);
    ASSERT(data);

    m_process    = process;
    m_remote_addr = data;

    m_img_header = mem_tool(m_process, m_remote_addr, 0x1000);

    extract_sections();
    //extract_imports();
    //extract_exception_directory();

}

