#include "strcov.h"
#include "say.h"

strcmpcov *strcmpcov::m_inst = 0;

strcmpcov::strcmpcov()
{
    if (m_inst) SAY_FATAL("Only one instance of strcmpcov allowed\n");
    m_inst = this;
}

strcmpcov::~strcmpcov()
{
    m_inst = 0;
}

void strcmpcov::install(std::vector<pehelper::import_module>* imports)
{
    for (auto &import: *imports) {

        SAY_DEBUG("import %s\n", import.name.c_str());

        import.sect->data.make_writeable();

        for (auto &func: import.funcs) {
            //SAY_INFO("%s.%s %p\n", import.name.c_str(), func.name.c_str(),
            //        func.externAddr);
            auto orig = *(size_t*)func.externAddr;
            bool should_save = false;

            if (strstr(func.name.c_str(), "strcmp")) {
                SAY_INFO("Patching strcmp: %p -> %p\n", func.externAddr,
                        __strcmp);
                *(size_t*)func.externAddr = (size_t)__strcmp;
                should_save = true;
            }
            else if (strstr(func.name.c_str(), "stricmp")) {
                SAY_INFO("Patching stricmp: %p -> %p\n", func.externAddr,
                        __stricmp);
                *(size_t*)func.externAddr = (size_t)__stricmp;
                should_save = true;
            }
            else if (strstr(func.name.c_str(), "strncmp")) {
                SAY_INFO("Patching strncmp: %p -> %p\n", func.externAddr,
                        __strncmp);
                *(size_t*)func.externAddr = (size_t)__strncmp;
                should_save = true;
            }
            else if (strstr(func.name.c_str(), "strnicmp")) {
                SAY_INFO("Patching strnicmp: %p -> %p\n", func.externAddr,
                        __strnicmp);
                *(size_t*)func.externAddr = (size_t)__strnicmp;
                should_save = true;
            }
            else if (strstr(func.name.c_str(), "memcmp")) {
                SAY_INFO("Patching memcmp: %p -> %p\n", func.externAddr,
                        __strnicmp);
                *(size_t*)func.externAddr = (size_t)__memcmp;
                should_save = true;
            }

            if (should_save) 
                m_saved.push_back(std::make_pair(func.externAddr, orig));
        }
        import.sect->data.restore_prev_protection();
    }
}

void strcmpcov::uninstall()
{
    for (auto &v: m_saved) {
        *(size_t*)v.first = v.second;
    }
    m_saved.clear();
}

int strcmpcov::__strcmp(char* str1, char* str2) {
    //SAY_INFO("strcmp: %s %s\n", str1, str2);
    auto res = strcmp(str1, str2);
    auto s1 = strlen(str1);
    auto s2 = strlen(str2);
    if (res && !m_inst->m_stopped) {
        m_inst->add_to_processing((uint8_t*)str1, (uint8_t*)str2, 
                s1 > s2 ? s2 : s1, true);
    }
    return res;
}

int strcmpcov::__stricmp(char* str1, char* str2) {
    //SAY_INFO("stricmp: %s %s\n", str1, str2);
    auto res = _stricmp(str1, str2);
    auto s1 = strlen(str1);
    auto s2 = strlen(str2);
    if (res && !m_inst->m_stopped) {
        m_inst->add_to_processing((uint8_t*)str1, (uint8_t*)str2, 
               s1 > s2 ? s2 : s1, true);
    }
    return res;
}

int strcmpcov::__strncmp(char* str1, char* str2, size_t n) {
    //SAY_INFO("strncmp: %s %s %d\n", str1, str2, n);
    auto res = strncmp(str1, str2, n);
    if (res && !m_inst->m_stopped) {
        m_inst->add_to_processing((uint8_t*)str1, (uint8_t*)str2, n, true);
    }
    return res;
}

int strcmpcov::__strnicmp(char* str1, char* str2, size_t n) {
    //SAY_INFO("strnicmp: %s %s %d\n", str1, str2, n);
    auto res = _strnicmp(str1, str2, n);
    if (res && !m_inst->m_stopped) {
        m_inst->add_to_processing((uint8_t*)str1, (uint8_t*)str2, n, true);
    }
    return res;
}

int strcmpcov::__memcmp(void *buf1, void *buf2, size_t count) {
    //SAY_INFO("memcmp: %p %p %d\n", buf1, buf2, count);
    auto res = memcmp(buf1, buf2, count);
    if (res && !m_inst->m_stopped) {
        m_inst->add_to_processing((uint8_t*)buf1, (uint8_t*)buf2, count, false);
    }
    return res;
}

void strcmpcov::add_to_processing(uint8_t* p1, uint8_t *p2, size_t sz,
        bool add_zero)
{
    std::vector<uint8_t> v1;
    std::vector<uint8_t> v2;

    v1.resize(sz);
    v2.resize(sz);

    memcpy(&v1[0], p1, v1.size());
    memcpy(&v2[0], p2, v2.size());

    strcmp_data el;
    el.buf1 = std::move(v1);
    el.buf2 = std::move(v2);
    el.should_add_zero = add_zero;
    m_data.push_back(std::move(el));
}
