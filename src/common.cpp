#include "common.h"
#include "Say.h"

#include <stdio.h>
#include <stdlib.h>

#include <TlHelp32.h>
#include <strsafe.h>
#include <windows.h>

#include <filesystem>
#include <sys/stat.h>

namespace helper {

size_t writeFile(const char *filePath, const char *fileData, size_t fileLen,
                 const char *access)
{
    FILE *file = 0;
    size_t result = 0;

    file = fopen(filePath, access);
    if (!file) {
        printf("[!] Can't write file %s, with '%s' access\n", filePath, access);
        return 0;
    }

    result = fwrite(fileData, 1, fileLen, file);
    fclose(file);
    return result;
}

char *getAllocTempFile(char *ext, char *prefix)
{
    char *res = 0;
    char tmp[64];

    res = (char *)malloc(MAX_PATH);

    do {

        if (!GetCurrentDirectory(MAX_PATH, res)) {
            SAY_ERROR("can't alloc %d bytes for path\n", MAX_PATH);
            break;
        }

        if (!SUCCEEDED(StringCchCat(res, MAX_PATH, "\\"))) {
            SAY_ERROR("str error\n");
            break;
        }

        if (prefix) {

            if (!SUCCEEDED(StringCchCat(res, MAX_PATH, prefix))) {
                SAY_ERROR("str error\n");
                break;
            }

            if (!SUCCEEDED(StringCchCat(res, MAX_PATH, "_"))) {
                SAY_ERROR("str error\n");
                break;
            }
        }

        if (!SUCCEEDED(StringCchPrintf(tmp, sizeof(tmp), "%d",
                                       GetCurrentProcessId()))) {
            SAY_ERROR("str error 2\n");
            break;
        }

        if (!SUCCEEDED(StringCchCat(res, MAX_PATH, tmp))) {
            SAY_ERROR("str error\n");
            break;
        }

        if (!SUCCEEDED(StringCchCat(res, MAX_PATH, "."))) {
            SAY_ERROR("str error\n");
            break;
        }

        if (ext) {
            if (!SUCCEEDED(StringCchCat(res, MAX_PATH, ext))) {
                SAY_ERROR("str error\n");
                break;
            }
        }
        else {
            if (!SUCCEEDED(StringCchCat(res, MAX_PATH, ".bin"))) {
                SAY_ERROR("str error\n");
                break;
            }
        }

    } while (0);

    return res;
}

wchar_t *asciiToUnicodeAlloc(const char *in, size_t sz, bool addZero)
{
    size_t len = 0;
    size_t len2 = 0;
    wchar_t *res = 0;

    if (!sz) {
        if (!SUCCEEDED(StringCchLengthA(in, STRSAFE_MAX_CCH, &len))) {
            SAY_ERROR("can't get len of %s\n", in);
            return res;
        }
    }
    else {
        len = sz;
    }

    if (addZero) {
        len2 = len + 1;
    }
    else {
        len2 = len;
    }

    res = (wchar_t *)malloc(len2 * 2);
    if (!res) {
        SAY_ERROR("can't alloc %d bytes\n", len * 2);
        return res;
    }

    for (size_t i = 0; i < len; i++) {
        res[i] = in[i];
    }

    if (addZero) res[len] = 0;

    return res;
}


void UnicodeToAscii(wchar_t* in, char *out, size_t len)
{
    size_t i = 0;

    while(in[i]) {

        out[i] = (char)in[i];

        i++;
        if (len && i >= len) {
            break;
        }
    }

    return;
}

std::vector<uint8_t> readFile(const char *filePath)
{

    size_t fileSize = 0;
    auto data = readAllocFile(filePath, &fileSize);
    ASSERT(fileSize);
    ASSERT(data);

    std::vector<uint8_t> res;
    res.resize(fileSize);
    memcpy(&res[0], data, fileSize);
    return res;
}

char *readAllocFile(const char *filePath, size_t *fileLen)
{

    FILE *file = 0;
    long fsize = 0;
    char *buffer = 0;
    size_t result = 0;

    do {

        file = fopen(filePath, "rb");
        if (!file)
            break;

        fseek(file, 0, SEEK_END);
        fsize = ftell(file);
        fseek(file, 0, SEEK_SET);

        if (fileLen)
            *fileLen = fsize;

        buffer = (char *)malloc(sizeof(char) * fsize);
        if (!buffer)
            break;

        result = fread(buffer, 1, fsize, file);
        if (result != fsize)
            break;

    } while (0);

    if (file)
        fclose(file);

    if (buffer && (result != fsize)) {
        free(buffer);
        buffer = 0;
    }

    return buffer;
}

std::string hresultAsString(HRESULT hr)
{
    _com_error err(hr);
    std::string message(err.ErrorMessage());
    return message;
}

std::string moduleByPtr(size_t funcPtr, bool fullPath)
{

    MODULEENTRY32 me = {0};
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    me.dwSize = sizeof(me);
    Module32First(hSnapshot, &me);

    std::string res = "<NO_MODULE>";

    do {
        // LOG_DEBUG("%p:%p %s %p?", me.modBaseAddr, me.modBaseAddr +
        // me.modBaseSize,
        //    me.szExePath, funcPtr);
        if ((size_t)me.modBaseAddr <= funcPtr &&
            (size_t)(me.modBaseAddr + me.modBaseSize) > funcPtr) {
            if (fullPath) {
                res = me.szExePath;
            }
            else {
                res = me.szModule;
            }
            break;
        }

    } while (Module32Next(hSnapshot, &me));

    CloseHandle(hSnapshot);
    return res;
}

#include <strsafe.h>

void files2VectorDr(const char *path, std::vector<std::vector<uint8_t>> &res)
{
    LPCTSTR lpcszFolder = path;

    WIN32_FIND_DATA ffd;
    TCHAR szNextPath[MAX_PATH];
    HANDLE hFind = INVALID_HANDLE_VALUE;

    StringCchCopy(szNextPath, MAX_PATH, lpcszFolder);
    StringCchCat(szNextPath, MAX_PATH, TEXT("\\*"));

    // Find the first file in the directory.

    hFind = FindFirstFile(szNextPath, &ffd);

    if (INVALID_HANDLE_VALUE == hFind) {
        return;
    }

    // List all the files in the directory with some info about them.

    TCHAR szOutLine[MAX_PATH] = {0};

    do {
        StringCchCopy(szNextPath + strlen(lpcszFolder) + 1, MAX_PATH,
                      ffd.cFileName);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if ('.' != ffd.cFileName[0]) {
                SAY_INFO("rec dir %s\n", ffd.cFileName);

                files2VectorDr(szNextPath, res);
            }
        }
        else {
            SAY_INFO("reading %s\n", szNextPath);
            res.push_back(readFile(szNextPath));
        }

    } while (FindNextFile(hFind, &ffd) != 0);

    FindClose(hFind);
}

std::vector<std::vector<uint8_t>> files2Vector(const char *path)
{
    std::vector<std::vector<uint8_t>> res;

    struct stat b;
    if (!stat(path, &b)) {

        // Input is file or dir
        size_t sz = 0;
        auto fileData = helper::readAllocFile(path, &sz);
        free(fileData);

        if (!sz) {
            // Input is directory

            for (const auto &dirEntry :
                 std::filesystem::recursive_directory_iterator(path)) {

                if (dirEntry.is_directory()) {
                    continue;
                }

                auto path2 = dirEntry.path().string();
                // printf("Reading file %s\n", path2.c_str());

                res.push_back(readFile(path2.c_str()));
            }
        }
        else {
            // Input is file
            res.push_back(readFile(path));
        }
    }

    return res;
}

void enumFiles(const char *path, EnumFiles_t clb)
{

    struct stat b;
    if (!stat(path, &b)) {

        // Input is file or dir
        size_t sz = 0;
        auto fileData = helper::readAllocFile(path, &sz);

        if (!sz) {
            // Input is directory

            for (const auto &dirEntry :
                 std::filesystem::recursive_directory_iterator(path)) {

                if (dirEntry.is_directory()) {
                    free(fileData);
                    continue;
                }

                auto path2 = dirEntry.path().string();
                // printf("Reading file %s\n", path2.c_str());

                auto d = readFile(path2.c_str());
                clb(path2.c_str(), &d[0], d.size());
            }
        }
        else {
            // SAY_INFO("File read %s %p %d\n", path, fileData, sz);
            // Input is file
            clb(path, (uint8_t *)fileData, sz);
        }
        free(fileData);
    }
}

std::string getLastErrorAsString()
{

    // Get the error message, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
        return std::string("<ZERO>"); // No error message has been recorded

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size-1);

    // Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

}; // namespace helper
