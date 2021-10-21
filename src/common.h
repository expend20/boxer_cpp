#ifndef _COMMON_H_
#define _COMMON_H_

#include <windows.h>
#include <TlHelp32.h>

#include <comdef.h>

#include <string>
#include <vector>

namespace helper {

typedef void (*EnumFiles_t)(const char *path, uint8_t *data, size_t sz);

void enumFiles(const char *path, EnumFiles_t clb);

std::vector<std::vector<uint8_t>> files2Vector(const char *path);
void files2VectorDr(const char *path, std::vector<std::vector<uint8_t>> &res);

size_t writeFile(const char *filePath, const char *fileData, size_t fileLen,
                 const char *access);

char *getAllocTempFile(char *ext, char *prefix);

char *readAllocFile(const char *filePath, size_t *fileLen);

std::vector<uint8_t> readFile(const char *filePath);

std::string hresultAsString(HRESULT hr);
std::string getLastErrorAsString();

std::string moduleByPtr(size_t funcPtr, bool fullPath);

wchar_t *asciiToUnicodeAlloc(const char *in, size_t sz, bool addZero);
void UnicodeToAscii(wchar_t *in, char *out, size_t len);

template <class T> inline void SAFE_RELEASE(T *&pT)
{
    if (pT != NULL) {
        pT->Release();
        pT = NULL;
    }
};
template <class T> void SAFE_RELEASE(T** ppT)
{
  if (*ppT)
  {
    (*ppT)->Release();
    *ppT = NULL;
  }
}

}; // namespace helper

#endif // _COMMON_H_
