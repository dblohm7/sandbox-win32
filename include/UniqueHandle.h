#ifndef __ASPK_UNIQUEHANDLE_H
#define __ASPK_UNIQUEHANDLE_H

#include <memory>
#include <type_traits>

#ifdef _WIN32_WINNT

namespace detail {

struct KernelHandleDeleter
{
  typedef HANDLE pointer;
  void operator()(pointer aHandle) { ::CloseHandle(aHandle); }
};

struct ModuleHandleDeleter
{
  typedef HMODULE pointer;
  void operator()(pointer aModule) { ::FreeLibrary(aModule); }
};

struct CoTaskMemFreeDeleter
{
  void operator()(void* aPtr) { ::CoTaskMemFree(aPtr); }
};

template <typename T>
struct MappedFileViewDeleter
{
  void operator()(T* aPtr) { ::UnmapViewOfFile(aPtr); }
};

struct ProcAttributeListDeleter
{
  void operator()(LPPROC_THREAD_ATTRIBUTE_LIST aProcAttrList) {
    ::DeleteProcThreadAttributeList(aProcAttrList);
  }
};

}  // namespace detail

using UniqueKernelHandle = std::unique_ptr<std::remove_pointer<HANDLE>::type, detail::KernelHandleDeleter>;
using UniqueModuleHandle = std::unique_ptr<std::remove_pointer<HMODULE>::type, detail::ModuleHandleDeleter>;
using UniqueCOMAllocatedString = std::unique_ptr<std::remove_pointer<PWSTR>::type, detail::CoTaskMemFreeDeleter>;
template <typename T>
using UniqueMappedFileView = std::unique_ptr<typename std::remove_pointer<T>::type, detail::MappedFileViewDeleter<T>>;
using UniqueProcAttributeList = std::unique_ptr<std::remove_pointer<LPPROC_THREAD_ATTRIBUTE_LIST>::type, detail::ProcAttributeListDeleter>;

#endif // _WIN32_WINNT

#endif // __ASPK_UNIQUEHANDLE_H

