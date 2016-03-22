#ifndef __ASPK_UNIQUEHANDLE_H
#define __ASPK_UNIQUEHANDLE_H

#include <memory>
#include <type_traits>

#define UNIQUE_HANDLE_TYPE(handleType, closeFnPtr) \
  std::unique_ptr<std::remove_pointer<handleType>::type, decltype(closeFnPtr)>
#define UNIQUE_HANDLE_DEPENDENT_TYPE(handleType, closeFnPtr) \
  std::unique_ptr<typename std::remove_pointer<handleType>::type, decltype(closeFnPtr)>
#define MAKE_UNIQUE_HANDLE(name, newExpr, closeFnPtr) \
  UNIQUE_HANDLE_TYPE(decltype(newExpr), closeFnPtr) name(newExpr, closeFnPtr)

#ifdef _WIN32_WINNT

typedef UNIQUE_HANDLE_TYPE(HANDLE, &::CloseHandle) UniqueKernelHandle;
#define MAKE_UNIQUE_KERNEL_HANDLE(name, newExpr) \
  MAKE_UNIQUE_HANDLE(name, newExpr, &::CloseHandle)
#define DECLARE_UNIQUE_KERNEL_HANDLE(name) \
  UniqueKernelHandle name(nullptr, &::CloseHandle)

typedef UNIQUE_HANDLE_TYPE(HMODULE, &::FreeLibrary) UniqueModuleHandle;
#define MAKE_UNIQUE_MODULE_HANDLE(name, path) \
  MAKE_UNIQUE_HANDLE(name, ::LoadLibraryW(path), &::FreeLibrary)

template <typename T>
using UniqueFileMapping = UNIQUE_HANDLE_DEPENDENT_TYPE(T, &::UnmapViewOfFile);

#endif // _WIN32_WINNT

#endif // __ASPK_UNIQUEHANDLE_H

