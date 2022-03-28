/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdlib>
#include <iostream>
#include <cstring>
#include <windows.h>
#include <sddl.h>

#include "dacl.h"
#include "sid.h"
#include "WindowsSandbox.h"

using std::wcout;
using std::wcerr;
using std::endl;
using std::hex;
using mozilla::WindowsSandbox;
using mozilla::WindowsSandboxLauncher;

namespace {

inline PIMAGE_DOS_HEADER
HMODULEToPtr(HMODULE aModule)
{
  // LoadLibraryEx can set the lower two bits as indicator flags (see MSDN docs)
  const UINT_PTR mask = 3;
  return reinterpret_cast<PIMAGE_DOS_HEADER>(reinterpret_cast<UINT_PTR>(aModule)
                                             & ~mask);
}

template<typename T, typename R> inline T
RVAToPtr(PVOID aBase, R aRva)
{
  return reinterpret_cast<T>(reinterpret_cast<PBYTE>(aBase) + aRva);
}

typedef void (*INITFUNC)();
typedef void (*DEINITFUNC)();

} // anonymous namespace

class PrototypeSandbox : public WindowsSandbox
{
public:
  explicit PrototypeSandbox(const wchar_t *aLibPath)
    :mLibPath(aLibPath),
     mLib(nullptr),
     mDeinit(nullptr)
  {}
  virtual ~PrototypeSandbox() {}

protected:
  virtual bool OnPrivInit();
  virtual bool OnInit();
  virtual void OnFini();
private:
  const wchar_t*  mLibPath;
  HMODULE         mLib;
  DEINITFUNC      mDeinit;
};

bool
PrototypeSandbox::OnPrivInit()
{
  HMODULE vlib = ::LoadLibraryEx(mLibPath, nullptr,
                                 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE);
  if (!vlib) {
    return false;
  }
  PIMAGE_DOS_HEADER mzHeader = HMODULEToPtr(vlib);
  PIMAGE_NT_HEADERS peHeader = RVAToPtr<PIMAGE_NT_HEADERS>(mzHeader,
                                                           mzHeader->e_lfanew);
  if (peHeader->OptionalHeader.AddressOfEntryPoint == 0) {
    // Library was linked with /NOENTRY, proceed
    mLib = ::LoadLibrary(mLibPath);
  }
  ::FreeLibrary(vlib);
  return !!mLib;
}

bool
PrototypeSandbox::OnInit()
{
  INITFUNC init = (INITFUNC) ::GetProcAddress(mLib, INIT_FUNCTION_NAME);
  mDeinit = (DEINITFUNC) ::GetProcAddress(mLib, DEINIT_FUNCTION_NAME);
  if (!init || !mDeinit) {
    return false;
  }
  init();
  return true;
}

void
PrototypeSandbox::OnFini()
{
  if (mDeinit) {
    mDeinit();
    mDeinit = nullptr;
  }
  if (mLib) {
    ::FreeLibrary(mLib);
    mLib = nullptr;
  }
}

int wmain(int argc, wchar_t* argv[])
{
  if (argc > 2)
  {
    PrototypeSandbox sb(argv[1]);
    if (!sb.Init(argc, argv)) {
      return EXIT_FAILURE;
    }
    sb.Fini();
  } else if (argc == 2) {
    WindowsSandboxLauncher sboxLauncher;
    sboxLauncher.Init();
    if (!sboxLauncher.Launch(argv[0], argv[1])) {
      wcerr << L"Failed to launch" << endl;
      return EXIT_FAILURE;
    }
    if (!sboxLauncher.Wait(INFINITE)) {
      return EXIT_FAILURE;
    }
  } else {
    wcout << L"Usage: " << argv[0] << " <path_to_dll>" << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

