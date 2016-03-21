/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdlib>
#include <iostream>
#include <sstream>

#include <windows.h>
#include <objbase.h>
#include <sddl.h>

#include "dacl.h"
#include "sid.h"
#include "UniqueHandle.h"
#include "WindowsSandbox.h"

#include "Test.h"
#include "comarshal.h"
#include "mscom.h"

using std::wcout;
using std::wcerr;
using std::endl;
using std::wostringstream;
using mozilla::WindowsSandboxLauncher;

namespace {

_COM_SMARTPTR_TYPEDEF(ITest, __uuidof(ITest));

struct BufDescriptor
{
  int mLen;
  BYTE mData[0];
};

class TestImp : public ITest
{
public:
  STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
  STDMETHODIMP_(ULONG) AddRef() override;
  STDMETHODIMP_(ULONG) Release() override;

  STDMETHODIMP Foo(long aParam, long* aOutVal) override;

  static HRESULT Create(HANDLE aEvent, REFIID riid, void** ppv);

private:
  TestImp(HANDLE aEvent);
  virtual ~TestImp();

private:
  ULONG mRefCnt;
  HANDLE mEvent;
};

TestImp::TestImp(HANDLE aEvent)
  : mEvent(aEvent)
{
}

TestImp::~TestImp()
{
}

HRESULT
TestImp::Create(HANDLE aEvent, REFIID riid, void** ppv)
{
  if (!ppv) {
    return E_INVALIDARG;
  }
  *ppv = nullptr;
  TestImp* imp = new TestImp(aEvent);
  if (!imp) {
    return E_OUTOFMEMORY;
  }
  HRESULT hr = imp->QueryInterface(riid, ppv);
  imp->Release();
  return hr;
}

HRESULT
TestImp::QueryInterface(REFIID riid, void** ppv)
{
  IUnknown* punk = nullptr;
  if (!ppv) {
    return E_INVALIDARG;
  }
  if (riid == IID_IUnknown) {
    punk = static_cast<IUnknown*>(this);
  } else if (riid == IID_ITest) {
    punk = static_cast<ITest*>(this);
  }

  *ppv = punk;
  if (!punk) {
    return E_NOINTERFACE;
  }
  punk->AddRef();
  return S_OK;
}

ULONG
TestImp::AddRef()
{
  return (ULONG) InterlockedIncrement((LONG*)&mRefCnt);
}

ULONG
TestImp::Release()
{
  ULONG newRefCnt = (ULONG) InterlockedDecrement((LONG*)&mRefCnt);
  if (newRefCnt == 0) {
    delete this;
  }
  return newRefCnt;
}

HRESULT
TestImp::Foo(long aParam, long* aOutVal)
{
  *aOutVal = 0xdeadbeef;
  ::SetEvent(mEvent);
  return aParam == 7 ? S_OK : E_INVALIDARG;
}

const WCHAR gSectionName[] = L"comtest-shm";
const WCHAR gEventName[] = L"comtest-evt";

class COMTestSandbox : public mozilla::WindowsSandbox
{
public:
  explicit COMTestSandbox()
    : mSection(nullptr, &::CloseHandle)
    , mSharedBuffer(nullptr, &::UnmapViewOfFile)
    , mEvent(nullptr, &::CloseHandle)
  {}
  virtual ~COMTestSandbox()
  {
    Fini();
  }

protected:
  virtual bool OnPrivInit();
  virtual bool OnInit();
  virtual void OnFini();

private:
  UniqueKernelHandle      mSection;
  UniqueFileMapping<BufDescriptor> mSharedBuffer;
  UniqueKernelHandle      mEvent;
};

bool
COMTestSandbox::OnPrivInit()
{
  mSection.reset(::OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, gSectionName));
  if (!mSection) {
    return false;
  }
  mSharedBuffer.reset(reinterpret_cast<BufDescriptor*>(
                      ::MapViewOfFile(mSection.get(), FILE_MAP_ALL_ACCESS, 0,
                                      0, 0)));
  if (!mSharedBuffer) {
    return false;
  }
  mEvent.reset(::OpenEvent(EVENT_MODIFY_STATE, FALSE, gEventName));
  if (!mEvent) {
    return false;
  }

  mozilla::MTARegion comrgn;

  // Get the CLSID of the proxy/stub marshaler DLL
  CLSID psClsid;
  HRESULT hr = ::CoGetPSClsid(IID_ITest, &psClsid);
  if (FAILED(hr)) {
    return false;
  }
  // Now look up the DLL's location via the registry
  LPOLESTR strClsid = nullptr;
  hr = ::StringFromCLSID(psClsid, &strClsid);
  if (FAILED(hr)) {
    return false;
  }
  wostringstream oss;
  oss << L"CLSID\\";
  oss << strClsid;
  oss << L"\\InProcServer32";
  ::CoTaskMemFree(strClsid);

  wchar_t proxyDllPath[MAX_PATH + 1] = {0};
  DWORD proxyDllPathNumBytes = sizeof(proxyDllPath);
  LONG regOk = ::RegGetValue(HKEY_CLASSES_ROOT, oss.str().c_str(), nullptr,
                             RRF_RT_REG_SZ, nullptr, proxyDllPath,
                             &proxyDllPathNumBytes);
  if (regOk != ERROR_SUCCESS) {
    return false;
  }
  // Now proxyDllPath contains the location of the proxy DLL; we need to
  // allow the sandbox to access it. Let's just leak a LoadLibrary call.
  HMODULE proxyDll = ::LoadLibrary(proxyDllPath);
  return !!proxyDll;
}

bool
COMTestSandbox::OnInit()
{
  if (FAILED(::CoInitializeEx(nullptr, COINIT_MULTITHREADED))) {
    return false;
  }

  MAKE_UNIQUE_KERNEL_HANDLE(callEvent, ::CreateEvent(nullptr, FALSE, FALSE, nullptr));
  if (!callEvent) {
    return false;
  }
  ITestPtr test;
  if (FAILED(TestImp::Create(callEvent.get(), IID_ITest, (void**)&test))) {
    return false;
  }
  mozilla::ProxyStream outStream(IID_ITest, test);
  if (!outStream.IsValid()) {
    return false;
  }
  int len = 0;
  const char* buf = outStream.GetBuffer(len);
  mSharedBuffer->mLen = len;
  memcpy(&mSharedBuffer->mData[0], buf, len);
  ::SignalObjectAndWait(mEvent.get(), callEvent.get(), INFINITE, FALSE);
  return true;
}

void
COMTestSandbox::OnFini()
{
  ::CoUninitialize();
}

}

// TODO: Remove these from global scope
static UniqueKernelHandle gSection(nullptr, &CloseHandle);
static UniqueKernelHandle gEvent(nullptr, &CloseHandle);
static const DWORD SHM_TIMEOUT = 10000U;

static BufDescriptor*
CreateSharedSection()
{
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, FALSE};
  gSection.reset(CreateFileMapping(NULL, &sa, PAGE_READWRITE, 0, 0x4000,
                                   gSectionName));
  if (!gSection) {
    return false;
  }
  gEvent.reset(CreateEvent(&sa, FALSE, FALSE, gEventName));
  return reinterpret_cast<BufDescriptor*>(MapViewOfFile(gSection.get(),
                                               FILE_MAP_ALL_ACCESS, 0, 0, 0));
}

int wmain(int argc, wchar_t* argv[])
{
  if (argc == 1) {
    WindowsSandboxLauncher sboxLauncher;
    if (!sboxLauncher.Init(WindowsSandboxLauncher::eInitNoSeparateWindowStation,
                      WindowsSandboxLauncher::DEFAULT_MITIGATION_POLICIES ^
                        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)) {
      wcout << L"WindowsSandboxLauncher::Init failed" << endl;
      return EXIT_FAILURE;
    }

    UniqueFileMapping<BufDescriptor> sharedBuf(CreateSharedSection(),
                                               &UnmapViewOfFile);
    if (!sharedBuf) {
      wcout << L"Failed to create shared section data" << endl;
      return EXIT_FAILURE;
    }

    if (!sboxLauncher.Launch(argv[0], L"")) {
      wcerr << L"Failed to launch" << endl;
      return EXIT_FAILURE;
    }

    if (WaitForSingleObject(gEvent.get(), ::IsDebuggerPresent() ? INFINITE : SHM_TIMEOUT) != WAIT_OBJECT_0) {
      wcout << L"Failure or timeout waiting for population of shared memory" << endl;
      return EXIT_FAILURE;
    }

    mozilla::MTARegion mtargn;

    // OK, we should have bytes of the interface
    mozilla::ProxyStream stream(sharedBuf->mData, sharedBuf->mLen);
    if (!stream.IsValid()) {
      wcout << L"ProxyStream creation failed" << endl;
      return EXIT_FAILURE;
    }

    ITestPtr test;
    if (!stream.GetInterface(IID_ITest, (void**)&test)) {
      wcout << L"ProxyStream::GetInterface failed" << endl;
      return EXIT_FAILURE;
    }

    long outVal = 0;
    HRESULT hr = test->Foo(7, &outVal);
    if (FAILED(hr) || outVal != 0xdeadbeef) {
      wcout << L"ITest::Foo failed" << endl;
      return EXIT_FAILURE;
    }

    if (!sboxLauncher.Wait(INFINITE)) {
      return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
  }

  COMTestSandbox sb;
  if (!sb.Init(argc, argv)) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

