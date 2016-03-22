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
#include <oleacc.h> // For IAccessible
#include <sddl.h>

#include "dacl.h"
#include "sid.h"
#include "UniqueHandle.h"
#include "WindowsSandbox.h"

#include "comarshal.h"
#include "mscom.h"

using std::wcout;
using std::wcerr;
using std::endl;
using std::wostringstream;
using mozilla::WindowsSandboxLauncher;

namespace {

struct BufDescriptor
{
  int mLen;
  BYTE mData[0];
};

class TestAccessible : public IAccessible
{
public:
  // IUnknown
  STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
  STDMETHODIMP_(ULONG) AddRef() override;
  STDMETHODIMP_(ULONG) Release() override;

  // IAccessible
  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accParent( 
      /* [retval][out] */ IDispatch __RPC_FAR *__RPC_FAR *ppdispParent) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accChildCount( 
      /* [retval][out] */ long __RPC_FAR *pcountChildren) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accChild( 
      /* [in] */ VARIANT varChild,
      /* [retval][out] */ IDispatch __RPC_FAR *__RPC_FAR *ppdispChild) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accName( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszName) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accValue( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszValue) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accDescription( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszDescription) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accRole( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ VARIANT __RPC_FAR *pvarRole) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accState( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ VARIANT __RPC_FAR *pvarState) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accHelp( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszHelp) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accHelpTopic( 
      /* [out] */ BSTR __RPC_FAR *pszHelpFile,
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ long __RPC_FAR *pidTopic) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accKeyboardShortcut( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszKeyboardShortcut) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accFocus( 
      /* [retval][out] */ VARIANT __RPC_FAR *pvarChild) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accSelection( 
      /* [retval][out] */ VARIANT __RPC_FAR *pvarChildren) override
    { return E_NOTIMPL; }


  virtual /* [id][propget] */ HRESULT STDMETHODCALLTYPE get_accDefaultAction( 
      /* [optional][in] */ VARIANT varChild,
      /* [retval][out] */ BSTR __RPC_FAR *pszDefaultAction) override
    { return E_NOTIMPL; }


  virtual /* [id] */ HRESULT STDMETHODCALLTYPE accSelect( 
      /* [in] */ long flagsSelect,
      /* [optional][in] */ VARIANT varChild) override
    { return E_NOTIMPL; }


  virtual /* [id] */ HRESULT STDMETHODCALLTYPE accLocation( 
      /* [out] */ long __RPC_FAR *pxLeft,
      /* [out] */ long __RPC_FAR *pyTop,
      /* [out] */ long __RPC_FAR *pcxWidth,
      /* [out] */ long __RPC_FAR *pcyHeight,
      /* [optional][in] */ VARIANT varChild) override
    { return E_NOTIMPL; }


  virtual /* [id] */ HRESULT STDMETHODCALLTYPE accNavigate( 
      /* [in] */ long navDir,
      /* [optional][in] */ VARIANT varStart,
      /* [retval][out] */ VARIANT __RPC_FAR *pvarEndUpAt) override
    { return E_NOTIMPL; }


  virtual /* [id] */ HRESULT STDMETHODCALLTYPE accHitTest( 
      /* [in] */ long xLeft,
      /* [in] */ long yTop,
      /* [retval][out] */ VARIANT __RPC_FAR *pvarChild) override;


  virtual /* [id] */ HRESULT STDMETHODCALLTYPE accDoDefaultAction( 
      /* [optional][in] */ VARIANT varChild) override
    { return E_NOTIMPL; }


  virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_accName( 
      /* [optional][in] */ VARIANT varChild,
      /* [in] */ BSTR szName) override
    { return E_NOTIMPL; }


  virtual /* [id][propput] */ HRESULT STDMETHODCALLTYPE put_accValue( 
      /* [optional][in] */ VARIANT varChild,
      /* [in] */ BSTR szValue) override
    { return E_NOTIMPL; }


  // IDispatch (support of scripting languages like VB)
  virtual HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *pctinfo) override
    { return E_NOTIMPL; }


  virtual HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT iTInfo, LCID lcid,
                                                ITypeInfo **ppTInfo) override
    { return E_NOTIMPL; }


  virtual HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID riid,
                                                  LPOLESTR *rgszNames,
                                                  UINT cNames,
                                                  LCID lcid,
                                                  DISPID *rgDispId) override
    { return E_NOTIMPL; }


  virtual HRESULT STDMETHODCALLTYPE Invoke(DISPID dispIdMember, REFIID riid,
                                           LCID lcid, WORD wFlags,
                                           DISPPARAMS *pDispParams,
                                           VARIANT *pVarResult,
                                           EXCEPINFO *pExcepInfo,
                                           UINT *puArgErr) override
    { return E_NOTIMPL; }



  static HRESULT Create(HANDLE aEvent, REFIID riid, void** ppv);

private:
  explicit TestAccessible(HANDLE aEvent);
  virtual ~TestAccessible();

private:
  ULONG   mRefCnt;
  HANDLE  mEvent;
};

TestAccessible::TestAccessible(HANDLE aEvent)
  : mRefCnt(1)
  , mEvent(aEvent)
{
}

TestAccessible::~TestAccessible()
{
}

HRESULT
TestAccessible::Create(HANDLE aEvent, REFIID riid, void** ppv)
{
  if (!ppv) {
    return E_INVALIDARG;
  }
  *ppv = nullptr;
  TestAccessible* imp = new TestAccessible(aEvent);
  if (!imp) {
    return E_OUTOFMEMORY;
  }
  HRESULT hr = imp->QueryInterface(riid, ppv);
  imp->Release();
  return hr;
}

HRESULT
TestAccessible::QueryInterface(REFIID riid, void** ppv)
{
  IUnknown* punk = nullptr;
  if (!ppv) {
    return E_INVALIDARG;
  }

  if (riid == IID_IUnknown) {
    punk = static_cast<IUnknown*>(this);
  } else if (riid == IID_IDispatch) {
    punk = static_cast<IDispatch*>(this);
  } else if (riid == IID_IAccessible) {
    punk = static_cast<IAccessible*>(this);
  }

  *ppv = punk;
  if (!punk) {
    return E_NOINTERFACE;
  }

  punk->AddRef();
  return S_OK;
}

ULONG
TestAccessible::AddRef()
{
  return (ULONG) InterlockedIncrement((LONG*)&mRefCnt);
}

ULONG
TestAccessible::Release()
{
  ULONG newRefCnt = (ULONG) InterlockedDecrement((LONG*)&mRefCnt);
  if (newRefCnt == 0) {
    delete this;
  }
  return newRefCnt;
}

HRESULT STDMETHODCALLTYPE
TestAccessible::accHitTest( 
      /* [in] */ long xLeft,
      /* [in] */ long yTop,
      /* [retval][out] */ VARIANT __RPC_FAR *pvarChild)
{
  bool inOk = xLeft == 7 && yTop == 248;
  pvarChild->vt = VT_I4;
  pvarChild->lVal = CHILDID_SELF;
  return inOk ? S_OK : E_FAIL;
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
  HRESULT hr = ::CoGetPSClsid(IID_IAccessible, &psClsid);
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
  IAccessiblePtr test;
  if (FAILED(TestAccessible::Create(callEvent.get(), IID_IAccessible, (void**)&test))) {
    return false;
  }
  mozilla::ProxyStream outStream(IID_IAccessible, test);
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

    IAccessiblePtr test;
    if (!stream.GetInterface(IID_IAccessible, (void**)&test)) {
      wcout << L"ProxyStream::GetInterface failed" << endl;
      return EXIT_FAILURE;
    }

    VARIANT outVal;
    HRESULT hr = test->accHitTest(7, 248, &outVal);
    if (FAILED(hr) || outVal.vt != VT_I4 || outVal.lVal != CHILDID_SELF) {
      wcout << L"IAccessible::accHitTest failed" << endl;
      return EXIT_FAILURE;
    }
    wcout << L"IAccessible::accHitTest succeeded!" << endl;

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

