/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "comarshal.h"
#include "mscom.h"

#include <windows.h>
#include <objbase.h>
#include <shlwapi.h>

namespace {

template <typename T>
class DynamicallyLinkedFunctionPtr;

template <typename R, typename... Args>
class DynamicallyLinkedFunctionPtr<R (__stdcall*)(Args...)>
{
  typedef R (__stdcall* FunctionPtrT)(Args...);

public:
  DynamicallyLinkedFunctionPtr(const wchar_t* aLibName, const char* aFuncName)
    : mModule(NULL)
    , mFunction(nullptr)
  {
    mModule = ::LoadLibraryW(aLibName);
    if (mModule) {
      mFunction = reinterpret_cast<FunctionPtrT>(
                    ::GetProcAddress(mModule, aFuncName));
    }
  }

  DynamicallyLinkedFunctionPtr(const DynamicallyLinkedFunctionPtr&) = delete;
  DynamicallyLinkedFunctionPtr& operator=(const DynamicallyLinkedFunctionPtr&) = delete;

  DynamicallyLinkedFunctionPtr(DynamicallyLinkedFunctionPtr&&) = delete;
  DynamicallyLinkedFunctionPtr& operator=(DynamicallyLinkedFunctionPtr&&) = delete;

  ~DynamicallyLinkedFunctionPtr()
  {
    if (mModule) {
      ::FreeLibrary(mModule);
    }
  }

  // TODO: s/std::forward/mozilla::Forward/
  R operator()(Args... args)
  {
    return mFunction(std::forward<Args>(args)...);
  }

  bool operator!() const
  {
    return !mFunction;
  }

private:
  HMODULE mModule;
  FunctionPtrT  mFunction;
};

} // anonymous namespace

namespace mozilla {

// GetBuffer() fails with this variant, but that's okay because we're just
// reconstructing the stream from a buffer anyway.
ProxyStream::ProxyStream(const BYTE* aInitBuf, const int aInitBufSize)
  : mStream(Init(aInitBuf, static_cast<const UINT>(aInitBufSize)))
  , mGlobalLockedBuf(nullptr, ::GlobalUnlock)
  , mBufSize(aInitBufSize)
{
}

IStream*
ProxyStream::Init(const BYTE* aInitBuf, const UINT aInitBufSize)
{
  // Need to link to this as ordinal 12 for Windows XP
  static DynamicallyLinkedFunctionPtr<decltype(&::SHCreateMemStream)>
    pSHCreateMemStream(L"shlwapi.dll", reinterpret_cast<const char*>(12));
  if (!pSHCreateMemStream) {
    return nullptr;
  }
  return pSHCreateMemStream(aInitBuf, aInitBufSize);
}

ProxyStream::ProxyStream(ProxyStream&& aOther)
  : mGlobalLockedBuf(nullptr, &::GlobalUnlock)
{
  // TODO: s/std::move/mozilla::Move/
  *this = std::move(aOther);
}

ProxyStream&
ProxyStream::operator=(ProxyStream&& aOther)
{
  mStream = aOther.mStream;
  // TODO: s/std::move/mozilla::Move/
  mGlobalLockedBuf = std::move(aOther.mGlobalLockedBuf);
  mBufSize = aOther.mBufSize;
  return *this;
}

ProxyStream::~ProxyStream()
{
}

const char*
ProxyStream::GetBuffer(int& aReturnedBufSize) const
{
  aReturnedBufSize = 0;
  if (!mStream) {
    return nullptr;
  }
  if (!mGlobalLockedBuf) {
    return nullptr;
  }
  aReturnedBufSize = mBufSize;
  return reinterpret_cast<const char*>(mGlobalLockedBuf.get());
}

/**
 * This is a "one-shot" call: once the interface has been retrieved, you cannot
 * invoke this function successfully anymore.
 */
bool
ProxyStream::GetInterface(REFIID aIID, void** aOutInterface)
{
  // We should not have a locked buffer on this side
  MOZ_ASSERT(!mGlobalLockedBuf);
  HRESULT hr = ::CoGetInterfaceAndReleaseStream(mStream.Detach(), aIID,
                                                aOutInterface);
  return SUCCEEDED(hr);
}

// TODO: CoMarshalInterface must be called on a MTA thread!
ProxyStream::ProxyStream(REFIID aIID, IUnknown* aObject)
  : mGlobalLockedBuf(nullptr, &::GlobalUnlock)
  , mBufSize(0)
{
  MTARegion mtaRegion;
  // CoMarshalInterface *must* be called on a MTA thread!
  MOZ_ASSERT(!!mtaRegion);
  if (!mtaRegion) {
    return;
  }

  IStreamPtr stream;
  HRESULT hr = ::CreateStreamOnHGlobal(nullptr, TRUE, &stream);
  if (FAILED(hr)) {
    return;
  }

  hr = ::CoMarshalInterface(stream, aIID, aObject, MSHCTX_LOCAL, nullptr,
                            MSHLFLAGS_NORMAL);
  if (FAILED(hr)) {
    return;
  }

  HGLOBAL hglobal = NULL;
  hr = ::GetHGlobalFromStream(stream, &hglobal);
  if (FAILED(hr)) {
    return;
  }

  mStream = stream;
  mGlobalLockedBuf.reset(::GlobalLock(hglobal));
  mBufSize = static_cast<int>(::GlobalSize(hglobal));
}

} // namespace mozilla

