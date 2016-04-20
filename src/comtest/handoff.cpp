/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "handoff.h"

namespace {

class ThreadHandoffInfo
{
public:
  explicit ThreadHandoffInfo(ICallFrame* aCallFrame,
                             IUnknown* aTargetInterface)
    : mCallFrame(aCallFrame)
    , mTargetInterface(aTargetInterface)
    , mIsDone(::CreateEvent(nullptr, FALSE, FALSE, nullptr))
    , mResult(E_UNEXPECTED)
  {
  }

  ~ThreadHandoffInfo()
  {
    if (mIsDone) {
      ::CloseHandle(mIsDone);
    }
  }

  bool IsDone() const
  {
    return ::WaitForSingleObject(mIsDone, INFINITE) == WAIT_OBJECT_0;
  }

  void Invoke()
  {
    mResult = mCallFrame->Invoke(mTargetInterface);
    ::SetEvent(mIsDone);
  }

  HRESULT GetResult() const
  {
    return mResult;
  }

private:
  ICallFrame* mCallFrame;
  IUnknown*   mTargetInterface;
  HANDLE      mIsDone;
  HRESULT     mResult;
};

} // anonymous namespace

namespace mozilla {
namespace mscom {

/* static */ HRESULT
Handoff::Create(HANDLE aTargetThread, IUnknown* aTargetInterface,
                ICallFrameEvents** aOutput)
{
  *aOutput = nullptr;
  Handoff* handoff = new Handoff(aTargetThread, aTargetInterface);
  HRESULT hr = handoff->QueryInterface(IID_ICallFrameEvents, (void**) aOutput);
  handoff->Release();
  return hr;
}

Handoff::Handoff(HANDLE aTargetThread, void* aTargetInterface)
  : mRefCnt(1)
  , mTargetThread(NULL)
  , mTargetInterface(static_cast<IUnknown*>(aTargetInterface))
{
  mTargetInterface->AddRef();
  // TODO ASK: Assert DuplicateHandle's return value
  ::DuplicateHandle(::GetCurrentProcess(), aTargetThread,
                    ::GetCurrentProcess(), &mTargetThread,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
}

Handoff::~Handoff()
{
  if (mTargetThread) {
    ::CloseHandle(mTargetThread);
  }
  if (mTargetInterface) {
    mTargetInterface->Release();
  }
}

HRESULT
Handoff::QueryInterface(REFIID riid, void** ppv)
{
  IUnknown* punk = nullptr;
  if (!ppv) {
    return E_INVALIDARG;
  }

  if (riid == IID_IUnknown) {
    punk = static_cast<IUnknown*>(static_cast<ICallFrameEvents*>(this));
  } else if (riid == IID_ICallFrameEvents) {
    punk = static_cast<ICallFrameEvents*>(this);
  } else if (riid == IID_ICallFrameWalker) {
    punk = static_cast<ICallFrameWalker*>(this);
  }

  *ppv = punk;
  if (!punk) {
    return E_NOINTERFACE;
  }

  punk->AddRef();
  return S_OK;
}

ULONG
Handoff::AddRef()
{
  return (ULONG) InterlockedIncrement((LONG*)&mRefCnt);
}

ULONG
Handoff::Release()
{
  ULONG newRefCnt = (ULONG) InterlockedDecrement((LONG*)&mRefCnt);
  if (newRefCnt == 0) {
    delete this;
  }
  return newRefCnt;
}

VOID CALLBACK
Handoff::TargetAPC(ULONG_PTR aContext)
{
  ThreadHandoffInfo* info = (ThreadHandoffInfo*)aContext;
  info->Invoke();
}

HRESULT
Handoff::OnCall(ICallFrame* aFrame)
{
  ThreadHandoffInfo handoffInfo(aFrame, mTargetInterface);
  DWORD queueOk = ::QueueUserAPC(&TargetAPC, mTargetThread,
                                 reinterpret_cast<UINT_PTR>(&handoffInfo));
  if (!queueOk) {
    return E_UNEXPECTED;
  }
  if (!handoffInfo.IsDone()) {
    return E_UNEXPECTED;
  }
  HRESULT hr = handoffInfo.GetResult();
  if (FAILED(hr)) {
    return hr;
  }
  hr = aFrame->GetReturnValue();
  if (FAILED(hr)) {
    return hr;
  }
  // Scan the outputs looking for any outparam interfaces that need wrapping
  hr = aFrame->WalkFrame(CALLFRAME_WALK_OUT, this);
  if (FAILED(hr)) {
    return hr;
  }
  // NOTE: Any logging for profiling purposes should go here.
  return S_OK;
}

HRESULT
Handoff::OnWalkInterface(REFIID aIid, PVOID* aInterface, BOOL aIsInParam,
                         BOOL aIsOutParam)
{
  if (!aInterface || !aIsOutParam) {
    return E_UNEXPECTED;
  }
  IUnknown* origInterface = static_cast<IUnknown*>(*aInterface);
  if (!origInterface) {
    // nullptr doesn't need wrapping
    return S_OK;
  }

  detail::ICallFrameEventsPtr handoff;
  HRESULT hr = Handoff::Create(mTargetThread, origInterface, &handoff);
  if (FAILED(hr)) {
    return hr;
  }

  void* replacementInterface = nullptr;
  hr = CreateInterceptor(aIid, handoff, &replacementInterface);
  if (FAILED(hr)) {
    return hr;
  }

  // handoff has taken a strong reference to origInterface, so we should release
  // it here before we replace *aInterface.
  origInterface->Release();
  // Now we can replace it with replacementInterface, whose refcount should
  // already be correct.
  *aInterface = replacementInterface;
  return S_OK;
}

} // namespace mscom
} // namespace mozilla
