/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_handoff_h
#define mozilla_handoff_h

#include "interceptor.h"

namespace mozilla {
namespace mscom {

namespace detail {

_COM_SMARTPTR_TYPEDEF(ICallFrameEvents, IID_ICallFrameEvents);

} // namespace detail

class Handoff : public ICallFrameEvents
              , public ICallFrameWalker
{
public:
  static HRESULT Create(HANDLE aTargetThread, IUnknown* aTargetInterface,
                        ICallFrameEvents** aOutput);

  template <typename InterfaceT>
  static HRESULT WrapInterface(HANDLE aTargetThread,
                               InterfaceT* aTargetInterface,
                               InterfaceT** aOutInterface)
  {
    detail::ICallFrameEventsPtr handoff;
    HRESULT hr = Handoff::Create(aTargetThread, aTargetInterface, &handoff);
    if (FAILED(hr)) {
      return hr;
    }
    return CreateInterceptor(aTargetInterface, handoff, aOutInterface);
  }

  // IUnknown
  STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
  STDMETHODIMP_(ULONG) AddRef() override;
  STDMETHODIMP_(ULONG) Release() override;

  // ICallFrameEvents
  STDMETHODIMP OnCall(ICallFrame* aFrame) override;

  // ICallFrameWalker
  STDMETHODIMP OnWalkInterface(REFIID aIid, PVOID* aInterface, BOOL aIsInParam,
                               BOOL aIsOutParam) override;

private:
  Handoff(HANDLE aTargetThread, void* aTargetInterface);
  ~Handoff();

  static VOID CALLBACK TargetAPC(ULONG_PTR aContext);

private:

private:
  ULONG     mRefCnt;
  HANDLE    mTargetThread;
  IUnknown* mTargetInterface;
};

} // namespace mscom
} // namespace mozilla

#endif // mozilla_handoff_h
