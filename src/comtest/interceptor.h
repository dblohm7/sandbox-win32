/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_interceptor_h
#define mozilla_interceptor_h

#include <callobj.h>
#include <comdef.h>

namespace mozilla {
namespace mscom {

namespace detail {

_COM_SMARTPTR_TYPEDEF(ICallInterceptor, IID_ICallInterceptor);

} // namespace detail

inline HRESULT
CreateInterceptor(REFIID aIidTarget, ICallFrameEvents* aEventSink,
                  void** aOutInterface)
{
  if (!aEventSink || !aOutInterface) {
    return E_INVALIDARG;
  }
  *aOutInterface = nullptr;

  detail::ICallInterceptorPtr interceptor;
  HRESULT hr = ::CoGetInterceptor(aIidTarget, nullptr, IID_ICallInterceptor,
                                  (void**)&interceptor);
  if (FAILED(hr)) {
    return hr;
  }

  hr = interceptor->RegisterSink(aEventSink);
  if (FAILED(hr)) {
    return hr;
  }

  return interceptor->QueryInterface(aIidTarget, aOutInterface);
}

template <typename InterfaceT>
inline HRESULT
CreateInterceptor(InterfaceT* aTargetInterface, ICallFrameEvents* aEventSink,
                  InterfaceT** aOutInterface)
{
  if (!aTargetInterface || !aEventSink) {
    return E_INVALIDARG;
  }

  REFIID iidTarget = __uuidof(aTargetInterface);

  return CreateInterceptor(iidTarget, aEventSink, (void**)aOutInterface);
}

} // namespace mscom
} // namespace mozilla

#endif // mozilla_interceptor_h
