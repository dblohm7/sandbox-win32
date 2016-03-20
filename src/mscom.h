/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_mscom_h
#define mozilla_mscom_h

#include <objbase.h>

// TODO: Replace these with real definitions
#define MOZ_RAII
#define MOZ_ASSERT(a)

namespace mozilla {

template<COINIT T>
class MOZ_RAII COMApartmentRegion
{
public:
  COMApartmentRegion()
    : mInitResult(::CoInitializeEx(nullptr, T))
  {
    // If this fires then we're probably mixing apartments on the same thread
    MOZ_ASSERT(SUCCEEDED(mInitResult));
  }

  ~COMApartmentRegion()
  {
    if (SUCCEEDED(mInitResult)) {
      ::CoUninitialize();
    }
  }

  bool operator!() const
  {
    return FAILED(mInitResult);
  }

private:
  COMApartmentRegion(const COMApartmentRegion&) = delete;
  COMApartmentRegion& operator=(const COMApartmentRegion&) = delete;
  COMApartmentRegion(COMApartmentRegion&&) = delete;
  COMApartmentRegion& operator=(COMApartmentRegion&&) = delete;

  HRESULT mInitResult;
};

typedef COMApartmentRegion<COINIT_APARTMENTTHREADED> STARegion;
typedef COMApartmentRegion<COINIT_MULTITHREADED> MTARegion;

} // namespace mozilla

#endif // mozilla_mscom_h

