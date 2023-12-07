/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "sid.h"
#include <aclapi.h>

namespace mozilla {

Sid::Sid()
  : mSid(nullptr),
    mSelfAllocated(false)
{
}

Sid::Sid(const WELL_KNOWN_SID_TYPE aSidType)
  : mSid(nullptr),
    mSelfAllocated(false)
{
  Init(aSidType);
}

Sid::Sid(const Sid& aOther)
  : mSid(nullptr),
    mSelfAllocated(false)
{
  *this = aOther;
}

Sid::Sid(Sid&& aOther)
  : mSid(aOther.mSid),
    mSelfAllocated(aOther.mSelfAllocated)
{
  aOther.mSid = nullptr;
  aOther.mSelfAllocated = false;
}

Sid::~Sid()
{
  Clear();
}

void
Sid::Clear()
{
  if (mSid) {
    if (mSelfAllocated) {
      ::free(mSid);
    } else {
      ::FreeSid(mSid);
    }
    mSid = nullptr;
    mSelfAllocated = false;
  }
}

Sid& Sid::operator=(const Sid& aOther)
{
  Clear();
  Init((PSID)aOther);
  return *this;
}

Sid& Sid::operator=(Sid&& aOther)
{
  Clear();
  mSid = aOther.mSid;
  mSelfAllocated = aOther.mSelfAllocated;
  aOther.mSid = nullptr;
  aOther.mSelfAllocated = false;
  return *this;
}

bool
Sid::Init(SID_IDENTIFIER_AUTHORITY& aAuth, DWORD aRid0, DWORD aRid1, DWORD aRid2,
          DWORD aRid3, DWORD aRid4, DWORD aRid5, DWORD aRid6, DWORD aRid7)
{
  if (mSid) {
    return false;
  }

  // RIDs listed backwards
  const DWORD ridVars[] = {
    aRid7,
    aRid6,
    aRid5,
    aRid4,
    aRid3,
    aRid2,
    aRid1,
    aRid0
  };

  // Count how many trailing RIDs are zero and subtract them from the
  // sub-authority count.
  BYTE numSubAuthorities = 8;
  for (auto rid : ridVars) {
    if (rid) {
      break;
    }
    --numSubAuthorities;
  }

  if (!numSubAuthorities) {
    return false;
  }

  BOOL result = ::AllocateAndInitializeSid(&aAuth, numSubAuthorities, aRid0,
                                           aRid1, aRid2, aRid3, aRid4, aRid5,
                                           aRid6, aRid7, &mSid);
  return !!result;
}

bool
Sid::Init(const WELL_KNOWN_SID_TYPE aSidType)
{
  DWORD newSidLen = 0;
  if (!::CreateWellKnownSid(aSidType, nullptr, nullptr, &newSidLen) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }

  PSID newSid = (PSID) ::calloc(newSidLen, 1);
  if (!::CreateWellKnownSid(aSidType, nullptr, newSid, &newSidLen)) {
    ::free(newSid);
    return false;
  }

  mSid = newSid;
  mSelfAllocated = true;
  return true;
}

bool
Sid::Init(const PSID aSid)
{
  if (mSid || !aSid || !::IsValidSid(aSid)) {
    return false;
  }

  DWORD len = ::GetLengthSid(aSid);
  PSID newSid = ::calloc(len, 1);
  if (!::CopySid(len, newSid, aSid)) {
    ::free(newSid);
    return false;
  }

  mSid = newSid;
  mSelfAllocated = true;
  return true;
}

bool
Sid::InitCustom()
{
  UUID uuid;
  if (::UuidCreate(&uuid) != RPC_S_OK) {
    return false;
  }

  DWORD *subAuth = (DWORD*) &uuid;
  SID_IDENTIFIER_AUTHORITY auth = SECURITY_RESOURCE_MANAGER_AUTHORITY;
  return Init(auth, subAuth[0], subAuth[1], subAuth[2], subAuth[3]);
}

void
Sid::GetTrustee(TRUSTEE& aTrustee) const
{
  if (!mSid) {
    return;
  }

  ::BuildTrusteeWithSid(&aTrustee, mSid);
}

bool
Sid::operator==(PSID aOther) const
{
  if ((mSid == nullptr || aOther == nullptr) && mSid != aOther) {
    return false;
  }
  if (!::IsValidSid(aOther)) {
    return false;
  }

  return !!::EqualSid(mSid, aOther);
}

bool
Sid::operator==(const Sid& aOther) const
{
  if ((!mSid || !aOther.mSid) && mSid != aOther.mSid) {
    return false;
  }

  return !!::EqualSid(mSid, aOther.mSid);
}

/* static */ const Sid&
Sid::GetAdministrators()
{
  static const Sid sAdministrators(WinBuiltinAdministratorsSid);
  return sAdministrators;
}

/* static */ const Sid&
Sid::GetLocalSystem()
{
  static const Sid sLocalSystem(WinLocalSystemSid);
  return sLocalSystem;
}

/* static */ const Sid&
Sid::GetEveryone()
{
  static const Sid sEveryone(WinWorldSid);
  return sEveryone;
}

/* static */ const Sid&
Sid::GetRestricted()
{
  static const Sid sRestricted(WinRestrictedCodeSid);
  return sRestricted;
}

/* static */ const Sid&
Sid::GetUsers()
{
  static const Sid sUsers(WinBuiltinUsersSid);
  return sUsers;
}

/* static */ const Sid&
Sid::GetIntegrityUntrusted()
{
  static const Sid sIntegrityUntrusted(WinUntrustedLabelSid);
  return sIntegrityUntrusted;
}

/* static */ const Sid&
Sid::GetIntegrityLow()
{
  static const Sid sIntegrityLow(WinLowLabelSid);
  return sIntegrityLow;
}

/* static */ const Sid&
Sid::GetIntegrityMedium()
{
  static const Sid sIntegrityMedium(WinMediumLabelSid);
  return sIntegrityMedium;
}

/* static */ const Sid&
Sid::GetIntegrityHigh()
{
  static const Sid sIntegrityHigh(WinHighLabelSid);
  return sIntegrityHigh;
}

/* static */ const Sid&
Sid::GetIntegritySystem()
{
  static const Sid sIntegritySystem(WinSystemLabelSid);
  return sIntegritySystem;
}

} // namespace mozilla

