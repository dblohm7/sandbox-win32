/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "sid.h"
#include <aclapi.h>

namespace mozilla {

Sid Sid::sAdministrators;
Sid Sid::sLocalSystem;
Sid Sid::sEveryone;
Sid Sid::sRestricted;
Sid Sid::sUsers;
Sid Sid::sIntegrityUntrusted;
Sid Sid::sIntegrityLow;
Sid Sid::sIntegrityMedium;
Sid Sid::sIntegrityHigh;
Sid Sid::sIntegritySystem;

Sid::Sid()
  :mSid(nullptr),
   mSelfAllocated(false)
{
}

Sid::Sid(const Sid& aOther)
  :mSid(nullptr),
   mSelfAllocated(false)
{
  *this = aOther;
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

bool
Sid::Init(SID_IDENTIFIER_AUTHORITY& aAuth, DWORD aRid0, DWORD aRid1, DWORD aRid2,
          DWORD aRid3, DWORD aRid4, DWORD aRid5, DWORD aRid6, DWORD aRid7)
{
  if (mSid || !aRid0) return false;
  BYTE numSubAuthorities = 1;
  if (aRid1) ++numSubAuthorities;
  if (aRid2) ++numSubAuthorities;
  if (aRid3) ++numSubAuthorities;
  if (aRid4) ++numSubAuthorities;
  if (aRid5) ++numSubAuthorities;
  if (aRid6) ++numSubAuthorities;
  if (aRid7) ++numSubAuthorities;
  BOOL result = ::AllocateAndInitializeSid(&aAuth, numSubAuthorities, aRid0,
                                           aRid1, aRid2, aRid3, aRid4, aRid5,
                                           aRid6, aRid7, &mSid);
  return result ? true : false;
}

bool
Sid::Init(WELL_KNOWN_SID_TYPE aSidType)
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
  if (mSid || !aSid || !::IsValidSid(aSid)) return false;
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
  DWORD subAuth[4];
  subAuth[0] = uuid.Data1;
  subAuth[1] = (uuid.Data2 << 16) | uuid.Data3;
  subAuth[2] = (uuid.Data4[0] << 24) |
               (uuid.Data4[1] << 16) |
               (uuid.Data4[2] << 8) |
               uuid.Data4[3];
  subAuth[3] = (uuid.Data4[4] << 24) |
               (uuid.Data4[5] << 16) |
               (uuid.Data4[6] << 8) |
               uuid.Data4[7];
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
  if (!IsValid() || !aOther || !::IsValidSid(aOther)) {
    return false;
  }
  return !!::EqualSid(mSid, aOther);
}

bool
Sid::operator==(const Sid& aOther) const
{
  if (!IsValid() || !aOther.IsValid()) {
    return false;
  }
  return !!::EqualSid(mSid, aOther.mSid);
}

/* static */ Sid&
Sid::GetAdministrators()
{
  if (sAdministrators.IsValid()) {
    return sAdministrators;
  }
  sAdministrators.Init(WinBuiltinAdministratorsSid);
  return sAdministrators;
}

/* static */ Sid&
Sid::GetLocalSystem()
{
  if (sLocalSystem.IsValid()) {
    return sLocalSystem;
  }
  sLocalSystem.Init(WinLocalSystemSid);
  return sLocalSystem;
}

/* static */ Sid&
Sid::GetEveryone()
{
  if (sEveryone.IsValid()) {
    return sEveryone;
  }
  sEveryone.Init(WinWorldSid);
  return sEveryone;
}

/* static */ Sid&
Sid::GetRestricted()
{
  if (sRestricted.IsValid()) {
    return sRestricted;
  }
  sRestricted.Init(WinRestrictedCodeSid);
  return sRestricted;
}

/* static */ Sid&
Sid::GetUsers()
{
  if (sUsers.IsValid()) {
    return sUsers;
  }
  sUsers.Init(WinBuiltinUsersSid);
  return sUsers;
}

/* static */ Sid&
Sid::GetIntegrityUntrusted()
{
  if (sIntegrityUntrusted.IsValid()) {
    return sIntegrityUntrusted;
  }
  sIntegrityUntrusted.Init(WinUntrustedLabelSid);
  return sIntegrityUntrusted;
}

/* static */ Sid&
Sid::GetIntegrityLow()
{
  if (sIntegrityLow.IsValid()) {
    return sIntegrityLow;
  }
  sIntegrityLow.Init(WinLowLabelSid);
  return sIntegrityLow;
}

/* static */ Sid&
Sid::GetIntegrityMedium()
{
  if (sIntegrityMedium.IsValid()) {
    return sIntegrityMedium;
  }
  sIntegrityMedium.Init(WinMediumLabelSid);
  return sIntegrityMedium;
}

/* static */ Sid&
Sid::GetIntegrityHigh()
{
  if (sIntegrityHigh.IsValid()) {
    return sIntegrityHigh;
  }
  sIntegrityHigh.Init(WinHighLabelSid);
  return sIntegrityHigh;
}

/* static */ Sid&
Sid::GetIntegritySystem()
{
  if (sIntegritySystem.IsValid()) {
    return sIntegritySystem;
  }
  sIntegritySystem.Init(WinSystemLabelSid);
  return sIntegritySystem;
}

} // namespace mozilla

