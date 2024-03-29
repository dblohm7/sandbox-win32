/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "sidattrs.h"
#include "MakeUniqueLen.h"

namespace mozilla {

bool
SidAttributes::CreateFromTokenGroups(HANDLE aToken, unsigned int aFilterFlags,
                                     Sid* aLogonSid)
{
  if (!aToken || !mSidAttrs.empty() || !mSids.empty()) {
    return false;
  }

  // Get size
  DWORD reqdLen = 0;
  if (!::GetTokenInformation(aToken, TokenGroups, nullptr, 0, &reqdLen) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }

  // Allocate and retrieve
  MAKE_UNIQUE_LEN(PTOKEN_GROUPS, tokenGroups, reqdLen);
  if (!::GetTokenInformation(aToken, TokenGroups, tokenGroups, reqdLen,
                             &reqdLen)) {
    return false;
  }

  // Pass 1: Figure out how many SID_AND_ATTRIBUTES we need
  DWORD sidCount = 0;
  for (DWORD i = 0; i < tokenGroups->GroupCount; ++i) {
    if (tokenGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY) {
      if (aFilterFlags & FILTER_INTEGRITY) {
        continue;
      }
    }
    if (tokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }
    if (mozilla::Sid::GetEveryone() == tokenGroups->Groups[i].Sid) {
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }
    if (mozilla::Sid::GetUsers() == tokenGroups->Groups[i].Sid) {
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }
    ++sidCount;
  }

  if (aFilterFlags & FILTER_ADD_RESTRICTED) {
    ++sidCount;
  }

  // Reserve space in the containers so that the vector's buffers don't get
  // reallocated.
  mSidAttrs.reserve(sidCount);
  mSids.reserve(sidCount);

  // Pass 2: Now populate the output
  DWORD sidIndex = 0;
  for (DWORD i = 0; i < tokenGroups->GroupCount; ++i) {
    if (tokenGroups->Groups[i].Attributes & SE_GROUP_INTEGRITY) {
      if (aFilterFlags & FILTER_INTEGRITY) {
        continue;
      }
    }

    if (tokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
      if (aLogonSid) {
        aLogonSid->Init(tokenGroups->Groups[i].Sid);
      }
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }

    if (mozilla::Sid::GetEveryone() == tokenGroups->Groups[i].Sid) {
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }

    if (mozilla::Sid::GetUsers() == tokenGroups->Groups[i].Sid) {
      if (aFilterFlags & FILTER_RESTRICTED_DISABLE) {
        continue;
      }
    }

    Sid newSid;
    if (!newSid.Init(tokenGroups->Groups[i].Sid)) {
      return false;
    }

    Push(newSid);
  }

  if (aFilterFlags & FILTER_ADD_RESTRICTED) {
    Push(mozilla::Sid::GetRestricted());
  }

  return true;
}

void
SidAttributes::Push(const Sid& aSid, const DWORD aAttrs)
{
  // DANGER: If the memory backing mSids hasn't been reserved ahead of time,
  //         the pointers stored in mSidAttrs will be invalid when mSids
  //         reallocates its buffer!
  mSids.push_back(aSid);
  SID_AND_ATTRIBUTES newSidAttr = { (PSID)mSids.back(), aAttrs };
  mSidAttrs.push_back(newSidAttr);
}

} // namespace mozilla
