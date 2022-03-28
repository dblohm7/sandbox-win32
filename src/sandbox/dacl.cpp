/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "dacl.h"
#include "sid.h"

#include <aclapi.h>

namespace mozilla {

Dacl::Dacl()
  : mAcl(nullptr),
    mModified(false)
{
}

Dacl::~Dacl()
{
  Clear();
}

void
Dacl::Clear()
{
  if (mAcl) {
    ::LocalFree(mAcl);
    mAcl = nullptr;
  }
}

void
Dacl::AddAllowedAce(const Sid& aSid, ACCESS_MASK aAccessMask)
{
  return AddAce(aSid, GRANT_ACCESS, aAccessMask);
}

void
Dacl::AddDeniedAce(const Sid& aSid, ACCESS_MASK aAccessMask)
{
  return AddAce(aSid, DENY_ACCESS, aAccessMask);
}

void
Dacl::AddAce(const Sid& aSid, ACCESS_MODE aAccessMode, ACCESS_MASK aAccessMask)
{
  EXPLICIT_ACCESS ea;
  ::memset(&ea, 0, sizeof(ea));
  ea.grfAccessPermissions = aAccessMask;
  ea.grfAccessMode = aAccessMode;
  ea.grfInheritance = NO_INHERITANCE;
  aSid.GetTrustee(ea.Trustee);
  mAces.push_back(ea);
  mModified = true;
}

Dacl::operator PACL()
{
  if (!mModified) {
    return mAcl;
  }
  if (!Merge(mAcl)) {
    return nullptr;
  }
  return mAcl;
}

bool
Dacl::Merge(PACL aAcl)
{
  PACL newAcl = nullptr;
  DWORD err = ::SetEntriesInAcl((ULONG)mAces.size(), &mAces[0], aAcl, &newAcl);
  if (ERROR_SUCCESS != err) {
    return false;
  }

  Clear();
  mAcl = newAcl;
  mModified = false;
  return true;
}

} // namespace mozilla

