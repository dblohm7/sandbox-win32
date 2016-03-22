/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DACL_H
#define __DACL_H

#include <vector>

#include <accctrl.h>
#include <windows.h>

namespace mozilla {

class Sid;

class Dacl
{
public:
  Dacl();
  ~Dacl();

  void Clear();

  void AddAllowedAce(const Sid& aSid, ACCESS_MASK aAccessMask);
  void AddDeniedAce(const Sid& aSid, ACCESS_MASK aAccessMask);
  bool Merge(PACL aAcl);

  operator PACL();

private:
  void AddAce(const Sid& aSid, ACCESS_MODE aAccessMode, ACCESS_MASK aAccessMask);

  PACL                          mAcl;
  bool                          mModified;
  std::vector<EXPLICIT_ACCESS>  mAces;
};

} // namespace mozilla

#endif // __DACL_H

