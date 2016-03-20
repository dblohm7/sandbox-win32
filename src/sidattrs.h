/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __SIDATTRS_H
#define __SIDATTRS_H

#include <vector>
#include "Sid.h"

namespace mozilla {

class SidAttributes
{
public:
  enum SidListFilterFlag
  {
    FILTER_NOTHING = 0,
    FILTER_INTEGRITY = 1,
    FILTER_RESTRICTED_DISABLE = 2,
    FILTER_ADD_RESTRICTED = 4
  };
  bool CreateFromTokenGroups(HANDLE aToken, unsigned int aFilterFlags,
                             Sid* aLogonSid = nullptr);
  size_t Count() const { return mSidAttrs.size(); }
  operator PSID_AND_ATTRIBUTES() { return &mSidAttrs[0]; }

private:
  void Push(const Sid& aSid, const DWORD aAttrs = 0);

  std::vector<SID_AND_ATTRIBUTES> mSidAttrs;
  std::vector<mozilla::Sid>       mSids;
};

} // namespace mozilla

#endif // __SIDATTRS_H

