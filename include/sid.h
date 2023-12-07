/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __SID_H
#define __SID_H

#include <accctrl.h>
#include <windows.h>

namespace mozilla {

class Sid final
{
public:
  Sid();
  explicit Sid(const WELL_KNOWN_SID_TYPE aSidType);
  Sid(const Sid& aOther);
  Sid(Sid&& aOther);
  ~Sid();

  Sid& operator=(const Sid& aOther);
  Sid& operator=(Sid&& aOther);

  bool Init(SID_IDENTIFIER_AUTHORITY& aAuth, DWORD aRid0, DWORD aRid1 = 0,
            DWORD aRid2 = 0, DWORD aRid3 = 0, DWORD aRid4 = 0, DWORD aRid5 = 0,
            DWORD aRid6 = 0, DWORD aRid7 = 0);
  bool Init(const WELL_KNOWN_SID_TYPE aSidType);
  bool Init(const PSID aSid);

  bool InitCustom();

  bool IsValid() const { return !!mSid; }
  void GetTrustee(TRUSTEE& aTrustee) const;

  operator PSID() const { return mSid; }
  bool operator== (PSID aOther) const;
  bool operator== (const Sid& aOther) const;

  static const Sid& GetAdministrators();
  static const Sid& GetLocalSystem();
  static const Sid& GetEveryone();
  static const Sid& GetRestricted();
  static const Sid& GetUsers();
  static const Sid& GetIntegrityUntrusted();
  static const Sid& GetIntegrityLow();
  static const Sid& GetIntegrityMedium();
  static const Sid& GetIntegrityHigh();
  static const Sid& GetIntegritySystem();

private:
  void Clear();

  PSID          mSid;
  bool          mSelfAllocated;
};

} // namespace mozilla

#endif // __SID_H

