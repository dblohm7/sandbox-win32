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

class Sid
{
public:
  Sid();
  Sid(const Sid& aOther);
  ~Sid();

  Sid& operator=(const Sid& aOther);

  bool Init(SID_IDENTIFIER_AUTHORITY& aAuth, DWORD aRid0, DWORD aRid1 = 0,
            DWORD aRid2 = 0, DWORD aRid3 = 0, DWORD aRid4 = 0, DWORD aRid5 = 0,
            DWORD aRid6 = 0, DWORD aRid7 = 0);
  bool Init(WELL_KNOWN_SID_TYPE aSidType);
  bool Init(const PSID aSid);

  bool InitCustom();

  bool IsValid() const { return !!mSid; }
  void GetTrustee(TRUSTEE& aTrustee) const;

  operator PSID() const { return mSid; }
  bool operator== (PSID aOther) const;
  bool operator== (const Sid& aOther) const;

  static Sid& GetAdministrators();
  static Sid& GetLocalSystem();
  static Sid& GetEveryone();
  static Sid& GetRestricted();
  static Sid& GetUsers();
  static Sid& GetIntegrityUntrusted();
  static Sid& GetIntegrityLow();
  static Sid& GetIntegrityMedium();
  static Sid& GetIntegrityHigh();
  static Sid& GetIntegritySystem();

private:
  void Clear();

  PSID          mSid;
  bool          mSelfAllocated;

  static Sid sAdministrators;
  static Sid sLocalSystem;
  static Sid sEveryone;
  static Sid sRestricted;
  static Sid sUsers;
  static Sid sIntegrityUntrusted;
  static Sid sIntegrityLow;
  static Sid sIntegrityMedium;
  static Sid sIntegrityHigh;
  static Sid sIntegritySystem;
};

} // namespace mozilla

#endif // __SID_H

