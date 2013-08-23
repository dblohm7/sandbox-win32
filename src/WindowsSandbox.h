/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __WINDOWSSANDBOX_H
#define __WINDOWSSANDBOX_H

#include <windows.h>
#include "scoped_handle_win.h"
#include "Sid.h"
#include <vector>

namespace mozilla {

class WindowsSandbox
{
public:
  WindowsSandbox() {}
  virtual ~WindowsSandbox() {}

  bool Init(int aArgc, wchar_t* aArgv[]);
  void Fini();

  static const wchar_t DESKTOP_NAME[];
  static const wchar_t SWITCH_IMPERSONATION_TOKEN_HANDLE[];
  static const wchar_t SWITCH_JOB_HANDLE[];

protected:
  virtual bool OnPrivInit() = 0;
  virtual bool OnInit() = 0;
  virtual void OnFini() = 0;

private:
  bool DropProcessIntegrityLevel();
};

class WindowsSandboxLauncher
{
public:
  WindowsSandboxLauncher();
  ~WindowsSandboxLauncher();

  bool Init();
  inline void AddHandleToInherit(HANDLE aHandle)
  {
    if (aHandle) {
      mHandlesToInherit.push_back(aHandle);
    }
  }
  bool Launch(const wchar_t* aExecutablePath, const wchar_t* aBaseCmdLine);
  bool Wait(unsigned int aTimeoutMs) const;
  bool IsSandboxRunning() const;

private:
  /*
  PTOKEN_GROUPS CreateSidsToDisable(HANDLE aToken,
                                    std::vector<SID_AND_ATTRIBUTES>& aOut,
                                    Sid& aLogonSid);
                                    */
  bool CreateSidList(HANDLE aToken, SID_AND_ATTRIBUTES*& aOutput,
                     unsigned int& aNumSidAttrs, unsigned int aFilterFlags,
                     mozilla::Sid* aLogonSid = nullptr);
  void FreeSidList(SID_AND_ATTRIBUTES* aListToFree);
  bool CreateTokens(const Sid& aCustomSid, ScopedHandle& aRestrictedToken,
                    ScopedHandle& aImpersonationToken, Sid& aLogonSid);
  HDESK CreateDesktop(const Sid& aCustomSid);
  bool CreateJob(ScopedHandle& aJob);
  bool GetWorkingDirectory(ScopedHandle& aToken, wchar_t* aBuf, size_t aBufLen);

  std::vector<HANDLE> mHandlesToInherit;
  bool    mHasWinVistaAPIs;
  bool    mHasWin8APIs;
  HANDLE  mProcess;
  HDESK   mDesktop;
};

} // namespace mozilla

#endif // __WINDOWSSANDBOX_H

