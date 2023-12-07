/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __WINDOWSSANDBOX_H
#define __WINDOWSSANDBOX_H

#include <windows.h>
#include "Dacl.h"
#include "Sid.h"
#include "UniqueHandle.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mozilla {

class WindowsSandbox
{
public:
  WindowsSandbox() {}
  virtual ~WindowsSandbox() {}

  bool Init(int aArgc, wchar_t* aArgv[]);
  void Fini();

  static const std::wstring DESKTOP_NAME;
  static const std::wstring_view SWITCH_JOB_HANDLE;

protected:
  virtual DWORD64 GetDeferredMitigationPolicies() { return 0; }
  virtual bool OnPrivInit() = 0;
  virtual bool OnInit() = 0;
  virtual void OnFini() = 0;

private:
  bool ValidateJobHandle(HANDLE aJob);
  bool SetMitigations(const DWORD64 aMitigations);
  bool DropProcessIntegrityLevel();
};

class WindowsSandboxLauncher
{
public:
  WindowsSandboxLauncher();
  virtual ~WindowsSandboxLauncher();

  enum InitFlags
  {
    eInitNormal = 0,
    eInitNoSeparateWindowStation = 1
  };

  bool Init(InitFlags aInitFlags = eInitNormal,
            DWORD64 aMitigationPolicies = DEFAULT_MITIGATION_POLICIES);

  inline void AddHandleToInherit(HANDLE aHandle)
  {
    if (aHandle) {
      mHandlesToInherit.push_back(aHandle);
    }
  }
  bool Launch(const std::wstring_view aExecutablePath, const std::wstring_view aBaseCmdLine);
  bool Wait(unsigned int aTimeoutMs) const;
  bool IsSandboxRunning() const;
  bool GetInheritableSecurityDescriptor(SECURITY_ATTRIBUTES& aSa,
                                        const BOOL aInheritable = TRUE);

  static const DWORD64 DEFAULT_MITIGATION_POLICIES;

protected:
  virtual bool PreResume() { return true; }

private:
  bool CreateTokens(const Sid& aCustomSid, UniqueKernelHandle& aRestrictedToken,
                    UniqueKernelHandle& aImpersonationToken, Sid& aLogonSid);
  HWINSTA CreateWindowStation();
  std::optional<std::wstring> GetWindowStationName(HWINSTA aWinsta);
  HDESK CreateDesktop(HWINSTA aWinsta, const Sid& aCustomSid);
  bool CreateJob(UniqueKernelHandle& aJob);
  std::optional<std::wstring> GetWorkingDirectory(UniqueKernelHandle& aToken);
  std::optional<std::wstring> CreateAbsolutePath(const std::wstring_view aInputPath);
  bool BuildInheritableSecurityDescriptor(const Sid& aLogonSid);

  InitFlags mInitFlags;
  std::vector<HANDLE> mHandlesToInherit;
  bool    mHasWin8APIs;
  bool    mHasWin10APIs;
  DWORD64 mMitigationPolicies;
  HANDLE  mProcess;
  HWINSTA mWinsta;
  HDESK   mDesktop;
  Dacl    mInheritableDacl;
  SECURITY_DESCRIPTOR mInheritableSd;
};

} // namespace mozilla

#endif // __WINDOWSSANDBOX_H

