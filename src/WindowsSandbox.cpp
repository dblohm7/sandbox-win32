/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WindowsSandbox.h"
#include "loki/ScopeGuard.h"
#include "dacl.h"
#include "sidattrs.h"
#include <sstream>
#include <shlobj.h>

using std::wistringstream;
using std::wostringstream;
using std::hex;

typedef HRESULT (__stdcall *SHGETKNOWNFOLDERPATH)(REFKNOWNFOLDERID,DWORD,HANDLE,PWSTR*);
typedef BOOL (WINAPI *INITIALIZEPROCTHREADATTRIBUTELIST)
                             (LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD,PSIZE_T);
typedef BOOL (WINAPI *UPDATEPROCTHREADATTRIBUTE)(LPPROC_THREAD_ATTRIBUTE_LIST,DWORD,DWORD_PTR,PVOID,SIZE_T,PVOID,PSIZE_T);
typedef VOID (WINAPI *DELETEPROCTHREADATTRIBUTELIST)(LPPROC_THREAD_ATTRIBUTE_LIST);

namespace mozilla {

const wchar_t WindowsSandbox::DESKTOP_NAME[] = L"moz-sandbox";
const wchar_t WindowsSandbox::SWITCH_JOB_HANDLE[] = L"--job";

bool
WindowsSandbox::DropProcessIntegrityLevel()
{
  HANDLE processToken = NULL;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_DEFAULT,
                          &processToken)) {
    return false;
  }
  TOKEN_MANDATORY_LABEL il;
  ZeroMemory(&il, sizeof(il));
  il.Label.Sid = mozilla::Sid::GetIntegrityLow();
  bool result = !!::SetTokenInformation(processToken, TokenIntegrityLevel,
                                        &il, sizeof(il));
  ::CloseHandle(processToken);
  return result;
}

bool
WindowsSandbox::Init(int aArgc, wchar_t* aArgv[])
{
  HANDLE job = NULL;
  for (int i = 1; i < aArgc; ++i) {
    if (!::wcscmp(aArgv[i], SWITCH_JOB_HANDLE) && i + 1 < aArgc) {
      std::wistringstream iss(aArgv[++i]);
      iss >> job;
      if (!iss) {
        return false;
      }
    }
  }
  bool ok = OnPrivInit();
  ok = ::RevertToSelf() && ok;
  ok = DropProcessIntegrityLevel() && ok;
  ok = ::AssignProcessToJobObject(job, ::GetCurrentProcess()) && ok;
  ::CloseHandle(job);
  if (!ok) {
    return ok;
  }
  return OnInit();
}

void
WindowsSandbox::Fini()
{
  OnFini();
}

bool
WindowsSandboxLauncher::CreateTokens(const Sid& aCustomSid,
                                     ScopedHandle& aRestrictedToken,
                                     ScopedHandle& aImpersonationToken,
                                     Sid& aLogonSid)
{
  // 1. Open the process's token and create a restricted token based on it
  HANDLE tmp = NULL;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_DEFAULT |
                          TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                          &tmp)) {
    return false;
  }
  ScopedHandle processToken(tmp);
  SidAttributes toDisable;
  if (!toDisable.CreateFromTokenGroups(processToken,
                                       SidAttributes::FILTER_RESTRICTED_DISABLE,
                                       &aLogonSid)) {
    return false;
  }
  SID_AND_ATTRIBUTES toRestrict[] = {{mozilla::Sid::GetEveryone()},
                                     {mozilla::Sid::GetUsers()},
                                     {mozilla::Sid::GetRestricted()},
                                     {aLogonSid},
                                     {const_cast<mozilla::Sid&>(aCustomSid)}};
  tmp = NULL;
  bool result = !!::CreateRestrictedToken(processToken, DISABLE_MAX_PRIVILEGE |
                                          SANDBOX_INERT, toDisable.Count(),
                                          toDisable, 0, nullptr,
                                          sizeof(toRestrict)
                                            / sizeof(SID_AND_ATTRIBUTES),
                                          toRestrict, &tmp);
  aRestrictedToken.Set(tmp);
  if (!result) {
    return false;
  }
  // The restricted token needs an updated default DACL
  mozilla::Dacl dacl;
  dacl.AddAllowedAce(mozilla::Sid::GetLocalSystem(), GENERIC_ALL);
  dacl.AddAllowedAce(mozilla::Sid::GetAdministrators(), GENERIC_ALL);
  dacl.AddAllowedAce(aLogonSid, GENERIC_ALL);
  TOKEN_DEFAULT_DACL tokenDacl;
  ZeroMemory(&tokenDacl, sizeof(tokenDacl));
  tokenDacl.DefaultDacl = (PACL)dacl;
  if (!SetTokenInformation(aRestrictedToken, TokenDefaultDacl, &tokenDacl,
                           sizeof(tokenDacl))) {
    return false;
  }
  // 2. Duplicate the process token for impersonation.
  //    This will allow the sandbox to temporarily masquerade as a more 
  //    privileged process until it reverts to self.
  SidAttributes toRestrictImp;
  if (!toRestrictImp.CreateFromTokenGroups(processToken,
                                           SidAttributes::FILTER_INTEGRITY)) {
    return false;
  }
  tmp = NULL;
  result = !!::CreateRestrictedToken(processToken, SANDBOX_INERT, 0, nullptr, 0,
                                     nullptr, toRestrictImp.Count(),
                                     toRestrictImp, &tmp);
  ScopedHandle tmpImpToken(tmp);
  tmp = NULL;
  // We need to duplicate the impersonation token to raise its impersonation
  // level to SecurityImpersonation, or else impersonation won't work.
  result = !!DuplicateTokenEx(tmpImpToken, TOKEN_IMPERSONATE | TOKEN_QUERY,
                              nullptr, SecurityImpersonation,
                              TokenImpersonation, &tmp);
  if (!result) {
    return false;
  }
  aImpersonationToken.Set(tmp);
  return true;
}

HDESK
WindowsSandboxLauncher::CreateDesktop(const Sid& aCustomSid)
{
  // 3. Create a new desktop for the sandbox.
  // 3a. Get the current desktop's DACL and Mandatory Label
  HDESK curDesktop = ::GetThreadDesktop(::GetCurrentThreadId());
  if (!curDesktop) {
    return false;
  }
  SECURITY_INFORMATION curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  if (mHasWinVistaAPIs) {
    curDesktopSecInfo |= LABEL_SECURITY_INFORMATION;
  }
  PSECURITY_DESCRIPTOR curDesktopSd = nullptr;
  DWORD curDesktopSdSize = 0;
  if (!::GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, curDesktopSd,
                               curDesktopSdSize, &curDesktopSdSize) &&
                               ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }
  curDesktopSd = (PSECURITY_DESCRIPTOR) ::calloc(curDesktopSdSize, 1);
  LOKI_ON_BLOCK_EXIT(::free, curDesktopSd);
  if (!::GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, curDesktopSd,
                               curDesktopSdSize, &curDesktopSdSize)) {
    return false;
  }
  // 3b. Convert security descriptor from self-relative to absolute so that we
  //     can modify it.
  DWORD curDesktopDaclSize = 0;
  DWORD curDesktopSaclSize = 0;
  DWORD curDesktopOwnerSize = 0;
  DWORD curDesktopPrimaryGroupSize = 0;
  if(!::MakeAbsoluteSD(curDesktopSd, nullptr, &curDesktopSdSize,
                       nullptr, &curDesktopDaclSize, nullptr,
                       &curDesktopSaclSize, nullptr, &curDesktopOwnerSize,
                       nullptr, &curDesktopPrimaryGroupSize) &&
     ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }
  PSECURITY_DESCRIPTOR modifiedCurDesktopSd =
                            (PSECURITY_DESCRIPTOR) ::calloc(curDesktopSdSize, 1);
  PACL curDesktopDacl = (PACL) ::calloc(curDesktopDaclSize, 1);
  LOKI_ON_BLOCK_EXIT(::free, curDesktopDacl);
  PACL curDesktopSacl = (PACL) ::calloc(curDesktopSaclSize, 1);
  LOKI_ON_BLOCK_EXIT(::free, curDesktopSacl);
  PSID curDesktopOwner = (PSID) ::calloc(curDesktopOwnerSize, 1);
  LOKI_ON_BLOCK_EXIT(::free, curDesktopOwner);
  PSID curDesktopPrimaryGroup = (PSID) ::calloc(curDesktopPrimaryGroupSize, 1);
  LOKI_ON_BLOCK_EXIT(::free, curDesktopPrimaryGroup);
  // This call is effectively making a copy of curDesktopSd (which is self-
  // relative) as an absolute security descriptor which we will modify. These
  // modifications are applied to the *current* desktop's DACL, not the new
  // desktop's DACL!
  bool result;
  result = !!::MakeAbsoluteSD(curDesktopSd, modifiedCurDesktopSd, &curDesktopSdSize,
                              curDesktopDacl, &curDesktopDaclSize, curDesktopSacl,
                              &curDesktopSaclSize, curDesktopOwner,
                              &curDesktopOwnerSize, curDesktopPrimaryGroup,
                              &curDesktopPrimaryGroupSize);
  if (!result) {
    return false;
  }
  // 3c. Add aCustomSid to the default desktop's DACL to finish plugging the
  //     SetThreadDesktop security hole.
  mozilla::Dacl modifiedCurDesktopDacl;
  modifiedCurDesktopDacl.AddDeniedAce(aCustomSid, GENERIC_ALL);
  result = modifiedCurDesktopDacl.Merge(curDesktopDacl);
  if (!result) {
    return false;
  }
  // 3d. Set the security descriptor for the current desktop
  if (!::SetSecurityDescriptorDacl(modifiedCurDesktopSd, TRUE,
                                   modifiedCurDesktopDacl, FALSE)) {
    return false;
  }
  curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  result = !!::SetUserObjectSecurity(curDesktop, &curDesktopSecInfo,
                                     modifiedCurDesktopSd);
  if (!result) {
    return false;
  }
  // 3e. Create the new desktop using the absolute security descriptor
  SECURITY_ATTRIBUTES newDesktopSa = {sizeof(newDesktopSa), curDesktopSd, FALSE};
  HDESK desktop = ::CreateDesktop(WindowsSandbox::DESKTOP_NAME, nullptr,
                                  nullptr, 0, DESKTOP_CREATEWINDOW,
                                  &newDesktopSa);
  return desktop;
}

bool
WindowsSandboxLauncher::CreateJob(ScopedHandle& aJob)
{
  // 4. Create the job object
  SECURITY_ATTRIBUTES jobSa = {sizeof(jobSa), nullptr, TRUE};
  aJob.Set(::CreateJobObject(&jobSa, nullptr));
  if (!aJob.IsValid()) {
    return false;
  }
  // 4a. Assign basic limits. This will prevent the sandboxed process from
  //     creating any new processes.
  JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimits;
  ZeroMemory(&basicLimits, sizeof(basicLimits));
  basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  basicLimits.ActiveProcessLimit = 1;
  if (!::SetInformationJobObject(aJob, JobObjectBasicLimitInformation,
                                 &basicLimits, sizeof(basicLimits))) {
    return false;
  }
  // 4b. Assign all UI limits.
  // To explicitly grant user handles, call UserHandleGrantAccess
  JOBOBJECT_BASIC_UI_RESTRICTIONS uiLimits;
  ZeroMemory(&uiLimits, sizeof(uiLimits));
  uiLimits.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP |
                                 JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                                 JOB_OBJECT_UILIMIT_EXITWINDOWS |
                                 JOB_OBJECT_UILIMIT_GLOBALATOMS | 
                                 JOB_OBJECT_UILIMIT_HANDLES |
                                 JOB_OBJECT_UILIMIT_READCLIPBOARD |
                                 JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                                 JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
  if (!::SetInformationJobObject(aJob, JobObjectBasicUIRestrictions, &uiLimits,
                                 sizeof(uiLimits))) {
    return false;
  }
  return true;
}

WindowsSandboxLauncher::WindowsSandboxLauncher()
  :mHasWinVistaAPIs(false),
   mHasWin8APIs(false),
   mProcess(NULL),
   mDesktop(NULL)
{
}

WindowsSandboxLauncher::~WindowsSandboxLauncher()
{
  if (mProcess) {
    ::CloseHandle(mProcess);
  }
  if (mDesktop) {
    ::CloseDesktop(mDesktop);
  }
}

bool
WindowsSandboxLauncher::Init()
{
  OSVERSIONINFO osv = {sizeof(osv)};
  if (!::GetVersionEx(&osv)) {
    return false;
  } 
  mHasWinVistaAPIs = osv.dwMajorVersion >= 6;
  mHasWin8APIs = osv.dwMajorVersion > 6 ||
          osv.dwMajorVersion == 6 && osv.dwMinorVersion >= 2;
  return true;
}

bool
WindowsSandboxLauncher::Wait(unsigned int aTimeoutMs) const
{
  return mProcess &&
         ::WaitForSingleObject(mProcess, aTimeoutMs) == WAIT_OBJECT_0;
}

bool
WindowsSandboxLauncher::IsSandboxRunning() const
{
  return mProcess && ::WaitForSingleObject(mProcess, 0) == WAIT_TIMEOUT;
}

bool
WindowsSandboxLauncher::GetWorkingDirectory(ScopedHandle& aToken, wchar_t* aBuf,
                                            size_t aBufCount)
{
  if (!aToken.IsValid() || !aBuf || !aBufCount) {
    return false;
  }
  if (mHasWinVistaAPIs) {
    HMODULE shell32 = ::LoadLibrary(L"shell32.dll");
    if (!shell32) {
      return false;
    }
    LOKI_ON_BLOCK_EXIT(::FreeLibrary, shell32);
    SHGETKNOWNFOLDERPATH pSHGetKnownFolderPath = (SHGETKNOWNFOLDERPATH)
                              ::GetProcAddress(shell32, "SHGetKnownFolderPath");
    if (!pSHGetKnownFolderPath) {
      return false;
    }
    PWSTR shWorkingDir = nullptr;
    if (FAILED(pSHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0, aToken,
                                     &shWorkingDir))) {
      return false;
    }
    LOKI_ON_BLOCK_EXIT(::CoTaskMemFree, shWorkingDir);
    if (::wcslen(shWorkingDir) > aBufCount - 1) {
      return false;
    }
    ::wcsncpy(aBuf, shWorkingDir, aBufCount - 1);
  } else {
    if (!::GetTempPath(aBufCount, aBuf)) {
      return false;
    }
  }
  return true;
}

bool
WindowsSandboxLauncher::Launch(const wchar_t* aExecutablePath,
                               const wchar_t* aBaseCmdLine)
{
  // customSid guards against the SetThreadDesktop() security hole
  mozilla::Sid customSid;
  if (!customSid.InitCustom()) {
    return false;
  }
  mozilla::Sid logonSid;
  ScopedHandle restrictedToken, impersonationToken;
  if (!CreateTokens(customSid, restrictedToken, impersonationToken, logonSid)) {
    return false;
  }
  mDesktop = CreateDesktop(customSid);
  ScopedHandle job;
  if (!CreateJob(job)) {
    return false;
  }
  // 5. Build the command line string
  wostringstream oss;
  oss << aBaseCmdLine;
  oss << L" ";
  oss << WindowsSandbox::SWITCH_JOB_HANDLE;
  oss << L" ";
  oss << hex << job;
  // 6. Set the working directory. With low integrity levels on Vista most
  //    directories are inaccessible.
  wchar_t workingDir[MAX_PATH + 1] = {0};
  if (!GetWorkingDirectory(restrictedToken, workingDir,
                           sizeof(workingDir)/sizeof(workingDir[0]))) {
    return false;
  }
  // 7. Initialize the explicit list of handles to inherit (Vista+).
  bool result = false;
  LPPROC_THREAD_ATTRIBUTE_LIST attrList = nullptr;
  LOKI_ON_BLOCK_EXIT(::free, attrList);
  DELETEPROCTHREADATTRIBUTELIST pDeleteProcThreadAttributeList = nullptr;
  if (mHasWinVistaAPIs) {
    SIZE_T attrListSize = 0;
    HMODULE kernel32 = ::GetModuleHandle(L"kernel32.dll");
    INITIALIZEPROCTHREADATTRIBUTELIST pInitializeProcThreadAttributeList =
      (INITIALIZEPROCTHREADATTRIBUTELIST)
      ::GetProcAddress(kernel32, "InitializeProcThreadAttributeList");
    UPDATEPROCTHREADATTRIBUTE pUpdateProcThreadAttribute =
      (UPDATEPROCTHREADATTRIBUTE) ::GetProcAddress(kernel32,
          "UpdateProcThreadAttribute");
    pDeleteProcThreadAttributeList = (DELETEPROCTHREADATTRIBUTELIST)
                    ::GetProcAddress(kernel32, "DeleteProcThreadAttributeList");
    if (!pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute ||
        !pDeleteProcThreadAttributeList) {
      return false;
    }
    if (!pInitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST) ::calloc(attrListSize, 1);
    if (!pInitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
      return false;
    }
    LOKI_ON_BLOCK_EXIT(pDeleteProcThreadAttributeList, attrList);
    size_t handleCount = mHandlesToInherit.size();
    HANDLE *inheritableHandles = new HANDLE[mHandlesToInherit.size() + 2];
    memcpy(inheritableHandles, &mHandlesToInherit[0],
           handleCount * sizeof(HANDLE));
    inheritableHandles[handleCount++] = impersonationToken;
    inheritableHandles[handleCount++] = job;
    result = !!pUpdateProcThreadAttribute(attrList, 0,
                                          PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                          inheritableHandles, handleCount *
                                          sizeof(HANDLE), nullptr, nullptr);
    delete[] inheritableHandles; inheritableHandles = nullptr;
    if (!result) {
      pDeleteProcThreadAttributeList(attrList);
      return false;
    }
  }
  // 8. Create the process using the restricted token
  STARTUPINFOEX siex;
  ZeroMemory(&siex, sizeof(siex));
  siex.StartupInfo.lpDesktop = (LPWSTR)WindowsSandbox::DESKTOP_NAME;
  DWORD creationFlags = CREATE_SUSPENDED;
  if (mHasWinVistaAPIs) {
    siex.StartupInfo.cb = sizeof(STARTUPINFOEX);
    siex.lpAttributeList = attrList;
    creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
  } else {
    siex.StartupInfo.cb = sizeof(STARTUPINFO);
  }
  if (!mHasWin8APIs) {
    // Job objects don't nest until Windows 8. To create a process that is to be
    // part of a job, we need to create it as a "breakaway" process.
    creationFlags |= CREATE_BREAKAWAY_FROM_JOB;
  }
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, FALSE};
  PROCESS_INFORMATION procInfo;
  result = !!CreateProcessAsUser(restrictedToken, aExecutablePath,
                                 const_cast<wchar_t*>(oss.str().c_str()), &sa,
                                 &sa, TRUE, creationFlags, L"", workingDir,
                                 &siex.StartupInfo, &procInfo);
  ScopedHandle childProcess(procInfo.hProcess);
  ScopedHandle mainThread(procInfo.hThread);
  if (mHasWinVistaAPIs) {
    pDeleteProcThreadAttributeList(attrList);
  }
  if (!result) {
    return false;
  }
  if (!::SetThreadToken(&procInfo.hThread, impersonationToken) ||
      ::ResumeThread(mainThread) == static_cast<DWORD>(-1)) {
    ::TerminateProcess(procInfo.hProcess, 1);
    return false;
  }
  mProcess = childProcess.Take();
  return true;
}

} // namespace mozilla

