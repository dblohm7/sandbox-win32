/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WindowsSandbox.h"
#include "ArrayLength.h"
#include "dacl.h"
#include "MakeUniqueLen.h"
#include "sidattrs.h"
#include <sstream>
#include <shlobj.h>
#include <VersionHelpers.h>

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
WindowsSandbox::SetMitigations(const DWORD64 aMitigations)
{
  const DWORD64 kDEPPolicies =
    PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
    PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
    ;
  const DWORD64 kASLRPolicies =
    PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS |
#if defined(_M_X64)
    PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
#endif
    PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
    ;
  // Not all mitigations can be set at runtime
  const DWORD64 kAvailableMitigations =
    kDEPPolicies |
    kASLRPolicies |
    PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
    PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON |
#if _WIN32_WINNT >= 0x0A00
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON |
#endif
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
    ;
  if ((aMitigations & ~kAvailableMitigations) != 0) {
    return false;
  }
  auto pSetProcessMitigationPolicy =
    reinterpret_cast<decltype(&SetProcessMitigationPolicy)>(::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"),
          "SetProcessMitigationPolicy"));
  if (!pSetProcessMitigationPolicy) {
    // Not available
    return true;
  }
  BOOL ok = TRUE;
  if (aMitigations & kDEPPolicies) {
    PROCESS_MITIGATION_DEP_POLICY depPolicy = {0};
    if (aMitigations & PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE) {
      depPolicy.Enable = 1;
    }
    if (aMitigations & PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE) {
      depPolicy.DisableAtlThunkEmulation = 1;
    }
    ok &= pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy,
                                      sizeof(depPolicy));
  }
  if (aMitigations & kASLRPolicies) {
    PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {0};
    if (aMitigations &
        PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS) {
      aslrPolicy.EnableForceRelocateImages = 1;
      aslrPolicy.DisallowStrippedImages = 1;
    }
    if (aMitigations &
        PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON) {
      aslrPolicy.EnableBottomUpRandomization = 1;
    }
#if defined(_M_X64)
    if (aMitigations &
        PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON) {
      aslrPolicy.EnableHighEntropy = 1;
    }
#endif
    ok &= pSetProcessMitigationPolicy(ProcessASLRPolicy, &aslrPolicy,
                                      sizeof(aslrPolicy));
  }
  if (aMitigations &
      PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON) {
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handleChkPolicy = {0};
    handleChkPolicy.RaiseExceptionOnInvalidHandleReference = 1;
    handleChkPolicy.HandleExceptionsPermanentlyEnabled = 1;
    ok &= pSetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy,
                                      &handleChkPolicy, sizeof(handleChkPolicy));
  }
  if (aMitigations &
      PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON) {
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY win32kPolicy = {0};
    win32kPolicy.DisallowWin32kSystemCalls = 1;
    ok &= pSetProcessMitigationPolicy(ProcessSystemCallDisablePolicy,
                                      &win32kPolicy, sizeof(win32kPolicy));
  }
#if _WIN32_WINNT >= 0x0A00
  if (IsWindows10OrGreater() && (aMitigations &
      PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signPolicy = {0};
    signPolicy.MicrosoftSignedOnly = 1;
    ok &= pSetProcessMitigationPolicy(ProcessSignaturePolicy,
                                      &signPolicy, sizeof(signPolicy));
  }
#endif
  if (aMitigations &
      PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON) {
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY dllPolicy = {0};
    dllPolicy.DisableExtensionPoints = 1;
    ok &= pSetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
                                      &dllPolicy, sizeof(dllPolicy));
  }
  return !!ok;
}

bool
WindowsSandbox::Init(int aArgc, wchar_t* aArgv[])
{
  DECLARE_UNIQUE_KERNEL_HANDLE(job);
  for (int i = 1; i < aArgc; ++i) {
    if (!::wcscmp(aArgv[i], SWITCH_JOB_HANDLE) && i + 1 < aArgc) {
      uintptr_t uijob;
      std::wistringstream iss(aArgv[++i]);
      iss >> uijob;
      if (!iss) {
        return false;
      }
      job.reset(reinterpret_cast<HANDLE>(uijob));
    }
  }
  if (!SetMitigations(GetDeferredMitigationPolicies())) {
    return false;
  }
  bool ok = OnPrivInit();
  ok = ::RevertToSelf() && ok;
  ok = DropProcessIntegrityLevel() && ok;
  ok = ::AssignProcessToJobObject(job.get(), ::GetCurrentProcess()) && ok;
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

const DWORD64 WindowsSandboxLauncher::DEFAULT_MITIGATION_POLICIES =
  PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE |
  PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE |
  PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE |
  PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS |
  PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
  PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
#if defined(_M_X64)
  PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
#endif
  PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON |
#if _WIN32_WINNT >= 0x0A00
  PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON |
#endif
  PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
  ;

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
  ScopedHandle processToken(tmp, &::CloseHandle);
  SidAttributes toDisable;
  if (!toDisable.CreateFromTokenGroups(processToken.get(),
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
  bool result = !!::CreateRestrictedToken(processToken.get(),
                                          DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
                                          toDisable.Count(), toDisable, 0,
                                          nullptr, ArrayLength(toRestrict),
                                          toRestrict, &tmp);
  aRestrictedToken.reset(tmp);
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
  if (!SetTokenInformation(aRestrictedToken.get(), TokenDefaultDacl, &tokenDacl,
                           sizeof(tokenDacl))) {
    return false;
  }
  // 2. Duplicate the process token for impersonation.
  //    This will allow the sandbox to temporarily masquerade as a more
  //    privileged process until it reverts to self.
  SidAttributes toRestrictImp;
  if (!toRestrictImp.CreateFromTokenGroups(processToken.get(),
                                           SidAttributes::FILTER_INTEGRITY)) {
    return false;
  }
  tmp = NULL;
  result = !!::CreateRestrictedToken(processToken.get(), SANDBOX_INERT, 0,
                                     nullptr, 0, nullptr, toRestrictImp.Count(),
                                     toRestrictImp, &tmp);
  ScopedHandle tmpImpToken(tmp, &::CloseHandle);
  tmp = NULL;
  // We need to duplicate the impersonation token to raise its impersonation
  // level to SecurityImpersonation, or else impersonation won't work.
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
  result = !!DuplicateTokenEx(tmpImpToken.get(), TOKEN_IMPERSONATE | TOKEN_QUERY,
                              &sa, SecurityImpersonation,
                              TokenImpersonation, &tmp);
  if (!result) {
    return false;
  }
  aImpersonationToken.reset(tmp);
  return true;
}

HWINSTA
WindowsSandboxLauncher::CreateWindowStation()
{
  DWORD desiredAccess = GENERIC_READ | WINSTA_CREATEDESKTOP;
  HWINSTA winsta = ::CreateWindowStation(nullptr, 0,
                                         desiredAccess, nullptr);
  return winsta;
}

std::unique_ptr<wchar_t[]>
WindowsSandboxLauncher::GetWindowStationName(HWINSTA aWinsta)
{
  DWORD len = 0;
  ::GetUserObjectInformation(aWinsta, UOI_NAME, nullptr, len, &len);
  auto name(std::make_unique<wchar_t[]>(len));
  if (!::GetUserObjectInformation(aWinsta, UOI_NAME, name.get(), len, &len)) {
    return nullptr;
  }
  return name;
}

HDESK
WindowsSandboxLauncher::CreateDesktop(HWINSTA aWinsta, const Sid& aCustomSid)
{
  // 3. Create a new desktop for the sandbox.
  // 3a. Get the current desktop's DACL and Mandatory Label
  HDESK curDesktop = ::GetThreadDesktop(::GetCurrentThreadId());
  if (!curDesktop) {
    return nullptr;
  }
  SECURITY_INFORMATION curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  if (mHasWinVistaAPIs) {
    curDesktopSecInfo |= LABEL_SECURITY_INFORMATION;
  }
  DWORD curDesktopSdSize = 0;
  if (!::GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, nullptr,
                               curDesktopSdSize, &curDesktopSdSize) &&
                               ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return nullptr;
  }
  MAKE_UNIQUE_LEN(PSECURITY_DESCRIPTOR, curDesktopSd, curDesktopSdSize);
  if (!::GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, curDesktopSd,
                               curDesktopSdSize, &curDesktopSdSize)) {
    return nullptr;
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
    return nullptr;
  }
  MAKE_UNIQUE_LEN(PSECURITY_DESCRIPTOR, modifiedCurDesktopSd, curDesktopSdSize);
  MAKE_UNIQUE_LEN(PACL, curDesktopDacl, curDesktopDaclSize);
  MAKE_UNIQUE_LEN(PACL, curDesktopSacl, curDesktopSaclSize);
  MAKE_UNIQUE_LEN(PSID, curDesktopOwner, curDesktopOwnerSize);
  MAKE_UNIQUE_LEN(PSID, curDesktopPrimaryGroup, curDesktopPrimaryGroupSize);

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
    return nullptr;
  }
  // 3c. Add aCustomSid to the default desktop's DACL to finish plugging the
  //     SetThreadDesktop security hole.
  mozilla::Dacl modifiedCurDesktopDacl;
  modifiedCurDesktopDacl.AddDeniedAce(aCustomSid, GENERIC_ALL);
  result = modifiedCurDesktopDacl.Merge(curDesktopDacl);
  if (!result) {
    return nullptr;
  }
  // 3d. Set the security descriptor for the current desktop
  if (!::SetSecurityDescriptorDacl(modifiedCurDesktopSd, TRUE,
                                   modifiedCurDesktopDacl, FALSE)) {
    return nullptr;
  }
  curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  result = !!::SetUserObjectSecurity(curDesktop, &curDesktopSecInfo,
                                     modifiedCurDesktopSd);
  if (!result) {
    return nullptr;
  }
  // 3e. Temporarily set the window station to the sandbox window station
  HWINSTA curWinsta = ::GetProcessWindowStation();
  if (!::SetProcessWindowStation(aWinsta)) {
    return nullptr;
  }
  // 3f. Create the new desktop using the absolute security descriptor
  SECURITY_ATTRIBUTES newDesktopSa = {sizeof(newDesktopSa), curDesktopSd, FALSE};
  HDESK desktop = ::CreateDesktop(WindowsSandbox::DESKTOP_NAME, nullptr,
                                  nullptr, 0, DESKTOP_CREATEWINDOW,
                                  &newDesktopSa);
  // 3g. Revert to our previous window station
  if (!::SetProcessWindowStation(curWinsta)) {
    // uh-oh! we should warn!
  }
  return desktop;
}

bool
WindowsSandboxLauncher::CreateJob(ScopedHandle& aJob)
{
  // 4. Create the job object
  SECURITY_ATTRIBUTES jobSa = {sizeof(jobSa), nullptr, TRUE};
  aJob.reset(::CreateJobObject(&jobSa, nullptr));
  if (!aJob) {
    return false;
  }
  // 4a. Assign basic limits. This will prevent the sandboxed process from
  //     creating any new processes.
  JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimits;
  ZeroMemory(&basicLimits, sizeof(basicLimits));
  basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  basicLimits.ActiveProcessLimit = 1;
  if (!::SetInformationJobObject(aJob.get(), JobObjectBasicLimitInformation,
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
  if (!::SetInformationJobObject(aJob.get(), JobObjectBasicUIRestrictions,
                                 &uiLimits, sizeof(uiLimits))) {
    return false;
  }
  return true;
}

WindowsSandboxLauncher::WindowsSandboxLauncher()
  : mHasWinVistaAPIs(false)
  , mHasWin8APIs(false)
  , mHasWin10APIs(false)
  , mMitigationPolicies(0)
  , mProcess(NULL)
  , mWinsta(NULL)
  , mDesktop(NULL)
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
  if (mWinsta) {
    ::CloseWindowStation(mWinsta);
  }
}

bool
WindowsSandboxLauncher::Init(DWORD64 aMitigationPolicies)
{
  OSVERSIONINFO osv = {sizeof(osv)};
  if (!::GetVersionEx(&osv)) {
    return false;
  }
  mHasWinVistaAPIs = osv.dwMajorVersion >= 6;
  mHasWin8APIs = osv.dwMajorVersion > 6 ||
          osv.dwMajorVersion == 6 && osv.dwMinorVersion >= 2;
  mHasWin10APIs = osv.dwMajorVersion >= 10;
  mMitigationPolicies = aMitigationPolicies;
#if _WIN32_WINNT >= 0x0A00
  if (!mHasWin10APIs) {
    mMitigationPolicies &=
      ~PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
  }
#endif
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
  if (!aToken || !aBuf || !aBufCount) {
    return false;
  }
  if (mHasWinVistaAPIs) {
    MAKE_UNIQUE_MODULE_HANDLE(shell32, L"shell32.dll");
    if (!shell32) {
      return false;
    }
    SHGETKNOWNFOLDERPATH pSHGetKnownFolderPath = (SHGETKNOWNFOLDERPATH)
                        ::GetProcAddress(shell32.get(), "SHGetKnownFolderPath");
    if (!pSHGetKnownFolderPath) {
      return false;
    }
    PWSTR shWorkingDir = nullptr;
    if (FAILED(pSHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0, aToken.get(),
                                     &shWorkingDir))) {
      return false;
    }
    MAKE_UNIQUE_HANDLE(shWorkingDirUniq, shWorkingDir, &::CoTaskMemFree);
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
  DECLARE_UNIQUE_KERNEL_HANDLE(restrictedToken);
  DECLARE_UNIQUE_KERNEL_HANDLE(impersonationToken);
  if (!CreateTokens(customSid, restrictedToken, impersonationToken, logonSid)) {
    return false;
  }
  mWinsta = CreateWindowStation();
  if (!mWinsta) {
    return false;
  }
  mDesktop = CreateDesktop(mWinsta, customSid);
  if (!mDesktop) {
    return false;
  }
  DECLARE_UNIQUE_KERNEL_HANDLE(job);
  if (!CreateJob(job)) {
    return false;
  }
  // 5. Build the command line string
  wostringstream oss;
  oss << aBaseCmdLine;
  oss << L" ";
  oss << WindowsSandbox::SWITCH_JOB_HANDLE;
  oss << L" ";
  oss << hex << job.get();
  // 6. Set the working directory. With low integrity levels on Vista most
  //    directories are inaccessible.
  wchar_t workingDir[MAX_PATH + 1] = {0};
  if (!GetWorkingDirectory(restrictedToken, workingDir, ArrayLength(workingDir))) {
    return false;
  }
  // 7. Initialize the explicit list of handles to inherit (Vista+).
  bool result = false;
  DECLARE_UNIQUE_LEN(LPPROC_THREAD_ATTRIBUTE_LIST, attrList);
  std::unique_ptr<HANDLE[]> inheritableHandles;
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
    /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST and
     * PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
     */
    const DWORD attrCount = 2;
    if (!pInitializeProcThreadAttributeList(nullptr, attrCount, 0,
                                            &attrListSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }
    ALLOC_UNIQUE_LEN(attrList, attrListSize);
    if (!pInitializeProcThreadAttributeList(attrList, attrCount, 0,
                                            &attrListSize)) {
      return false;
    }
    MAKE_UNIQUE_HANDLE(listDeleter, attrList, pDeleteProcThreadAttributeList);
    size_t handleCount = mHandlesToInherit.size();
    inheritableHandles = std::make_unique<HANDLE[]>(handleCount + 2);
    memcpy(inheritableHandles.get(), &mHandlesToInherit[0],
           handleCount * sizeof(HANDLE));
    inheritableHandles[handleCount++] = impersonationToken.get();
    inheritableHandles[handleCount++] = job.get();
    result = !!pUpdateProcThreadAttribute(attrList, 0,
                                          PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                          inheritableHandles.get(),
                                          handleCount * sizeof(HANDLE), nullptr,
                                          nullptr);
    if (!result) {
      return false;
    }
    result = !!pUpdateProcThreadAttribute(attrList, 0,
                                          PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                          &mMitigationPolicies,
                                          sizeof(DWORD64), nullptr, nullptr);
    if (!result) {
      return false;
    }
    // Can't delete attrList yet
    listDeleter.release();
  }
  // 8. Create the process using the restricted token
  STARTUPINFOEX siex;
  ZeroMemory(&siex, sizeof(siex));
  auto winstaName = GetWindowStationName(mWinsta);
  std::wostringstream ssDesktop;
  ssDesktop << winstaName.get() << L"\\" << WindowsSandbox::DESKTOP_NAME;
  siex.StartupInfo.lpDesktop = (LPWSTR)ssDesktop.str().c_str();
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
  result = !!::CreateProcessAsUser(restrictedToken.get(), aExecutablePath,
                                   const_cast<wchar_t*>(oss.str().c_str()), &sa,
                                   &sa, TRUE, creationFlags, L"", workingDir,
                                   &siex.StartupInfo, &procInfo);
  MAKE_UNIQUE_KERNEL_HANDLE(childProcess, procInfo.hProcess);
  MAKE_UNIQUE_KERNEL_HANDLE(mainThread, procInfo.hThread);
  if (mHasWinVistaAPIs) {
    pDeleteProcThreadAttributeList(attrList);
  }
  if (!result) {
    return false;
  }
  if (!::SetThreadToken(&procInfo.hThread, impersonationToken.get()) ||
      ::ResumeThread(mainThread.get()) == static_cast<DWORD>(-1)) {
    ::TerminateProcess(procInfo.hProcess, 1);
    return false;
  }
  mProcess = childProcess.release();
  return true;
}

} // namespace mozilla

