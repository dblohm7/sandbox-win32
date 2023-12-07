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
#include <string_view>

#include <aclapi.h>
#include <pathcch.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <VersionHelpers.h>

using namespace ::std::literals::string_literals;
using namespace ::std::literals::string_view_literals;
using std::wistringstream;
using std::wostringstream;
using std::hex;

namespace mozilla {

const std::wstring WindowsSandbox::DESKTOP_NAME = L"moz-sandbox"s;
const std::wstring_view WindowsSandbox::SWITCH_JOB_HANDLE = L"--job"sv;

bool
WindowsSandbox::DropProcessIntegrityLevel()
{
  HANDLE processToken = nullptr;
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
WindowsSandbox::ValidateJobHandle(HANDLE aJob)
{
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
  BOOL ok = ::QueryInformationJobObject(aJob,
                                        JobObjectBasicAccountingInformation,
                                        &info, sizeof(info), nullptr);
#ifdef DEBUG
  if (!ok) {
    DebugBreak();
  }
#endif
  return !!ok;
}

bool
WindowsSandbox::Init(int aArgc, wchar_t* aArgv[])
{
  UniqueKernelHandle job;
  for (int i = 1; i < aArgc; ++i) {
    if (SWITCH_JOB_HANDLE == aArgv[i] && i + 1 < aArgc) {
      uintptr_t uijob;
      std::wistringstream iss(aArgv[++i]);
      iss >> hex >> uijob;
      if (!iss) {
        return false;
      }

      job.reset(reinterpret_cast<HANDLE>(uijob));
    }
  }

  bool ok = ValidateJobHandle(job.get());
  ok = ok && OnPrivInit();
  ok = ok && ::RevertToSelf();
  ok = ok && DropProcessIntegrityLevel();
  ok = ok && ::AssignProcessToJobObject(job.get(), ::GetCurrentProcess());
  ok = ok && SetMitigations(GetDeferredMitigationPolicies());
  if (!ok) {
    return ok;
  }

  job.reset();
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
                                     UniqueKernelHandle& aRestrictedToken,
                                     UniqueKernelHandle& aImpersonationToken,
                                     Sid& aLogonSid)
{
  // 1. Open the process's token and create a restricted token based on it
  HANDLE tmp = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_DEFAULT |
                          TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                          &tmp)) {
    return false;
  }
  UniqueKernelHandle processToken(tmp);

  SidAttributes toDisable;
  if (!toDisable.CreateFromTokenGroups(processToken.get(),
                                       SidAttributes::FILTER_RESTRICTED_DISABLE,
                                       &aLogonSid)) {
    return false;
  }

  // Now that we have aLogonSid, build a security descriptor that can be used
  // for securable objects that need to be inherited by the sandboxed process.
  if (!BuildInheritableSecurityDescriptor(aLogonSid)) {
    return false;
  }

  // Create the restricted token...
  SID_AND_ATTRIBUTES toRestrict[] = {{mozilla::Sid::GetEveryone()},
                                     {mozilla::Sid::GetUsers()},
                                     {mozilla::Sid::GetRestricted()},
                                     {aLogonSid},
                                     {const_cast<mozilla::Sid&>(aCustomSid)}};
  tmp = nullptr;
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
  Dacl dacl;
  dacl.AddAllowedAce(mozilla::Sid::GetLocalSystem(), GENERIC_ALL);
  dacl.AddAllowedAce(mozilla::Sid::GetAdministrators(), GENERIC_ALL);
  dacl.AddAllowedAce(aLogonSid, GENERIC_ALL);

  TOKEN_DEFAULT_DACL tokenDacl;
  ZeroMemory(&tokenDacl, sizeof(tokenDacl));
  tokenDacl.DefaultDacl = (PACL)dacl;
  if (!tokenDacl.DefaultDacl) {
    return false;
  }

  if (!::SetTokenInformation(aRestrictedToken.get(), TokenDefaultDacl,
                             &tokenDacl, sizeof(tokenDacl))) {
    return false;
  }

  // 2. Duplicate the process token for impersonation.
  //    This will allow the sandbox to temporarily masquerade as a more
  //    privileged process until it reverts to self.

  //    NOTE: FILTER_ADD_RESTRICTED needed here because CreateRestrictedToken
  //          always requires the Restricted SID as part of the SidsToRestrict
  //          parameter.
  SidAttributes toRestrictImp;
  if (!toRestrictImp.CreateFromTokenGroups(processToken.get(),
                                           SidAttributes::FILTER_INTEGRITY |
                                           SidAttributes::FILTER_ADD_RESTRICTED)) {
    return false;
  }

  tmp = nullptr;
  result = !!::CreateRestrictedToken(processToken.get(), SANDBOX_INERT, 0,
                                     nullptr, 0, nullptr, toRestrictImp.Count(),
                                     toRestrictImp, &tmp);
  UniqueKernelHandle tmpImpToken(tmp);
  tmp = nullptr;

  // We need to duplicate the impersonation token to raise its impersonation
  // level to SecurityImpersonation, or else impersonation won't work.
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
  result = !!::DuplicateTokenEx(tmpImpToken.get(), TOKEN_IMPERSONATE | TOKEN_QUERY,
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
  PACL pdacl = nullptr;
  PSECURITY_DESCRIPTOR psd = nullptr;
  if (::GetSecurityInfo(::GetProcessWindowStation(), SE_WINDOW_OBJECT,
                        DACL_SECURITY_INFORMATION, nullptr, nullptr, &pdacl,
                        nullptr, &psd) != ERROR_SUCCESS) {
    return nullptr;
  }

  SECURITY_ATTRIBUTES sa = {sizeof(sa), psd, FALSE};
  DWORD desiredAccess = GENERIC_READ | WINSTA_CREATEDESKTOP;
  HWINSTA winsta = ::CreateWindowStation(nullptr, 0,
                                         desiredAccess, &sa);
  ::LocalFree(psd);
  return winsta;
}

std::optional<std::wstring>
WindowsSandboxLauncher::GetWindowStationName(HWINSTA aWinsta)
{
  DWORD lenBytes = 0;
  if (!::GetUserObjectInformation(aWinsta, UOI_NAME, nullptr, lenBytes, &lenBytes) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return {};
  }

  auto name = std::make_optional<std::wstring>(
      static_cast<std::wstring::size_type>((lenBytes+1)/sizeof(std::wstring::value_type)),
      std::wstring::value_type(0));
  if (!::GetUserObjectInformation(aWinsta, UOI_NAME, name.value().data(),
                                  name.value().length() * sizeof(std::wstring::value_type),
                                  nullptr)) {
    return {};
  }

  // Chop off terminator
  name.value().pop_back();

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

  SECURITY_INFORMATION curDesktopSecInfo = DACL_SECURITY_INFORMATION |
                                           LABEL_SECURITY_INFORMATION;
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
  if (aWinsta) {
    if (!::SetProcessWindowStation(aWinsta)) {
      return nullptr;
    }
  }

  // 3f. Create the new desktop using the absolute security descriptor
  SECURITY_ATTRIBUTES newDesktopSa = {sizeof(newDesktopSa), curDesktopSd, FALSE};
  HDESK desktop = ::CreateDesktop(WindowsSandbox::DESKTOP_NAME.c_str(), nullptr,
                                  nullptr, 0, DESKTOP_CREATEWINDOW,
                                  &newDesktopSa);
  // 3g. Revert to our previous window station
  if (aWinsta) {
    if (!::SetProcessWindowStation(curWinsta)) {
      return nullptr;
    }
  }

  return desktop;
}

bool
WindowsSandboxLauncher::CreateJob(UniqueKernelHandle& aJob)
{
  // 4. Create the job object
  SECURITY_ATTRIBUTES jobSa;
  if (!GetInheritableSecurityDescriptor(jobSa)) {
    return false;
  }

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
  : mInitFlags(eInitNormal)
  , mHasWin8APIs(false)
  , mHasWin10APIs(false)
  , mMitigationPolicies(0)
  , mProcess(nullptr)
  , mWinsta(nullptr)
  , mDesktop(nullptr)
{
  ZeroMemory(&mInheritableSd, sizeof(mInheritableSd));
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
WindowsSandboxLauncher::Init(InitFlags aInitFlags, DWORD64 aMitigationPolicies)
{
  mInitFlags = aInitFlags;
  OSVERSIONINFO osv = {sizeof(osv)};
  if (!::GetVersionEx(&osv)) {
    return false;
  }
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

std::optional<std::wstring>
WindowsSandboxLauncher::GetWorkingDirectory(UniqueKernelHandle& aToken)
{
  if (!aToken) {
    return {};
  }

  PWSTR shWorkingDir = nullptr;
  if (FAILED(::SHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0, aToken.get(),
                                    &shWorkingDir))) {
    return {};
  }
  UniqueCOMAllocatedString shWorkingDirUniq(shWorkingDir);

  return std::make_optional<std::wstring>(shWorkingDir);
}

std::optional<std::wstring>
WindowsSandboxLauncher::CreateAbsolutePath(const std::wstring_view aInputPath)
{
  wchar_t buf[MAX_PATH + 1] = {};
  if (!_wfullpath(buf, std::wstring(aInputPath).c_str(), ArrayLength(buf))) {
    return {};
  }

  HRESULT hr = ::PathCchAddExtension(buf, ArrayLength(buf), L"exe");
  if (FAILED(hr)) {
    return {};
  }

  return std::make_optional<std::wstring>(buf);
}

bool
WindowsSandboxLauncher::Launch(const std::wstring_view aExecutablePath,
                               const std::wstring_view aBaseCmdLine)
{
  auto absExePath = CreateAbsolutePath(aExecutablePath);
  if (!absExePath) {
    return false;
  }

  // customSid guards against the SetThreadDesktop() security hole
  mozilla::Sid customSid;
  if (!customSid.InitCustom()) {
    return false;
  }

  mozilla::Sid logonSid;
  UniqueKernelHandle restrictedToken;
  UniqueKernelHandle impersonationToken;
  if (!CreateTokens(customSid, restrictedToken, impersonationToken, logonSid)) {
    return false;
  }

  if (!(mInitFlags & eInitNoSeparateWindowStation)) {
    mWinsta = CreateWindowStation();
    if (!mWinsta) {
      return false;
    }
  }

  mDesktop = CreateDesktop(mWinsta, customSid);
  if (!mDesktop) {
    return false;
  }

  UniqueKernelHandle job;
  if (!CreateJob(job)) {
    return false;
  }

  // 5. Build the command line string
  wostringstream oss;
  oss << absExePath.value();
  oss << L" "sv;
  oss << aBaseCmdLine;
  oss << L" "sv;
  oss << WindowsSandbox::SWITCH_JOB_HANDLE;
  oss << L" "sv;
  oss << hex << job.get();

  // 6. Set the working directory. With low integrity levels on Vista most
  //    directories are inaccessible.
  auto workingDir = GetWorkingDirectory(restrictedToken);
  if (!workingDir) {
    return false;
  }

  // 7. Initialize the explicit list of handles to inherit (Vista+).
  bool result = false;
  DECLARE_UNIQUE_LEN(LPPROC_THREAD_ATTRIBUTE_LIST, attrList);
  std::unique_ptr<HANDLE[]> inheritableHandles;
  SIZE_T attrListSize = 0;

  /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST and
   * PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
   */
  const DWORD attrCount = 2;
  if (!::InitializeProcThreadAttributeList(nullptr, attrCount, 0,
                                           &attrListSize) &&
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return false;
  }

  ALLOC_UNIQUE_LEN(attrList, attrListSize);
  if (!::InitializeProcThreadAttributeList(attrList, attrCount, 0,
                                           &attrListSize)) {
    return false;
  }

  UniqueProcAttributeList listDeleter(attrList);
  size_t handleCount = mHandlesToInherit.size();
  inheritableHandles = std::make_unique<HANDLE[]>(handleCount + 2);
  memcpy(inheritableHandles.get(), &mHandlesToInherit[0],
         handleCount * sizeof(HANDLE));
  inheritableHandles[handleCount++] = impersonationToken.get();
  inheritableHandles[handleCount++] = job.get();
  result = !!::UpdateProcThreadAttribute(attrList, 0,
                                         PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                         inheritableHandles.get(),
                                         handleCount * sizeof(HANDLE), nullptr,
                                         nullptr);
  if (!result) {
    return false;
  }

  result = !!::UpdateProcThreadAttribute(attrList, 0,
                                         PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                         &mMitigationPolicies,
                                         sizeof(DWORD64), nullptr, nullptr);
  if (!result) {
    return false;
  }

  // 8. Create the process using the restricted token
  std::wstring desktop;
  if (mWinsta) {
    auto winstaName = GetWindowStationName(mWinsta);
    if (!winstaName) {
      return false;
    }
    desktop = winstaName.value();
    desktop += L"\\"sv;
  }
  desktop += WindowsSandbox::DESKTOP_NAME;

  STARTUPINFOEX siex = {};
  siex.StartupInfo.lpDesktop = (LPWSTR)desktop.c_str();

  DWORD creationFlags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
  siex.StartupInfo.cb = sizeof(STARTUPINFOEX);
  siex.lpAttributeList = attrList;

  if (!mHasWin8APIs) {
    // Job objects don't nest until Windows 8. To create a process that is to be
    // part of a job, we need to create it as a "breakaway" process.
    creationFlags |= CREATE_BREAKAWAY_FROM_JOB;
  }

  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, FALSE};

  PROCESS_INFORMATION procInfo;
  result = !!::CreateProcessAsUser(restrictedToken.get(), absExePath.value().c_str(),
                                   const_cast<wchar_t*>(oss.str().c_str()), &sa,
                                   &sa, TRUE, creationFlags, L"", workingDir.value().c_str(),
                                   &siex.StartupInfo, &procInfo);

  UniqueKernelHandle childProcess(procInfo.hProcess);
  UniqueKernelHandle mainThread(procInfo.hThread);
  if (!result) {
    return false;
  }

  if (!::SetThreadToken(&procInfo.hThread, impersonationToken.get())) {
    ::TerminateProcess(procInfo.hProcess, 1);
    return false;
  }

  if (!PreResume()) {
    ::TerminateProcess(procInfo.hProcess, 1);
    return false;
  }

  if (::ResumeThread(mainThread.get()) == static_cast<DWORD>(-1)) {
    ::TerminateProcess(procInfo.hProcess, 1);
    return false;
  }

  mProcess = childProcess.release();
  return true;
}

bool
WindowsSandboxLauncher::BuildInheritableSecurityDescriptor(const Sid& aLogonSid)
{
  mInheritableDacl.Clear();
  mInheritableDacl.AddAllowedAce(mozilla::Sid::GetLocalSystem(), GENERIC_ALL);
  mInheritableDacl.AddAllowedAce(mozilla::Sid::GetAdministrators(), GENERIC_ALL);
  mInheritableDacl.AddAllowedAce(aLogonSid, GENERIC_ALL);

  if (!::InitializeSecurityDescriptor(&mInheritableSd,
                                      SECURITY_DESCRIPTOR_REVISION)) {
    mInheritableDacl.Clear();
    return false;
  }

  PACL pacl = (PACL) mInheritableDacl;
  if (!pacl) {
    mInheritableDacl.Clear();
    return false;
  }

  if (!::SetSecurityDescriptorDacl(&mInheritableSd, TRUE, pacl, FALSE)) {
    mInheritableDacl.Clear();
    return false;
  }

  return true;
}

bool
WindowsSandboxLauncher::GetInheritableSecurityDescriptor(SECURITY_ATTRIBUTES &aSa,
                                                         const BOOL aInheritable)
{
  PACL pacl = (PACL) mInheritableDacl;
  if (!pacl) {
    return false;
  }

  aSa = {sizeof(aSa), &mInheritableSd, aInheritable};
  return true;
}

} // namespace mozilla

