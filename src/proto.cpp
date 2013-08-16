/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdlib>
#include <iostream>
#include <cstring>
#include <sstream>
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>

#include "dacl.h"
#include "sid.h"

using std::wcout;
using std::endl;
using std::flush;
using std::wostringstream;
using std::wistringstream;
using std::hex;

const wchar_t CMD_OPT_SANDBOXED[] = L"--sandboxed";
wchar_t DESKTOP_NAME[] = L"moz-sandbox";

class WindowsSandbox
{
public:
  WindowsSandbox() {}
  virtual ~WindowsSandbox() {}

  bool Init(HANDLE aPrivilegedToken, HANDLE aJob);
  void Fini();

protected:
  virtual bool OnPrivInit() = 0;
  virtual bool OnInit() = 0;
  virtual void OnFini() = 0;

private:
};

bool
WindowsSandbox::Init(HANDLE aPrivilegedToken, HANDLE aJob)
{
  if (!aPrivilegedToken) {
    return false;
  }
  if (!::ImpersonateLoggedOnUser(aPrivilegedToken)) {
    return false;
  }
  bool ok = OnPrivInit();
  ok = ::RevertToSelf() && ok;
  ::CloseHandle(aPrivilegedToken);
  ok = ::AssignProcessToJobObject(aJob, ::GetCurrentProcess()) && ok;
  ::CloseHandle(aJob);
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

class PrototypeSandbox : public WindowsSandbox
{
public:
  explicit PrototypeSandbox(const wchar_t *aLibPath)
    :mLibPath(aLibPath)
  {}
  virtual ~PrototypeSandbox() {}

protected:
  virtual bool OnPrivInit() { return true; }
  virtual bool OnInit() { return true; }
  virtual void OnFini() {}
private:
  const wchar_t* mLibPath;
};

PTOKEN_GROUPS CreateSidsToDisable(HANDLE aToken, std::vector<SID_AND_ATTRIBUTES>& aOut, mozilla::Sid& aLogonSid)
{
  aOut.clear();
  if (!aToken || aLogonSid.IsValid()) {
    return nullptr;
  }
  // Get size
  DWORD reqdLen = 0;
  if (!::GetTokenInformation(aToken, TokenGroups, nullptr, 0, &reqdLen) &&
      ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return nullptr;
  }
  PTOKEN_GROUPS tokenGroups = (PTOKEN_GROUPS)::calloc(reqdLen, 1);
  if (!::GetTokenInformation(aToken, TokenGroups, tokenGroups, reqdLen,
                             &reqdLen)) {
    ::free(tokenGroups);
    return nullptr;
  }
  for (DWORD i = 0; i < tokenGroups->GroupCount; ++i) {
    wchar_t nameBuf[256] = {0};
    wchar_t domain[256] = {0};
    DWORD nameBufLen = sizeof(nameBuf)/sizeof(wchar_t);
    DWORD domainLen = sizeof(domain)/sizeof(wchar_t);
    SID_NAME_USE type = SidTypeUnknown;
    ::LookupAccountSid(nullptr, tokenGroups->Groups[i].Sid, nameBuf, &nameBufLen, domain, &domainLen, &type);
    if (tokenGroups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
      aLogonSid.Init(tokenGroups->Groups[i].Sid);
      LPTSTR strSid = nullptr;
      ConvertSidToStringSid(tokenGroups->Groups[i].Sid, &strSid);
      wcout << "Omitting \"" << strSid << "\" (Logon ID SID)" << endl;
      LocalFree(strSid);
      continue;
    }
    if (mozilla::Sid::GetEveryone() == tokenGroups->Groups[i].Sid ||
        mozilla::Sid::GetUsers() == tokenGroups->Groups[i].Sid) {
      wcout << "Omitting \"" << nameBuf << "\"" << endl;
      continue;
    }
    wcout << "Keeping \"" << nameBuf << "\"" << endl;
    aOut.push_back(tokenGroups->Groups[i]);
  }
  return tokenGroups;
}

bool CreateSandboxedProcess(wchar_t* aExecutablePath, wchar_t* aLibraryPath)
{
  HANDLE processToken = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                        &processToken)) {
    return false;
  }
  // Disable: Want to disable everything but logon ID SID, everyone, and BUILTIN\Users
  // Restrict: Want to have everyone, users, restricted, and logon id SID
  mozilla::Sid logonSid;
  std::vector<SID_AND_ATTRIBUTES> toDisable;
  PTOKEN_GROUPS tokenGroups = CreateSidsToDisable(processToken, toDisable,
                                                  logonSid);
  if (!tokenGroups) {
    CloseHandle(processToken);
    return false;
  }
  // customSid guards against the SetThreadDesktop() security hole
  mozilla::Sid customSid;
  if (!customSid.InitCustom()) {
    return false;
  }
  SID_AND_ATTRIBUTES toRestrict[] = {{mozilla::Sid::GetEveryone()},
                                     {mozilla::Sid::GetUsers()},
                                     {mozilla::Sid::GetRestricted()},
                                     {logonSid},
                                     {customSid}};
  HANDLE restrictedToken = NULL;
  bool result = !!CreateRestrictedToken(processToken, DISABLE_MAX_PRIVILEGE,
                                        toDisable.size(), &toDisable[0], 0,
                                        nullptr, sizeof(toRestrict)
                                          / sizeof(SID_AND_ATTRIBUTES),
                                        toRestrict, &restrictedToken);
  free(tokenGroups); tokenGroups = nullptr;
  if (!result) {
    CloseHandle(processToken);
    return false;
  }
  SECURITY_ATTRIBUTES saInheritable = {sizeof(saInheritable), nullptr, TRUE};
  HANDLE impersonationToken = NULL;
  result = !!DuplicateTokenEx(processToken, TOKEN_IMPERSONATE | TOKEN_QUERY,
                              &saInheritable, SecurityImpersonation,
                              TokenImpersonation, &impersonationToken);
  CloseHandle(processToken);
  if (!result) {
    return false;
  }
  // Now define an appropriate default DACL for the token and call SetTokenInformation to set it.
  // Make the ACL system, admins, logon ID allow full control
  mozilla::Dacl dacl;
  dacl.AddAllowedAce(mozilla::Sid::GetLocalSystem(), GENERIC_ALL);
  dacl.AddAllowedAce(mozilla::Sid::GetAdministrators(), GENERIC_ALL);
  dacl.AddAllowedAce(logonSid, GENERIC_ALL);
  TOKEN_DEFAULT_DACL tokenDacl;
  ZeroMemory(&tokenDacl, sizeof(tokenDacl));
  tokenDacl.DefaultDacl = (PACL)dacl;
  if (!SetTokenInformation(restrictedToken, TokenDefaultDacl, &tokenDacl,
                           sizeof(tokenDacl))) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  TOKEN_MANDATORY_LABEL il;
  ZeroMemory(&il, sizeof(il));
  il.Label.Sid = mozilla::Sid::GetIntegrityLow();
  if (!SetTokenInformation(restrictedToken, TokenIntegrityLevel, &il, 
                           sizeof(il))) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  HDESK curDesktop = GetThreadDesktop(GetCurrentThreadId());
  if (!curDesktop) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  SECURITY_INFORMATION curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  // TODO ASK: If Vista+
  curDesktopSecInfo |= LABEL_SECURITY_INFORMATION;
  PSECURITY_DESCRIPTOR curDesktopSd = nullptr;
  DWORD curDesktopSdSize = 0;
  if (!GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, curDesktopSd,
                             curDesktopSdSize, &curDesktopSdSize) &&
                             GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  curDesktopSd = (PSECURITY_DESCRIPTOR) calloc(curDesktopSdSize, 1);
  if (!GetUserObjectSecurity(curDesktop, &curDesktopSecInfo, curDesktopSd,
        curDesktopSdSize, &curDesktopSdSize)) {
    free(curDesktopSd);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  // Convert from self-relative to absolute
  DWORD curDesktopDaclSize = 0;
  DWORD curDesktopSaclSize = 0;
  DWORD curDesktopOwnerSize = 0;
  DWORD curDesktopPrimaryGroupSize = 0;
  if(!MakeAbsoluteSD(curDesktopSd, nullptr, &curDesktopSdSize,
                     nullptr, &curDesktopDaclSize, nullptr,
                     &curDesktopSaclSize, nullptr, &curDesktopOwnerSize,
                     nullptr, &curDesktopPrimaryGroupSize) &&
     GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    free(curDesktopSd);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  PSECURITY_DESCRIPTOR newDesktopSd = (PSECURITY_DESCRIPTOR) calloc(curDesktopSdSize, 1);
  PACL curDesktopDacl = (PACL) calloc(curDesktopDaclSize, 1);
  PACL curDesktopSacl = (PACL) calloc(curDesktopSaclSize, 1);
  PSID curDesktopOwner = (PSID) calloc(curDesktopOwnerSize, 1);
  PSID curDesktopPrimaryGroup = (PSID) calloc(curDesktopPrimaryGroupSize, 1);
  result = !!MakeAbsoluteSD(curDesktopSd, newDesktopSd, &curDesktopSdSize,
                            curDesktopDacl, &curDesktopDaclSize, curDesktopSacl,
                            &curDesktopSaclSize, curDesktopOwner,
                            &curDesktopOwnerSize, curDesktopPrimaryGroup,
                            &curDesktopPrimaryGroupSize);
  if (!result) {
    free(curDesktopSd);
    free(curDesktopDacl);
    free(curDesktopSacl);
    free(curDesktopOwner);
    free(curDesktopPrimaryGroup);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  mozilla::Dacl newDesktopDacl;
  newDesktopDacl.AddDeniedAce(customSid, GENERIC_ALL);
  result = newDesktopDacl.Merge(curDesktopDacl);
  free(curDesktopDacl); curDesktopDacl = nullptr;
  if (!result) {
    free(curDesktopSd);
    free(curDesktopSacl);
    free(curDesktopOwner);
    free(curDesktopPrimaryGroup);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  if (!SetSecurityDescriptorDacl(newDesktopSd, TRUE, newDesktopDacl, FALSE)) {
    free(curDesktopSd);
    free(curDesktopSacl);
    free(curDesktopOwner);
    free(curDesktopPrimaryGroup);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  curDesktopSecInfo = DACL_SECURITY_INFORMATION;
  result = !!SetUserObjectSecurity(curDesktop, &curDesktopSecInfo,
                                   newDesktopSd);
  free(curDesktopSacl); curDesktopSacl = nullptr;
  free(curDesktopOwner); curDesktopOwner = nullptr;
  free(curDesktopPrimaryGroup); curDesktopPrimaryGroup = nullptr;
  if (!result) {
    free(curDesktopSd);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  // A default security descriptor won't cut it for the new desktop; it must
  // be adjusted to permit low integrity
  SECURITY_ATTRIBUTES newDesktopSa = {sizeof(newDesktopSa), curDesktopSd, FALSE};
  // TODO ASK: We shouldn't have 1:1 desktop-to-sandbox ratio (they eat memory)
  HDESK desktop = CreateDesktop(DESKTOP_NAME, nullptr, nullptr, 0,
                                DESKTOP_CREATEWINDOW /* required */,
                                &newDesktopSa);
  free(curDesktopSd); curDesktopSd = nullptr;
  if (!desktop) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  SECURITY_ATTRIBUTES jobSa = {sizeof(jobSa), nullptr, TRUE};
  HANDLE job = CreateJobObject(&jobSa, nullptr);
  if (!job) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimits;
  ZeroMemory(&basicLimits, sizeof(basicLimits));
  // Block CreateProcess
  basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  basicLimits.ActiveProcessLimit = 1;
  if (!SetInformationJobObject(job, JobObjectBasicLimitInformation, &basicLimits,
                               sizeof(basicLimits))) {
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  JOBOBJECT_BASIC_UI_RESTRICTIONS uiLimits;
  ZeroMemory(&uiLimits, sizeof(uiLimits));
  // To explicitly grant user handles, call UserHandleGrantAccess
  uiLimits.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP |
                                 JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                                 JOB_OBJECT_UILIMIT_EXITWINDOWS |
                                 JOB_OBJECT_UILIMIT_GLOBALATOMS | 
                                 JOB_OBJECT_UILIMIT_HANDLES |
                                 JOB_OBJECT_UILIMIT_READCLIPBOARD |
                                 JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
                                 JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
  if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &uiLimits,
                               sizeof(uiLimits))) {
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  wostringstream oss;
  oss << aExecutablePath;
  oss << L" ";
  oss << CMD_OPT_SANDBOXED;
  oss << L" ";
  oss << aLibraryPath;
  oss << L" ";
  oss << hex << impersonationToken;
  oss << L" ";
  oss << hex << job;
  /*
  wchar_t workingDir[MAX_PATH + 1] = {0};
  if (!GetTempPath(sizeof(workingDir)/sizeof(workingDir[0]), workingDir)) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  */
  // NOTE: SHGetKnownFolderPath is Vista-specific
  PWSTR workingDir = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0,
                                  restrictedToken, &workingDir))) {
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, FALSE};
  SIZE_T attrListSize = 0;
  if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize) &&
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    CoTaskMemFree(workingDir);
    return false;
  }
  LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(attrListSize, 1);
  if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
    free(attrList);
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    CoTaskMemFree(workingDir);
    return false;
  }
  HANDLE inheritableHandles[] = {impersonationToken, job};
  if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 inheritableHandles, sizeof(inheritableHandles),
                                 nullptr, nullptr)) {
    free(attrList);
    CloseHandle(job);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    CoTaskMemFree(workingDir);
    return false;
  }
  STARTUPINFOEX siex;
  ZeroMemory(&siex, sizeof(siex));
  siex.StartupInfo.cb = sizeof(STARTUPINFOEX);
  siex.StartupInfo.lpDesktop = DESKTOP_NAME;
  siex.lpAttributeList = attrList;
  DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT;
  // TODO ASK: If less than Windows 8
  creationFlags |= CREATE_BREAKAWAY_FROM_JOB;
  PROCESS_INFORMATION procInfo;
  result = !!CreateProcessAsUser(restrictedToken, aExecutablePath,
                                 const_cast<wchar_t*>(oss.str().c_str()), &sa,
                                 &sa, TRUE, creationFlags, L"", workingDir,
                                 &siex.StartupInfo, &procInfo);
  DeleteProcThreadAttributeList(attrList);
  free(attrList);
  CloseHandle(impersonationToken);
  CloseHandle(restrictedToken);
  CoTaskMemFree(workingDir);
  if (result) {
    CloseHandle(procInfo.hThread);
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    CloseHandle(procInfo.hProcess);
  }
  CloseHandle(job);
  return result;
}

int wmain(int argc, wchar_t* argv[])
{
  if (argc == 5 && !wcsicmp(argv[1], CMD_OPT_SANDBOXED)) {
    HANDLE privToken = NULL, job = NULL;
    {
      wistringstream iss(argv[3]);
      iss >> privToken;
      if (!iss) {
        return false;
      }
    }
    {
      wistringstream iss(argv[4]);
      iss >> job;
      if (!iss) {
        return false;
      }
    }
    PrototypeSandbox sb(argv[2]);
    if (!sb.Init(privToken, job)) {
      return EXIT_FAILURE;
    }
  } else if (argc == 2) {
    if (!CreateSandboxedProcess(argv[0], argv[1])) {
      return EXIT_FAILURE;
    }
  } else {
    wcout << L"Usage: " << argv[0] << " <path_to_dll>" << endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

