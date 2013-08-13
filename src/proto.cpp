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

bool InitSandbox(wchar_t* aLibraryPath, wchar_t* aPrivToken)
{
  wistringstream iss(aPrivToken);
  HANDLE privToken = NULL;
  iss >> privToken;
  if (!iss) {
    return false;
  }
  if (!ImpersonateLoggedOnUser(privToken)) {
    return false;
  }
  return true;
}

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
  SID_AND_ATTRIBUTES toRestrict[] = {{mozilla::Sid::GetEveryone()},
                                     {mozilla::Sid::GetUsers()},
                                     {mozilla::Sid::GetRestricted()},
                                     {logonSid}};
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
  tokenDacl.DefaultDacl = (PACL)dacl;
  if (!SetTokenInformation(restrictedToken, TokenDefaultDacl, &tokenDacl,
                           sizeof(tokenDacl))) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  // TODO ASK: We shouldn't have 1:1 desktop-to-sandbox ratio (they eat memory)
  HDESK desktop = CreateDesktop(DESKTOP_NAME, nullptr, nullptr, 0, DESKTOP_CREATEWINDOW /* required */, /* TODO: Security descriptor? */ nullptr);
  if (!desktop) {
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
  wchar_t tmpPath[MAX_PATH + 1] = {0};
  if (!GetTempPath(sizeof(tmpPath)/sizeof(tmpPath[0]), tmpPath)) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, FALSE};
  SIZE_T attrListSize = 0;
  if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize) &&
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(attrListSize, 1);
  if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
    free(attrList);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                 &impersonationToken, sizeof(HANDLE), nullptr,
                                 nullptr)) {
    free(attrList);
    CloseHandle(restrictedToken);
    CloseHandle(impersonationToken);
    return false;
  }
  // TODO ASK: Low integrity
  STARTUPINFOEX siex;
  ZeroMemory(&siex, sizeof(siex));
  siex.StartupInfo.cb = sizeof(STARTUPINFOEX);
  siex.StartupInfo.lpDesktop = DESKTOP_NAME;
  siex.lpAttributeList = attrList;
  PROCESS_INFORMATION procInfo;
  result = !!CreateProcessAsUser(restrictedToken, aExecutablePath,
                                 const_cast<wchar_t*>(oss.str().c_str()), &sa,
                                 &sa, TRUE, EXTENDED_STARTUPINFO_PRESENT, L"",
                                 tmpPath, &siex.StartupInfo, &procInfo);
  DeleteProcThreadAttributeList(attrList);
  free(attrList);
  CloseHandle(impersonationToken);
  CloseHandle(restrictedToken);
  if (result) {
    CloseHandle(procInfo.hThread);
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    CloseHandle(procInfo.hProcess);
  }
  return result;
}

int wmain(int argc, wchar_t* argv[])
{
  if (argc == 4 && !wcsicmp(argv[1], CMD_OPT_SANDBOXED)) {
    if (!InitSandbox(argv[2], argv[3])) {
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

