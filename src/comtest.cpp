/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdlib>
#include <iostream>

#include <windows.h>
#include <objbase.h>
#include <sddl.h>

#include "dacl.h"
#include "sid.h"
#include "WindowsSandbox.h"

using std::wcout;
using std::wcerr;
using std::endl;
using mozilla::WindowsSandboxLauncher;

namespace {

class COMTestSandbox : public mozilla::WindowsSandbox
{
public:
  explicit COMTestSandbox()
  {}
  virtual ~COMTestSandbox()
  {
    Fini();
  }

protected:
  virtual bool OnPrivInit();
  virtual bool OnInit();
  virtual void OnFini();

private:
};

bool
COMTestSandbox::OnPrivInit()
{
  return true;
}

bool
COMTestSandbox::OnInit()
{
  if (FAILED(::CoInitializeEx(nullptr, COINIT_MULTITHREADED))) {
    return false;
  }
  return true;
}

void
COMTestSandbox::OnFini()
{
  ::CoUninitialize();
}

}

int wmain(int argc, wchar_t* argv[])
{
  if (argc == 1) {
    WindowsSandboxLauncher sboxLauncher;
    sboxLauncher.Init();
    if (!sboxLauncher.Launch(argv[0], L"")) {
      wcerr << L"Failed to launch" << endl;
      return EXIT_FAILURE;
    }
    if (!sboxLauncher.Wait(INFINITE)) {
      return EXIT_FAILURE;
    }
  }

  COMTestSandbox sb;
  if (!sb.Init(argc, argv)) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

