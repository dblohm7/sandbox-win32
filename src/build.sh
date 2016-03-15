#!/bin/bash

# Defaults
INIT_FUNCTION_NAME=INITIALIZE_CDM_MODULE
DEINIT_FUNCTION_NAME=DeinitializeCdmModule

# Overridable via command line
if [ $# -eq 2 ]; then
  INIT_FUNCTION_NAME=$1
  DEINIT_FUNCTION_NAME=$2
fi

cl -Zi -EHsc -MD -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE -DINIT_FUNCTION_NAME=\"$INIT_FUNCTION_NAME\" -DDEINIT_FUNCTION_NAME=\"$DEINIT_FUNCTION_NAME\" proto.cpp dacl.cpp sid.cpp sidattrs.cpp WindowsSandbox.cpp advapi32.lib user32.lib rpcrt4.lib ole32.lib shlwapi.lib
mt -manifest sandbox-win32.manifest -outputresource:proto.exe;#1

cl -Zi -EHsc -MD -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE comtest.cpp dacl.cpp sid.cpp sidattrs.cpp WindowsSandbox.cpp advapi32.lib user32.lib rpcrt4.lib ole32.lib shlwapi.lib
mt -manifest sandbox-win32.manifest -outputresource:comtest.exe;#1
