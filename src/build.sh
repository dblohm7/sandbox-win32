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

# Change to -x64 for win64
midl -win32 -env win32 -Oicf Test.idl
# NOTE: Need to #define WIN32 for 32-bit COM stuff... not sure why it uses that
cl -Zi -EHsc -MD -LD -DWIN32 -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE -DREGISTER_PROXY_DLL Test_i.c Test_p.c dlldata.c rpcrt4.lib -FeITest.dll -link -def:itest.def
regsvr32 -s ITest.dll
cl -Zi -EHsc -MD -D_WIN32_WINNT=0x0A00 -DUNICODE -D_UNICODE comtest.cpp dacl.cpp sid.cpp sidattrs.cpp WindowsSandbox.cpp advapi32.lib user32.lib rpcrt4.lib ole32.lib shlwapi.lib
mt -manifest sandbox-win32.manifest -outputresource:comtest.exe;#1
