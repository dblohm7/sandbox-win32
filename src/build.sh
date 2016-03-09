#!/bin/bash
if [ $# -ne 2 ]; then
  echo "Must provide INIT_FUNCTION_NAME and DEINIT_FUNCTION_NAME"
  exit 1
fi
cl -Zi -EHsc -MD -DUNICODE -D_UNICODE -DINIT_FUNCTION_NAME=\"$1\" -DDEINIT_FUNCTION_NAME=\"$2\" -I 'C:\Users\aklotz\Downloads\loki\loki-0.1.7\include' proto.cpp dacl.cpp sid.cpp sidattrs.cpp WindowsSandbox.cpp advapi32.lib user32.lib rpcrt4.lib ole32.lib
