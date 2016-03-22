/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_comarshal_h
#define mozilla_comarshal_h

// #include "ipc/IPCMessageUtils.h"

#if defined(MOZILLA_INTERNAL_API)
#include "mozilla/UniquePtr.h"
#else
#include <memory>
#endif

// For smart pointer and associated macros
#include <comdef.h>

#if !defined(__IPC_GLUE_IPCMESSAGEUTILS_H__)
namespace IPC {
template <typename T>
struct ParamTraits;
} // namespace IPC
#endif

namespace mozilla {

_COM_SMARTPTR_TYPEDEF(IStream, __uuidof(IStream));

class ProxyStream
{
public:
  ProxyStream(REFIID aIID, IUnknown* aObject);
  ProxyStream(const BYTE* aInitBuf, const int aInitBufSize);

  ~ProxyStream();

  // Not copyable because this can mess up COM marshaling. If we wanted this
  // to be copyable, we could call ::CoMarshalInterface() with the
  // MSHLFLAGS_TABLESTRONG flag, but it's more work to track references.
  ProxyStream(const ProxyStream& aOther) = delete;
  ProxyStream& operator=(const ProxyStream& aOther) = delete;

  ProxyStream(ProxyStream&& aOther);
  ProxyStream& operator=(ProxyStream&& aOther);

  inline bool IsValid() const { return !!mStream; }

  bool GetInterface(REFIID aIID, void** aOutInterface);

private:
  IStream* Init(const BYTE* aInitBuf, const UINT aInitBufSize);

  // GetBuffer should not be called outside of IPDL serializer
  friend struct IPC::ParamTraits<mozilla::ProxyStream>;
#if !defined(MOZILLA_INTERNAL_API)
public:
#endif
  const char* GetBuffer(int& aReturnedBufSize) const;

private:
  // TODO: s/std::unique_ptr/mozilla::UniquePtr/
  typedef std::unique_ptr<void, decltype(&::GlobalUnlock)> GlobalLockedPtr;

private:
  IStreamPtr      mStream;
  GlobalLockedPtr mGlobalLockedBuf;
  int             mBufSize;
};

} // namespace mozilla

#if defined(__IPC_GLUE_IPCMESSAGEUTILS_H__)

namespace IPC {

template<>
struct ParamTraits<mozilla::ProxyStream>
{
  typedef mozilla::ProxyStream paramType;

  static void Write(Message* aMsg, const paramType& aParam)
  {
    int bufLen;
    const PBYTE buf = aParam.GetBuffer(bufLen);
    MOZ_ASSERT(buf);
    aMsg->WriteData(reinterpret_cast<const char*>(buf), bufLen);
  }

  static bool Read(const Message* aMsg, void** aIter, paramType* aResult)
  {
    int length;
    const char* buf;
    if (!aMsg->ReadData(aIter, &buf, &length)) {
      return false;
    }
    *aResult = paramType(reinterpret_cast<const PBYTE>(buf), length);
    return true;
  }
};

} // namespace IPC

#endif // defined(__IPC_GLUE_IPCMESSAGEUTILS_H__)

#endif // mozilla_comarshal_h
