#ifndef __ASPK_MAKEUNIQUELEN_H
#define __ASPK_MAKEUNIQUELEN_H

#include <memory>
#include <type_traits>

#define DECLARE_UNIQUE_LEN(type, name) \
  std::unique_ptr<unsigned char[]> name##Bytes; \
  type name = nullptr
#define ALLOC_UNIQUE_LEN(name, numBytes) \
  name##Bytes = std::make_unique<unsigned char[]>(numBytes); \
  name = reinterpret_cast<decltype(name)>(name##Bytes.get())
#define MAKE_UNIQUE_LEN(type, name, numBytes) \
  auto name##Bytes(std::make_unique<unsigned char[]>(numBytes)); \
  auto name = reinterpret_cast<type>(name##Bytes.get())

#endif // __ASPK_MAKEUNIQUELEN_H

