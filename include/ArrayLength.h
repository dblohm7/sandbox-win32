#ifndef __ARRAYLENGTH_H
#define __ARRAYLENGTH_H

template<typename T, size_t N>
inline /* constexpr */ size_t ArrayLength(T (&)[N])
{
  return N;
}

#endif // __ARRAYLENGTH_H

