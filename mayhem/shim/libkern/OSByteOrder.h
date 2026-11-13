#ifndef VSMC_SHIM_OSBYTEORDER_H
#define VSMC_SHIM_OSBYTEORDER_H
#include <stdint.h>

static inline uint16_t OSSwapInt16(uint16_t v) { return __builtin_bswap16(v); }
static inline uint32_t OSSwapInt32(uint32_t v) { return __builtin_bswap32(v); }
static inline uint64_t OSSwapInt64(uint64_t v) { return __builtin_bswap64(v); }
#define OSSwapHostToBigInt16(x) OSSwapInt16(x)
#define OSSwapHostToBigInt32(x) OSSwapInt32(x)
#define OSSwapHostToBigInt64(x) OSSwapInt64(x)
#define OSSwapBigToHostInt16(x) OSSwapInt16(x)
#define OSSwapBigToHostInt32(x) OSSwapInt32(x)
#define OSSwapBigToHostInt64(x) OSSwapInt64(x)
#endif
