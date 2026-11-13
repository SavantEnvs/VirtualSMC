#ifndef VSMC_SHIM_PIO_H
#define VSMC_SHIM_PIO_H
#include <stdint.h>

// Deterministic fake RTC: index/target pair returns a function of the selected register.
inline uint8_t &shim_rtc_index() { static uint8_t idx; return idx; }
static inline void outb(uint16_t port, uint8_t value) { if (port == 0x70) shim_rtc_index() = value; }
static inline uint8_t inb(uint16_t port) { return port == 0x71 ? static_cast<uint8_t>(shim_rtc_index() * 0x11 & 0x59) : 0; }
#endif
