#pragma once
#include <stdint.h>

// Deterministic clock: each query advances a counter that the harness resets per input.
inline uint64_t &shim_clock_ns() { static uint64_t now; return now; }

inline uint64_t getCurrentTimeNs() {
	shim_clock_ns() += 250000000ULL;
	return shim_clock_ns();
}

inline uint64_t getTimeSinceNs(uint64_t start, uint64_t current = 0) {
	if (current == 0) current = getCurrentTimeNs();
	return current > start ? current - start : 0;
}

inline uint64_t getTimeLeftNs(uint64_t start, uint64_t timeout, uint64_t current = 0) {
	if (current == 0) current = getCurrentTimeNs();
	uint64_t spent = current > start ? current - start : 0;
	return spent < timeout ? timeout - spent : 0;
}

constexpr uint64_t convertNsToMs(uint64_t t) { return t / 1000000ULL; }
constexpr uint64_t convertNsToSc(uint64_t t) { return t / 1000000000ULL; }
constexpr uint64_t convertMsToSc(uint64_t t) { return t / 1000ULL; }
constexpr uint64_t convertMsToNs(uint64_t t) { return t * 1000000ULL; }
constexpr uint64_t convertScToNs(uint64_t t) { return t * 1000000000ULL; }
constexpr uint64_t convertScToMs(uint64_t t) { return t * 1000ULL; }
