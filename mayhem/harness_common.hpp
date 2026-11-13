#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Cursor over the fuzz input; reads past the end yield zeros so every input decodes the same way.
struct Reader {
	const uint8_t *p;
	size_t n;

	Reader(const uint8_t *data, size_t size) : p(data), n(size) {}

	bool empty() const { return n == 0; }

	uint8_t u8() {
		if (!n) return 0;
		n--;
		return *p++;
	}

	uint16_t u16() {
		uint16_t v = u8();
		return static_cast<uint16_t>(v | (static_cast<uint16_t>(u8()) << 8));
	}

	uint32_t u32() {
		uint32_t v = u16();
		return v | (static_cast<uint32_t>(u16()) << 16);
	}

	uint64_t u64() {
		uint64_t v = u32();
		return v | (static_cast<uint64_t>(u32()) << 32);
	}

	void bytes(uint8_t *dst, size_t len) {
		for (size_t i = 0; i < len; i++) dst[i] = u8();
	}
};
