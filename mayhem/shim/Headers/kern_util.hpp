// Subset of Lilu's kern_util.hpp, re-implemented for user space.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <type_traits>
#include <libkern/OSByteOrder.h>
#include "../shim_os.hpp"

#define EXPORT __attribute__((visibility("default")))
#define PACKED __attribute__((packed))

#define ADDPR(a) shim_##a
inline constexpr bool shim_debugEnabled = false;

inline void shim_log(const char *, ...) {}
#define SYSLOG_COND(cond, module, str, ...) do { if (0 && (cond)) shim_log(str, ## __VA_ARGS__); } while (0)
#define SYSLOG(module, str, ...) do { if (0) shim_log(str, ## __VA_ARGS__); } while (0)
#define DBGLOG(module, str, ...) do { if (0) shim_log(str, ## __VA_ARGS__); } while (0)
// A kernel panic: the process dies the same way.
#define PANIC(module, str, ...) do { abort(); } while (0)

#define lilu_os_memcpy memcpy
#define lilu_os_memmove memmove
#define kern_os_realloc(ptr, size) realloc(ptr, size)
#define kern_os_free(ptr) free(ptr)

template <typename T, size_t N>
constexpr size_t arrsize(const T (&)[N]) {
	return N;
}

template <typename T>
constexpr T getBit(T n) {
	return static_cast<T>(1U) << n;
}

template <typename T, typename Y>
inline bool findNotEquals(T &in, size_t size, Y value) {
	for (size_t i = 0; i < size; i++)
		if (in[i] != value)
			return true;
	return false;
}

namespace Buffer {
	template <typename T>
	inline T *create(size_t size) {
		return static_cast<T *>(calloc(size, sizeof(T)));
	}
}

template <typename T>
inline void emptyDeleter(T) {}

template <typename T, typename P, void (*deleter)(P) = emptyDeleter<P>>
class evector_base {
	T *ptr {nullptr};
	size_t cnt {0};
	size_t rsvd {0};
public:
	size_t size() const { return cnt; }
	T *data() const { return ptr; }
	size_t last() const { return cnt - 1; }
	T &operator [](size_t index) { return ptr[index]; }
	const T &operator [](size_t index) const { return ptr[index]; }

	template <size_t MUL = 1>
	T *reserve(size_t num) {
		if (rsvd < num) {
			T *nPtr = static_cast<T *>(kern_os_realloc(ptr, MUL * num * sizeof(T)));
			if (!nPtr) return nullptr;
			ptr = nPtr;
			rsvd = MUL * num;
		}
		return ptr;
	}

	void erase(size_t index, bool release = true) {
		deleter(ptr[index]);
		if (--cnt != index)
			lilu_os_memmove(&ptr[index], &ptr[index + 1], (cnt - index) * sizeof(T));
		if (release && cnt == 0) {
			kern_os_free(ptr);
			ptr = nullptr;
			rsvd = 0;
		}
	}

	template <size_t MUL = 1>
	bool push_back(T &element) {
		if (reserve<MUL>(cnt + 1)) {
			ptr[cnt] = element;
			cnt++;
			return true;
		}
		return false;
	}

	template <size_t MUL = 1>
	bool push_back(T &&element) {
		if (reserve<MUL>(cnt + 1)) {
			ptr[cnt] = element;
			cnt++;
			return true;
		}
		return false;
	}

	evector_base() = default;
	evector_base(const evector_base &) = delete;
	evector_base operator =(const evector_base &) = delete;

	void deinit() {
		if (ptr) {
			for (size_t i = 0; i < cnt; i++)
				deleter(ptr[i]);
			kern_os_free(ptr);
			ptr = nullptr;
			cnt = rsvd = 0;
		}
	}
};

template <typename T, void (*deleter)(T) = emptyDeleter<T>>
class evector : public evector_base<typename std::remove_reference<T>::type, T, deleter> {};
