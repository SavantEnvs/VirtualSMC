// Force-included in place of kern_vsmc.hpp / kern_efiend.hpp (suppressed with -Dkern_vsmc_hpp
// -Dkern_efiend_h): the few VirtualSMC and EfiBackend entry points the keystore code calls.
#pragma once

// The kernel headers pull in <stdatomic.h>, whose atomic_* macros break libstdc++'s <memory>; load the C++
// library first so it is already parsed.
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <VirtualSMC/kern_keystore.hpp>

class VirtualSMCKeystore;

struct VirtualSMC {
	enum WatchDogJob : uint8_t {
		WatchDogDoNothing = 0,
		WatchDogShutdownToS5 = 1,
		WatchDogForceRestart = 2,
		WatchDogForceStartup = 3,
		WatchDogReserved = 4,
		WatchDogShutdownToUnk = 32
	};

	static inline VirtualSMCKeystore *keystore {nullptr};

	static VirtualSMCKeystore *getKeystore() { return keystore; }
	static bool isServicingReady() { return keystore != nullptr; }
	static void setInterrupts(bool) {}
	static bool postInterrupt(SMC_EVENT_CODE, const void * = nullptr, uint32_t = 0) { return true; }
	static void postWatchDogJob(uint8_t, uint64_t, bool = false) {}
};

namespace EfiBackend {
	inline bool submitEncryptionKey(const uint8_t *, bool) { return true; }
	inline bool eraseTempEncryptionKey() { return true; }
}
