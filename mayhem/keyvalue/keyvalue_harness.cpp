// Fuzzes the key/value (de)serialiser used for the keystore's persisted form
// (VirtualSMC/kern_keyvalue.cpp, VirtualSMC/kern_value.cpp).
#include <stdlib.h>
#include <string.h>

#include <VirtualSMCSDK/kern_keyvalue.hpp>

#include "../harness_common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	uint32_t checksum = 0;

	// Raw stream as it would come back from NVRAM: key, size, bytes, repeated.
	{
		const uint8_t *src = data;
		uint32_t left = static_cast<uint32_t>(size);
		for (unsigned i = 0; i < 64; i++) {
			SMC_KEY name = 0;
			SMC_DATA out[SMC_MAX_DATA_SIZE];
			memset(out, 0, sizeof(out));
			SMC_DATA_SIZE outsz = 0;
			if (!VirtualSMCKeyValue::deserialize(src, left, name, out, outsz))
				break;
			checksum += name;
			for (SMC_DATA_SIZE j = 0; j < outsz; j++) checksum = checksum * 31 + out[j];
		}
	}

	// Round trip: build a value from the input, serialise it into an exactly sized buffer, read it back.
	if (size >= 7) {
		Reader in(data, size);
		SMC_KEY key = in.u32();
		SMC_KEY_TYPE type = in.u32();
		SMC_KEY_ATTRIBUTES attr = in.u8();
		SMC_DATA_SIZE sz = in.u8();
		SerializeLevel level = static_cast<SerializeLevel>(in.u8() % 3);
		SMC_DATA buf[256] = {};
		in.bytes(buf, sz);

		auto *value = new VirtualSMCValue;
		if (value->init(buf, sz, type, attr, level)) {
			auto kv = VirtualSMCKeyValue::create(key, value);
			checksum += kv.serializable(true) + kv.serializable(false);

			size_t need = kv.serializedSize();
			auto *blob = static_cast<uint8_t *>(malloc(need));
			uint8_t *dst = blob;
			kv.serialize(dst);
			checksum += static_cast<uint32_t>(dst - blob);

			const uint8_t *src = blob;
			uint32_t left = static_cast<uint32_t>(need);
			SMC_KEY name = 0;
			SMC_DATA out[SMC_MAX_DATA_SIZE];
			memset(out, 0, sizeof(out));
			SMC_DATA_SIZE outsz = 0;
			if (VirtualSMCKeyValue::deserialize(src, left, name, out, outsz)) {
				checksum += name;
				for (SMC_DATA_SIZE j = 0; j < outsz; j++) checksum = checksum * 31 + out[j];
			}
			free(blob);

			VirtualSMCKeyValue::deleter(kv);
		} else {
			delete value;
		}
	}

	__asm__ volatile("" : : "r"(checksum));
	return 0;
}
