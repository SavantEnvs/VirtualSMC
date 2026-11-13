// Fuzzes the SMC fixed-point/float codecs and typed value constructors from VirtualSMC's plugin API
// (VirtualSMC/kern_vsmcapi.cpp, VirtualSMCSDK/kern_vsmcapi.hpp).
#include <math.h>
#include <string.h>

#include <VirtualSMCSDK/kern_vsmcapi.hpp>

#include "../harness_common.hpp"

namespace {

char hexDigit(unsigned v) { return static_cast<char>(v < 10 ? '0' + v : 'a' + (v - 10)); }

// Picks a real spNN/fpNN key type most of the time and an arbitrary 32-bit one otherwise.
uint32_t pickType(Reader &in, bool fixedPoint) {
	uint8_t sel = in.u8();
	if (sel >= 192) return in.u32();
	unsigned integral = 1U + sel % 15U;
	char name[4] = {fixedPoint ? 'f' : 's', 'p', hexDigit(integral), hexDigit((fixedPoint ? 16U : 15U) - integral)};
	uint32_t type;
	memcpy(&type, name, sizeof(type));
	return type;
}

double pickDouble(Reader &in) {
	uint8_t sel = in.u8();
	if (sel < 128) return static_cast<double>(static_cast<int16_t>(in.u16())) / 256.0;
	if (sel < 192) return static_cast<double>(in.u32()) / 65536.0;
	uint64_t bits = in.u64();
	double d;
	memcpy(&d, &bits, sizeof(d));
	return d;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	Reader in(data, size);
	uint32_t checksum = 0;

	for (unsigned step = 0; step < 16 && !in.empty(); step++) {
		switch (in.u8() % 12) {
			case 0: {
				uint32_t type = pickType(in, false);
				uint16_t raw = in.u16();
				checksum += static_cast<uint32_t>(static_cast<int32_t>(VirtualSMCAPI::decodeSp(type, raw) * 1000.0));
				break;
			}
			case 1: {
				uint32_t type = pickType(in, false);
				checksum += VirtualSMCAPI::encodeSp(type, pickDouble(in));
				break;
			}
			case 2: {
				uint32_t type = pickType(in, true);
				uint16_t raw = in.u16();
				checksum += static_cast<uint32_t>(static_cast<int32_t>(VirtualSMCAPI::decodeFp(type, raw) * 1000.0));
				break;
			}
			case 3: {
				uint32_t type = pickType(in, true);
				checksum += VirtualSMCAPI::encodeFp(type, pickDouble(in));
				break;
			}
			case 4: {
				uint32_t type = pickType(in, false);
				checksum += static_cast<uint32_t>(VirtualSMCAPI::decodeIntSp(type, in.u16()));
				break;
			}
			case 5: {
				uint32_t type = pickType(in, false);
				checksum += VirtualSMCAPI::encodeIntSp(type, static_cast<int16_t>(in.u16()));
				break;
			}
			case 6: {
				uint32_t type = pickType(in, true);
				checksum += VirtualSMCAPI::decodeIntFp(type, in.u16());
				break;
			}
			case 7: {
				uint32_t type = pickType(in, true);
				checksum += VirtualSMCAPI::encodeIntFp(type, in.u16());
				break;
			}
			case 8: {
				uint32_t raw = in.u32();
				float f = VirtualSMCAPI::decodeFlt(raw);
				checksum += VirtualSMCAPI::encodeFlt(f);
				break;
			}
			case 9: {
				// Typed constructors: encode, wrap in a value, read the bytes back.
				VirtualSMCValue *value = nullptr;
				uint8_t attrs = in.u8();
				switch (in.u8() % 8) {
					case 0: value = VirtualSMCAPI::valueWithFlag(in.u8() & 1, nullptr, attrs); break;
					case 1: value = VirtualSMCAPI::valueWithUint8(in.u8(), nullptr, attrs); break;
					case 2: value = VirtualSMCAPI::valueWithSint8(static_cast<int8_t>(in.u8()), nullptr, attrs); break;
					case 3: value = VirtualSMCAPI::valueWithUint16(in.u16(), nullptr, attrs); break;
					case 4: value = VirtualSMCAPI::valueWithSint16(static_cast<int16_t>(in.u16()), nullptr, attrs); break;
					case 5: value = VirtualSMCAPI::valueWithUint32(in.u32(), nullptr, attrs); break;
					case 6: {
						uint32_t type = pickType(in, false);
						value = VirtualSMCAPI::valueWithSp(pickDouble(in), type, nullptr, attrs);
						break;
					}
					default: {
						uint32_t type = pickType(in, true);
						value = VirtualSMCAPI::valueWithFp(pickDouble(in), type, nullptr, attrs);
						break;
					}
				}
				if (value) {
					SMC_DATA_SIZE sz = 0;
					const SMC_DATA *bytes = value->get(sz);
					for (SMC_DATA_SIZE i = 0; i < sz; i++) checksum = checksum * 31 + bytes[i];
					VirtualSMCValue::deleter(value);
				}
				break;
			}
			default: {
				// Raw value construction: size is a full byte, so sizes above SMC_MAX_DATA_SIZE are reachable.
				SMC_DATA_SIZE sz = in.u8();
				SMC_KEY_TYPE type = in.u32();
				SMC_KEY_ATTRIBUTES attrs = in.u8();
				SerializeLevel level = static_cast<SerializeLevel>(in.u8() % 3);
				SMC_DATA buf[256] = {};
				in.bytes(buf, sz);
				auto *value = VirtualSMCAPI::valueWithData(buf, sz, type, nullptr, attrs, level);
				if (value) {
					SMC_DATA_SIZE got = 0;
					const SMC_DATA *bytes = value->get(got);
					for (SMC_DATA_SIZE i = 0; i < got; i++) checksum = checksum * 31 + bytes[i];
					checksum += value->serializable(true) + value->serializable(false);
					VirtualSMCValue::deleter(value);
				}
				break;
			}
		}
	}

	__asm__ volatile("" : : "r"(checksum));
	return 0;
}
