// Known-answer probe for mayhem/test.sh. Exercises the real VirtualSMC sources (built with normal flags)
// and prints one PASS/FAIL line per check; test.sh counts them.
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <memory>

#include <Headers/kern_devinfo.hpp>
#include <VirtualSMC/kern_keys.hpp>
#include <VirtualSMC/kern_keystore.hpp>
#include <VirtualSMCSDK/kern_keyvalue.hpp>
#include <VirtualSMCSDK/kern_vsmcapi.hpp>

static int failures = 0;

#define CHECK(name, cond) \
	do { \
		bool ok_ = (cond); \
		printf("%s %s\n", ok_ ? "PASS" : "FAIL", name); \
		if (!ok_) failures++; \
	} while (0)

static bool wireEquals(uint16_t v, uint8_t hi, uint8_t lo) {
	uint8_t b[2];
	memcpy(b, &v, 2);
	return b[0] == hi && b[1] == lo;
}

static uint16_t fromWire(uint8_t hi, uint8_t lo) {
	uint8_t b[2] = {hi, lo};
	uint16_t v;
	memcpy(&v, b, 2);
	return v;
}

static SMC_KEY key(const char *name) {
	SMC_KEY k;
	memcpy(&k, name, sizeof(k));
	return k;
}

static OSData *data32(uint32_t v) { return new OSData(&v, sizeof(v)); }

static OSDictionary *entry(const char *name, uint32_t type, uint8_t attr, const uint8_t *value, size_t len) {
	auto *d = new OSDictionary;
	d->setObject("name", new OSData(name, 4));
	d->setObject("type", data32(type));
	d->setObject("attr", new OSData(&attr, 1));
	d->setObject("value", new OSData(value, len));
	return d;
}

int main() {
	// Fixed-point codecs: big-endian on the wire, value scaled by 2^fraction bits.
	CHECK("encodeSp sp78 1.5 -> 01 80", wireEquals(VirtualSMCAPI::encodeSp(SmcKeyTypeSp78, 1.5), 0x01, 0x80));
	CHECK("encodeSp sp78 -2.25 -> 82 40", wireEquals(VirtualSMCAPI::encodeSp(SmcKeyTypeSp78, -2.25), 0x82, 0x40));
	CHECK("decodeSp sp78 01 80 == 1.5", VirtualSMCAPI::decodeSp(SmcKeyTypeSp78, fromWire(0x01, 0x80)) == 1.5);
	CHECK("decodeSp sp78 82 40 == -2.25", VirtualSMCAPI::decodeSp(SmcKeyTypeSp78, fromWire(0x82, 0x40)) == -2.25);
	CHECK("encodeSp unknown type -> 0", VirtualSMCAPI::encodeSp(SmcKeyTypeUint16, 1.5) == 0);
	CHECK("encodeFp fp88 1.5 -> 01 80", wireEquals(VirtualSMCAPI::encodeFp(SmcKeyTypeFp88, 1.5), 0x01, 0x80));
	CHECK("encodeFp fpe2 2.5 -> 00 0a", wireEquals(VirtualSMCAPI::encodeFp(SmcKeyTypeFpe2, 2.5), 0x00, 0x0a));
	CHECK("decodeFp fpe2 00 0a == 2.5", VirtualSMCAPI::decodeFp(SmcKeyTypeFpe2, fromWire(0x00, 0x0a)) == 2.5);
	CHECK("encodeIntSp sp78 3 -> 03 00", wireEquals(VirtualSMCAPI::encodeIntSp(SmcKeyTypeSp78, 3), 0x03, 0x00));
	CHECK("decodeIntSp sp78 03 00 == 3", VirtualSMCAPI::decodeIntSp(SmcKeyTypeSp78, fromWire(0x03, 0x00)) == 3);
	CHECK("encodeIntFp fpe2 5 -> 00 14", wireEquals(VirtualSMCAPI::encodeIntFp(SmcKeyTypeFpe2, 5), 0x00, 0x14));
	CHECK("decodeIntFp fpe2 00 14 == 5", VirtualSMCAPI::decodeIntFp(SmcKeyTypeFpe2, fromWire(0x00, 0x14)) == 5);
	CHECK("encodeFlt 1.0 == 0x3f800000", VirtualSMCAPI::encodeFlt(1.0f) == 0x3f800000U);
	CHECK("decodeFlt 0xc0200000 == -2.5", VirtualSMCAPI::decodeFlt(0xc0200000U) == -2.5f);

	// Typed value constructors.
	{
		auto *v = VirtualSMCAPI::valueWithUint16(0x1234, nullptr, SMC_KEY_ATTRIBUTE_READ);
		SMC_DATA_SIZE sz = 0;
		const SMC_DATA *p = v ? v->get(sz) : nullptr;
		CHECK("valueWithUint16 0x1234 size 2", p && sz == 2);
		CHECK("valueWithUint16 0x1234 bytes 12 34", p && sz == 2 && p[0] == 0x12 && p[1] == 0x34);
		if (v) VirtualSMCValue::deleter(v);
	}
	{
		CHECK("valueWithData size 0 rejected", VirtualSMCAPI::valueWithData(nullptr, 0, SmcKeyTypeUint8, nullptr, 0) == nullptr);
	}

	// Key/value stream format: name(4) size(1) bytes.
	{
		auto *val = new VirtualSMCValue;
		const uint8_t raw[3] = {0xAA, 0xBB, 0xCC};
		CHECK("value init 3 bytes", val->init(raw, 3, SmcKeyTypeUint8, SMC_KEY_ATTRIBUTE_READ));
		auto kv = VirtualSMCKeyValue::create(key("ABCD"), val);
		CHECK("serializedSize == 8", kv.serializedSize() == 8);
		uint8_t blob[8] = {};
		uint8_t *dst = blob;
		kv.serialize(dst);
		const uint8_t expect[8] = {'A', 'B', 'C', 'D', 3, 0xAA, 0xBB, 0xCC};
		CHECK("serialize layout", dst == blob + 8 && memcmp(blob, expect, 8) == 0);
		const uint8_t *src = blob;
		uint32_t left = 8;
		SMC_KEY name = 0;
		SMC_DATA out[SMC_MAX_DATA_SIZE] = {};
		SMC_DATA_SIZE outsz = 0;
		CHECK("deserialize ok", VirtualSMCKeyValue::deserialize(src, left, name, out, outsz));
		CHECK("deserialize name", name == key("ABCD"));
		CHECK("deserialize payload", outsz == 3 && memcmp(out, raw, 3) == 0 && left == 0 && src == blob + 8);
		const uint8_t *shortSrc = blob;
		uint32_t shortLeft = 7;
		CHECK("deserialize truncated rejected", !VirtualSMCKeyValue::deserialize(shortSrc, shortLeft, name, out, outsz));
		VirtualSMCKeyValue::deleter(kv);
	}

	// Keystore: provider dictionary -> keys, access control, writes.
	{
		BaseDeviceInfo::get().modelType = WIOKit::ComputerModel::ComputerDesktop;
		const uint8_t v1[2] = {0x12, 0x34};
		const uint8_t v2[1] = {0x07};
		auto *arr = new OSArray;
		arr->setObject(entry("TST1", SmcKeyTypeUint16, SMC_KEY_ATTRIBUTE_READ | SMC_KEY_ATTRIBUTE_WRITE, v1, 2));
		arr->setObject(entry("TST2", SmcKeyTypeUint8, SMC_KEY_ATTRIBUTE_READ, v2, 1));
		arr->setObject(new OSString("junk"));
		auto *bad = new OSDictionary;
		bad->setObject("name", new OSData("TST3", 4));
		arr->setObject(bad);
		OSDictionary props;
		props.setObject("Generic", arr);

		SMCInfo info;
		memset(&info, 0, sizeof(info));
		auto ks = std::make_unique<VirtualSMCKeystore>();
		CHECK("keystore init", ks->init(&props, nullptr, info, nullptr, WIOKit::ComputerModel::ComputerDesktop, false));

		const VirtualSMCValue *val = nullptr;
		SMC_DATA_SIZE sz = 0;
		const SMC_DATA *p = nullptr;
		CHECK("read TST1 ok", ks->readValueByName(key("TST1"), val) == SmcSuccess && val);
		p = val ? val->get(sz) : nullptr;
		CHECK("read TST1 bytes 12 34", p && sz == 2 && p[0] == 0x12 && p[1] == 0x34);
		CHECK("read missing key -> not found", ks->readValueByName(key("NOPE"), val) == SmcNotFound);
		CHECK("incomplete entry TST3 skipped", ks->readValueByName(key("TST3"), val) == SmcNotFound);

		SMC_DATA_SIZE isz = 0;
		SMC_KEY_TYPE ity = 0;
		SMC_KEY_ATTRIBUTES iat = 0;
		CHECK("info TST1", ks->getInfoByName(key("TST1"), isz, ity, iat) == SmcSuccess && isz == 2 &&
			  ity == SmcKeyTypeUint16 && iat == (SMC_KEY_ATTRIBUTE_READ | SMC_KEY_ATTRIBUTE_WRITE));

		const SMC_DATA nv[2] = {0xBE, 0xEF};
		CHECK("write TST1 ok", ks->writeValueByName(key("TST1"), nv) == SmcSuccess);
		p = (ks->readValueByName(key("TST1"), val) == SmcSuccess && val) ? val->get(sz) : nullptr;
		CHECK("read back TST1 be ef", p && sz == 2 && p[0] == 0xBE && p[1] == 0xEF);
		const SMC_DATA nv1[1] = {0x55};
		CHECK("write read-only TST2 refused", ks->writeValueByName(key("TST2"), nv1) == SmcNotWritable);
		p = (ks->readValueByName(key("TST2"), val) == SmcSuccess && val) ? val->get(sz) : nullptr;
		CHECK("TST2 unchanged 07", p && sz == 1 && p[0] == 0x07);
		CHECK("write missing key -> not found", ks->writeValueByName(key("NOPE"), nv) == SmcNotFound);

		uint32_t amount = ks->getPublicKeyAmount();
		CHECK("key amount >= 3 (TST1, TST2, built-ins)", amount >= 3);
		p = (ks->readValueByName(key("#KEY"), val) == SmcSuccess && val) ? val->get(sz) : nullptr;
		uint32_t keyCount = 0;
		if (p && sz == 4) {
			keyCount = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
		}
		CHECK("#KEY reports the public key amount (big-endian)", keyCount == amount);

		bool found1 = false, found2 = false, allOk = true;
		for (uint32_t i = 0; i < amount; i++) {
			SMC_KEY k = 0;
			if (ks->readNameByIndex(i, k) != SmcSuccess) { allOk = false; continue; }
			found1 |= k == key("TST1");
			found2 |= k == key("TST2");
		}
		SMC_KEY past = 0;
		CHECK("every index below amount resolves", allOk);
		CHECK("TST1 and TST2 are listed by index", found1 && found2);
		CHECK("index == amount is out of range", ks->readNameByIndex(amount, past) == SmcKeyIndexRangeError);

		// Plugin override of an existing key swaps its value.
		VirtualSMCAPI::Plugin plugin {};
		plugin.product = "kat-plugin";
		plugin.version = 1;
		plugin.apiver = VirtualSMCAPI::Version;
		VirtualSMCAPI::addKey(key("TST2"), plugin.data, VirtualSMCAPI::valueWithUint8(0x99, nullptr, SMC_KEY_ATTRIBUTE_READ));
		CHECK("plugin load ok", ks->loadPlugin(&plugin) == kIOReturnSuccess);
		p = (ks->readValueByName(key("TST2"), val) == SmcSuccess && val) ? val->get(sz) : nullptr;
		CHECK("plugin overrides TST2 -> 99", p && sz == 1 && p[0] == 0x99);
		plugin.apiver = VirtualSMCAPI::Version + 1;
		CHECK("plugin with wrong api rejected", ks->loadPlugin(&plugin) == kIOReturnInvalid);
	}

	return failures ? 1 : 0;
}
