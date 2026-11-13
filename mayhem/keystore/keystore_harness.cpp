// Fuzzes the VirtualSMC keystore (VirtualSMC/kern_keystore.cpp, kern_keys.cpp, kern_value.cpp): builds
// the provider dictionaries that Lilu would hand over from a plist, initialises a keystore, then drives
// the SMC read/write/info/index paths and plugin loading the way AppleSMC and plugin kexts do.
//
// Two things are deliberately kept out of reach of the generated operations:
//  - Writes to DUSR: its handler executes `cli; hlt` in a loop on purpose (it freezes the OS), which in
//    user space is just a privileged-instruction trap with nothing to learn from.
//  - Plugins that replace EPCI or KPST: the keystore caches raw pointers to those two values and a
//    replacement frees them, which is a plugin-API contract violation rather than a keystore input.
#include <stdlib.h>
#include <string.h>
#include <memory>
#include <vector>

#include <Headers/kern_devinfo.hpp>
#include <Headers/kern_time.hpp>
#include <VirtualSMC/kern_keys.hpp>
#include <VirtualSMC/kern_keystore.hpp>

#include "../harness_common.hpp"

// Standards-conforming access to the private storages, so every input can free what it allocated.
template <typename Tag, typename Tag::type Member>
struct Rob {
	friend typename Tag::type robbed(Tag) { return Member; }
};
struct DataTag {
	using type = VirtualSMCAPI::KeyStorage VirtualSMCKeystore::*;
	friend type robbed(DataTag);
};
struct HiddenTag {
	using type = VirtualSMCAPI::KeyStorage VirtualSMCKeystore::*;
	friend type robbed(HiddenTag);
};
template struct Rob<DataTag, &VirtualSMCKeystore::dataStorage>;
template struct Rob<HiddenTag, &VirtualSMCKeystore::dataHiddenStorage>;

namespace {

const char *const kSections[] = {
	"Generic", "GenericV1", "GenericV2", "GenericDesktopV1", "GenericDesktopV2",
	"GenericLaptopV1", "GenericLaptopV2", "Mac-TEST", "Unrelated",
};

const char *const kKnownKeys[] = {
	"HBKP", "EPCI", "KPST", "#KEY", "$Adr", "$Num", "BEMB", "LDKN", "RMde", "NTOK", "RGEN", "CRCA", "CRCa",
	"CRCB", "CRCb", "CRCC", "CRCc", "CRCU", "CRCu", "CRCR", "CRCr", "CRCF", "CRCK", "REV ", "RVBF", "RVUF",
	"RBr ", "RPlt", "RVCR", "RMAC", "RMSN", "RSSN", "CLKH", "CLKT", "CLWK", "DPLM", "LDSP", "LDLG", "MSSD",
	"MSDW", "MSFW", "MSSP", "MSSW", "MSWr", "MSPC", "MSPP", "MSPS", "NATi", "NATJ", "OSWD", "WKTP", "MSQC",
	"EVCT", "EVRD", "EVHF", "EFBM", "EFBP", "EFBS", "MSPR", "DUSR", "FAC0", "KPPW", "OSK0", "OSK1", "____",
};
constexpr size_t kKnownCount = sizeof(kKnownKeys) / sizeof(kKnownKeys[0]);

SMC_KEY keyFromName(const char *name) {
	SMC_KEY key;
	memcpy(&key, name, sizeof(key));
	return key;
}

bool isKey(SMC_KEY key, const char *name) { return key == keyFromName(name); }

// Mostly a key the keystore really has, sometimes an arbitrary one.
SMC_KEY pickKey(Reader &in) {
	uint8_t sel = in.u8();
	if (sel < 224) return keyFromName(kKnownKeys[sel % kKnownCount]);
	return in.u32();
}

OSData *makeData(Reader &in, size_t len) {
	uint8_t buf[256];
	in.bytes(buf, len);
	return new OSData(buf, len);
}

// One merge() entry: every field optional and, when present, sometimes the wrong shape.
OSDictionary *makeEntry(Reader &in) {
	auto *dict = new OSDictionary;
	uint8_t present = in.u8();
	uint8_t shape = in.u8();

	if (present & 0x01) {
		if (shape & 0x01) {
			dict->setObject("name", new OSNumber(in.u32()));
		} else if (shape & 0x02) {
			dict->setObject("name", makeData(in, 4U));
		} else {
			uint8_t sel = in.u8();
			if (sel < 192) {
				dict->setObject("name", new OSData(kKnownKeys[sel % kKnownCount], 4));
			} else {
				dict->setObject("name", makeData(in, in.u8() % 8U));
			}
		}
	}
	if (present & 0x02)
		dict->setObject("type", makeData(in, (shape & 0x04) ? in.u8() % 8U : 4U));
	if (present & 0x04)
		dict->setObject("attr", makeData(in, (shape & 0x08) ? in.u8() % 4U : 1U));
	if (present & 0x08) {
		if (shape & 0x10) {
			dict->setObject("value", new OSString("value"));
		} else {
			dict->setObject("value", makeData(in, in.u8() % 160U));
		}
	}
	if (present & 0x10)
		dict->setObject("size", (shape & 0x20) ? static_cast<OSObject *>(new OSNumber(in.u8())) : makeData(in, 1U));
	if (present & 0x20)
		dict->setObject("hidden", new OSBoolean(shape & 0x40));
	if (present & 0x40)
		dict->setObject("serialize", new OSBoolean(shape & 0x80));
	return dict;
}

OSArray *makeArray(Reader &in) {
	auto *arr = new OSArray;
	unsigned count = in.u8() % 6U;
	for (unsigned i = 0; i < count; i++) {
		if (in.u8() < 12)
			arr->setObject(new OSString("not a dictionary"));
		else
			arr->setObject(makeEntry(in));
	}
	return arr;
}

OSDictionary *makeProvider(Reader &in) {
	auto *dict = new OSDictionary;
	unsigned sections = in.u8() % 4U;
	for (unsigned i = 0; i < sections; i++) {
		const char *name = kSections[in.u8() % (sizeof(kSections) / sizeof(kSections[0]))];
		if (in.u8() < 12)
			dict->setObject(name, new OSBoolean(true));
		else
			dict->setObject(name, makeArray(in));
	}
	return dict;
}

struct PluginHolder {
	VirtualSMCAPI::Plugin plugin {};
	~PluginHolder() {
		plugin.data.deinit();
		plugin.dataHidden.deinit();
	}
};

int comparePlugin(const void *a, const void *b) { return VirtualSMCKeyValue::compare(a, b); }

void fillPluginStorage(Reader &in, VirtualSMCAPI::KeyStorage &storage) {
	unsigned count = in.u8() % 6U;
	for (unsigned i = 0; i < count; i++) {
		SMC_KEY key = pickKey(in);
		if (isKey(key, "EPCI") || isKey(key, "KPST"))
			key = keyFromName("PLG0");
		SMC_DATA_SIZE sz = in.u8() % 24U;
		SMC_KEY_TYPE type = in.u32();
		SMC_KEY_ATTRIBUTES attr = in.u8();
		SMC_DATA buf[24];
		in.bytes(buf, sizeof(buf));
		VirtualSMCAPI::addKey(key, storage, VirtualSMCAPI::valueWithData(buf, sz, type, nullptr, attr));
	}
	// The plugin API requires sorted storage.
	if (storage.size())
		qsort(storage.data(), storage.size(), sizeof(VirtualSMCKeyValue), comparePlugin);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0)
		return -1;

	Reader in(data, size);
	shim_clock_ns() = 1000000000ULL;

	uint8_t flags = in.u8();
	SMCInfo info;
	info.main[0] = flags & 0x03;
	if (flags & 0x04) {
		for (size_t i = 1; i < sizeof(info.main); i++) info.main[i] = static_cast<uint8_t>(0x10 + i);
		for (size_t i = 0; i < sizeof(info.flasherBase); i++) info.flasherBase[i] = static_cast<uint8_t>(0x20 + i);
		for (size_t i = 0; i < sizeof(info.flasherUpdate); i++) info.flasherUpdate[i] = static_cast<uint8_t>(0x30 + i);
		for (size_t i = 0; i < sizeof(info.branch); i++) info.branch[i] = static_cast<uint8_t>('a' + i);
	}
	memcpy(info.platform, "j137ap\0", 7);
	memcpy(info.serial, "C02TESTSERIAL001", sizeof(info.serial));
	memcpy(info.macAddress, "\x00\x11\x22\x33\x44\x55", sizeof(info.macAddress));

	int model = (flags & 0x08) ? WIOKit::ComputerModel::ComputerLaptop : WIOKit::ComputerModel::ComputerDesktop;
	BaseDeviceInfo::get().modelType = model;
	const char *board = (flags & 0x10) ? "Mac-TEST" : nullptr;

	std::unique_ptr<OSDictionary> mainprops((flags & 0x80) ? makeProvider(in) : nullptr);
	std::unique_ptr<OSDictionary> userprops((flags & 0x40) ? makeProvider(in) : nullptr);

	auto ks = std::make_unique<VirtualSMCKeystore>();
	std::vector<std::unique_ptr<PluginHolder>> plugins;
	uint32_t checksum = 0;

	if (ks->init(mainprops.get(), userprops.get(), info, board, model, flags & 0x20)) {
		for (unsigned op = 0; op < 48 && !in.empty(); op++) {
			switch (in.u8() % 9) {
				case 0: {
					const VirtualSMCValue *value = nullptr;
					if (ks->readValueByName(pickKey(in), value) == SmcSuccess && value) {
						SMC_DATA_SIZE sz = 0;
						const SMC_DATA *bytes = value->get(sz);
						for (SMC_DATA_SIZE i = 0; i < sz; i++) checksum = checksum * 31 + bytes[i];
					}
					break;
				}
				case 1: {
					SMC_KEY key = pickKey(in);
					SMC_DATA buf[SMC_MAX_DATA_SIZE];
					in.bytes(buf, sizeof(buf));
					if (!isKey(key, "DUSR"))
						checksum += ks->writeValueByName(key, buf);
					break;
				}
				case 2: {
					SMC_DATA_SIZE sz = 0;
					SMC_KEY_TYPE type = 0;
					SMC_KEY_ATTRIBUTES attr = 0;
					if (ks->getInfoByName(pickKey(in), sz, type, attr) == SmcSuccess)
						checksum += sz + type + attr;
					break;
				}
				case 3: {
					SMC_KEY key = 0;
					uint32_t idx = in.u8() < 200 ? in.u8() : in.u32();
					if (ks->readNameByIndex(idx, key) == SmcSuccess)
						checksum += key;
					break;
				}
				case 4:
					checksum += ks->getPublicKeyAmount();
					break;
				case 5:
					if (in.u8() & 1) ks->handlePowerOn(); else ks->handlePowerOff();
					break;
				case 6: {
					auto holder = std::make_unique<PluginHolder>();
					holder->plugin.product = "fuzz-plugin";
					holder->plugin.version = 1;
					holder->plugin.apiver = (in.u8() < 240) ? VirtualSMCAPI::Version : in.u8();
					fillPluginStorage(in, holder->plugin.data);
					fillPluginStorage(in, holder->plugin.dataHidden);
					checksum += static_cast<uint32_t>(ks->loadPlugin(&holder->plugin));
					plugins.push_back(std::move(holder));
					break;
				}
				case 7: {
					std::unique_ptr<OSArray> extra(makeArray(in));
					checksum += ks->merge(extra.get());
					break;
				}
				default: {
					std::unique_ptr<OSDictionary> extra(makeProvider(in));
					checksum += ks->mergeProvider(extra.get(), board, model);
					break;
				}
			}
		}
	}

	((*ks).*robbed(DataTag{})).deinit();
	((*ks).*robbed(HiddenTag{})).deinit();
	plugins.clear();

	__asm__ volatile("" : : "r"(checksum));
	return 0;
}
