#pragma once
#include <Headers/kern_util.hpp>
#include "../shim_os.hpp"

namespace WIOKit {
	struct ComputerModel {
		enum {
			ComputerInvalid = 0x0,
			ComputerLaptop  = 0x1,
			ComputerDesktop = 0x2,
			ComputerAny = ComputerLaptop | ComputerDesktop
		};
	};

	// Same contract as Lilu: an OSData of exactly sizeof(T) bytes, anything else is a miss.
	template <typename T>
	inline bool getOSDataValue(const OSObject *obj, const char *, T &value) {
		if (obj) {
			auto data = OSDynamicCast(OSData, obj);
			if (data && data->getLength() == sizeof(T)) {
				value = *static_cast<const T *>(data->getBytesNoCopy());
				return true;
			}
		}
		return false;
	}

	template <typename T>
	inline bool getOSDataValue(const OSDictionary *dict, const char *name, T &value) {
		return getOSDataValue(dict->getObject(name), name, value);
	}
}
