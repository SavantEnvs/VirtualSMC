#pragma once
#include <Headers/kern_iokit.hpp>

struct BaseDeviceInfo {
	int modelType {WIOKit::ComputerModel::ComputerDesktop};
	static BaseDeviceInfo &get() {
		static BaseDeviceInfo info;
		return info;
	}
};
