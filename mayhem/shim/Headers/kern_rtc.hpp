#pragma once
#include <stdint.h>

struct RTCStorage {
	static constexpr uint16_t R_PCH_RTC_INDEX = 0x70;
	static constexpr uint16_t R_PCH_RTC_TARGET = 0x71;
	static constexpr uint8_t RTC_SEC = 0x00;
	static constexpr uint8_t RTC_MIN = 0x02;
	static constexpr uint8_t RTC_HOUR = 0x04;
};
