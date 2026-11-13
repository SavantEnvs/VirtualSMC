// Minimal user-space stand-ins for the XNU libkern/IOKit classes VirtualSMC touches.
#ifndef VSMC_SHIM_OS_HPP
#define VSMC_SHIM_OS_HPP

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <utility>

typedef int IOReturn;
static constexpr IOReturn kIOReturnSuccess = 0;
static constexpr IOReturn kIOReturnNoMemory = 0x2bd;
static constexpr IOReturn kIOReturnInvalid = 0x2c2;
static constexpr IOReturn kIOReturnNoSpace = 0x2cb;

typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;
typedef int vm_prot_t;

class OSObject {
public:
	virtual ~OSObject() = default;
	void retain() const {}
	void release() const {}
};

#define OSDynamicCast(type, inst) \
	dynamic_cast<type *>(const_cast<OSObject *>(static_cast<const OSObject *>(inst)))

class OSData : public OSObject {
	std::vector<uint8_t> bytes;
public:
	OSData(const void *src, size_t len) : bytes(static_cast<const uint8_t *>(src), static_cast<const uint8_t *>(src) + len) {}
	unsigned int getLength() const { return static_cast<unsigned int>(bytes.size()); }
	const void *getBytesNoCopy() const { return bytes.data(); }
};

class OSBoolean : public OSObject {
	bool v;
public:
	explicit OSBoolean(bool b) : v(b) {}
	bool isTrue() const { return v; }
};

class OSNumber : public OSObject {
	uint64_t v;
public:
	explicit OSNumber(uint64_t n) : v(n) {}
	uint64_t unsigned64BitValue() const { return v; }
};

class OSString : public OSObject {
	std::string s;
public:
	explicit OSString(const char *c) : s(c) {}
	const char *getCStringNoCopy() const { return s.c_str(); }
};

// Containers own their children.
class OSArray : public OSObject {
	std::vector<OSObject *> items;
public:
	~OSArray() override { for (auto *o : items) delete o; }
	bool setObject(OSObject *o) { items.push_back(o); return true; }
	unsigned int getCount() const { return static_cast<unsigned int>(items.size()); }
	OSObject *getObject(unsigned int i) const { return i < items.size() ? items[i] : nullptr; }
};

class OSDictionary : public OSObject {
	std::vector<std::pair<std::string, OSObject *>> items;
public:
	~OSDictionary() override { for (auto &kv : items) delete kv.second; }
	bool setObject(const char *key, OSObject *o) { items.emplace_back(key, o); return true; }
	OSObject *getObject(const char *key) const {
		for (auto &kv : items)
			if (kv.first == key) return kv.second;
		return nullptr;
	}
};

class IORegistryEntry : public OSObject {};

class IONotifier : public OSObject {};

class IOService : public IORegistryEntry {
public:
	static OSDictionary *nameMatching(const char *) { return nullptr; }
	static IONotifier *addMatchingNotification(const char *, OSDictionary *, bool (*)(void *, void *, IOService *, IONotifier *), void *) { return nullptr; }
};

typedef bool (*IOServiceMatchingNotificationHandler)(void *, void *, IOService *, IONotifier *);
static constexpr const char *gIOFirstPublishNotification = "IOServiceFirstPublish";

#endif
