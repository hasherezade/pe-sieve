#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"

class ModuleData {

public:
	ModuleData(HANDLE _processHandle, HMODULE _module)
		: processHandle(_processHandle), moduleHandle(_module),
		is_module_named(false), original_size(0), original_module(nullptr),
		is_relocated(false), is_dot_net(false)
	{
		memset(szModName, 0, MAX_PATH);
	}

	~ModuleData()
	{
		peconv::free_pe_buffer(original_module, original_size);
	}

	bool is64bit()
	{
		if (original_module == nullptr) {
			return false;
		}
		return peconv::is64bit(original_module);
	}

	bool isDotNet() { return this->is_dot_net; }

	ULONGLONG rvaToVa(DWORD rva)
	{
		return reinterpret_cast<ULONGLONG>(this->moduleHandle) + rva;
	}

	DWORD vaToRva(ULONGLONG va)
	{
		ULONGLONG module_base = reinterpret_cast<ULONGLONG>(this->moduleHandle);
		if (va < module_base) {
			return NULL; // not this module
		}
		if (va > module_base + this->original_size) {
			return NULL; // not this module
		}
		ULONGLONG diff = (va - module_base);
		return static_cast<DWORD>(diff);
	}

	bool loadOriginal();
	bool reloadWow64();
	bool relocateToBase();

	HANDLE processHandle;
	HMODULE moduleHandle;
	char szModName[MAX_PATH];
	bool is_module_named;

	PBYTE original_module;
	size_t original_size;

protected:
	bool isDotNetManagedCode();
	bool is_relocated;
	bool is_dot_net;

	friend class PeSection;
};

// the module loaded within the scanned process
class RemoteModuleData
{
public:

	static std::string getModuleName(HANDLE _processHandle, HMODULE _modBaseAddr);
	static std::string getMappedName(HANDLE _processHandle, LPVOID _modBaseAddr);

	RemoteModuleData(HANDLE _processHandle, HMODULE _modBaseAddr)
		: processHandle(_processHandle), modBaseAddr(_modBaseAddr)
	{
		is_ready = false;
		memset(headerBuffer, 0, peconv::MAX_HEADER_SIZE);
		init();
	}

	virtual ~RemoteModuleData() {}

	bool isSectionExecutable(size_t section_number);
	bool hasExecutableSection();
	bool isInitialized()
	{
		if (!is_ready) init();
		return is_ready;
	}

	BYTE headerBuffer[peconv::MAX_HEADER_SIZE];

protected:
	bool init();
	bool loadHeader();
	ULONGLONG RemoteModuleData::getRemoteSectionVa(const size_t section_num);

	HANDLE processHandle;
	HMODULE modBaseAddr;

	bool is_ready;

	friend class PeSection;
};
