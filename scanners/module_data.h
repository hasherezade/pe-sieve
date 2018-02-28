#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"

class ModuleData {

public:
	ModuleData(HANDLE _processHandle, HMODULE _module)
		: processHandle(_processHandle), moduleHandle(_module),
		is_module_named(false), original_size(0), original_module(nullptr)
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

	bool convertPath();
	bool loadOriginal();
	bool reloadWow64();

	HANDLE processHandle;
	HMODULE moduleHandle;
	char szModName[MAX_PATH];
	bool is_module_named;

	PBYTE original_module;
	size_t original_size;
};
