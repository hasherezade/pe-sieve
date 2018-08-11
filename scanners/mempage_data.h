#pragma once

#include <Windows.h>

#include "peconv.h"

class MemPageData
{
public:
	MemPageData(HANDLE _process, ULONGLONG _start_va)
		: processHandle(_process), start_va(_start_va),
		is_listed_module(false),
		is_info_filled(false), loadedData(nullptr), loadedSize(0)
	{
		fillInfo();
	}

	virtual ~MemPageData()
	{
		_freeRemote();
	}

	bool fillInfo();
	bool isInfoFilled() { return is_info_filled; }
	size_t getLoadedSize() { return loadedSize; }
	const PBYTE getLoadedData() { return loadedData;  }

	ULONGLONG start_va;
	DWORD protection;
	DWORD initial_protect;
	bool is_private;
	DWORD mapping_type;
	bool is_listed_module;

	ULONGLONG alloc_base;
	ULONGLONG region_start;
	ULONGLONG region_end;

	bool load()
	{
		if (loadedData) {
			return true;
		}
		if (!_loadRemote()) {
			return false;
		}
		//check again:
		if (loadedData) {
			return true;
		}
		return true;
	}

	bool hasMappedName();
	// checks if the memory area is mapped 1-to-1 from the file on the disk
	bool isRealMapping();

protected:
	bool _loadRemote();

	void _freeRemote()
	{
		peconv::free_aligned(loadedData, loadedSize);
		loadedData = nullptr;
		loadedSize = 0;
	}

	PBYTE loadedData;
	size_t loadedSize;

	bool is_info_filled;
	HANDLE processHandle;
};
