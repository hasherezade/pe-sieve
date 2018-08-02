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
		freeRemote();
	}

	bool fillInfo();
	bool isInfoFilled() { return is_info_filled; }

	ULONGLONG start_va;
	DWORD protection;
	DWORD initial_protect;
	bool is_private;
	DWORD mapping_type;
	bool is_listed_module;

	ULONGLONG alloc_base;
	ULONGLONG region_start;
	ULONGLONG region_end;

protected:
	bool loadRemote();

	void freeRemote()
	{
		peconv::free_aligned(loadedData, loadedSize);
		loadedData = nullptr;
		loadedSize = 0;
	}

	// checks if the memory area is mapped 1-to-1 from the file on the disk
	bool isRealMapping();

	PBYTE loadedData;
	size_t loadedSize;

	bool is_info_filled;
	HANDLE processHandle;

	friend class MemPageScanner;
	friend class ArtefactScanner;
};

BYTE* find_pattern(BYTE *buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size);
