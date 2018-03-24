#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"

class MemPageScanReport : public ModuleScanReport
{
public:
	MemPageScanReport(HANDLE processHandle, HMODULE _module, t_scan_status status)
		: ModuleScanReport(processHandle, _module, status)
	{
		 is_executable = false;
		 is_manually_loaded = false;
		 protection = 0;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"workingset_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"is_executable\" : "; 
		outs << std::dec << is_executable;
		outs << ",\n";
		outs << "\"is_manually_loaded\" : "; 
		outs << std::dec << is_manually_loaded;
		outs << ",\n";
		outs << "\"protection\" : "; 
		outs << std::dec << protection;
		outs << "\n}";
		return true;
	}

	bool is_executable;
	bool is_manually_loaded;
	DWORD protection;
};

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
};

class MemPageScanner {
public:
	MemPageScanner(HANDLE _procHndl, MemPageData &_memPageDatal)
		: processHandle(_procHndl), memPage(_memPageDatal),
		isDeepScan(true)
	{
	}
	virtual ~MemPageScanner() {}

	virtual MemPageScanReport* scanRemote();

	DWORD getInitialAccess(MemPageData &memPageData);

protected:
	ULONGLONG findPeHeader(MemPageData &memPageData);

	bool isDeepScan;
	HANDLE processHandle;
	MemPageData &memPage;
};
