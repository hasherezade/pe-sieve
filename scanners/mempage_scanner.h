#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "../module_data.h"

class MemPageScanReport : public ModuleScanReport
{
public:
	MemPageScanReport(HANDLE processHandle, HMODULE _module, t_scan_status status)
		: ModuleScanReport(processHandle, _module, status)
	{
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"workingset_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"is_rwx\" : "; 
		outs << std::dec << is_rwx;
		outs << ",\n";
		outs << "\"is_manually_loaded\" : "; 
		outs << std::dec << is_manually_loaded;
		outs << "\n}";
		return true;
	}
	bool is_rwx;
	bool is_manually_loaded;
};

class MemPageData
{
public:
	MemPageData(ULONGLONG _start_va, size_t _size, DWORD _protect)
		: start_va(_start_va), size(_size), protection(_protect), is_listed_module(false) {}

	virtual ~MemPageData() {}

	bool is_wx()
	{
		return (protection & 2) && (protection & 4); // WRITE + EXECUTE -> suspicious
	}

	ULONGLONG start_va;
	size_t size;
	DWORD protection;
	bool is_listed_module;
};

class MemPageScanner {
public:
	MemPageScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}
	virtual ~MemPageScanner() {}

	virtual MemPageScanReport* scanRemote(MemPageData &memPageData);

protected:
	HANDLE processHandle;
};
