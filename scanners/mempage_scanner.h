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

typedef enum {
	MEMPROTECT_R = 1,
	MEMPROTECT_X = 2,
	MEMPROTECT_W = 4,
	MEMPROTECT_V = 8,
	MEMPROTECT_G = 16
} t_mempage_protect;

class MemPageData
{
public:
	MemPageData(ULONGLONG _start_va, size_t _size, DWORD _protect)
		: start_va(_start_va), size(_size), protection(_protect), is_listed_module(false) {}

	virtual ~MemPageData() {}

	bool is_readable()
	{
		return (protection & MEMPROTECT_R);
	}

	bool is_wx()
	{
		return (protection & MEMPROTECT_X) && (protection & MEMPROTECT_W); // WRITE + EXECUTE -> suspicious
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
