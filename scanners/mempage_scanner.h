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
	MemPageData(HANDLE _process, ULONGLONG _start_va, size_t _size, DWORD _basic_protection)
		: processHandle(_process), start_va(_start_va), size(_size),
		basic_protection(_basic_protection), is_listed_module(false),
		is_info_filled(false)
	{
		fillInfo();
	}

	virtual ~MemPageData() {}

	bool fillInfo();
	bool isInfoFilled() { return is_info_filled; }

	ULONGLONG start_va;
	size_t size;
	DWORD basic_protection;
	DWORD protection;
	DWORD initial_protect;
	bool is_private;
	bool is_listed_module;

protected:
	bool is_info_filled;
	HANDLE processHandle;
};

class MemPageScanner {
public:
	MemPageScanner(HANDLE procHndl)
		: processHandle(procHndl)
	{
	}
	virtual ~MemPageScanner() {}

	virtual MemPageScanReport* scanRemote(MemPageData &memPageData);

	bool hasPeHeader(MemPageData &memPageData);

	DWORD getInitialAccess(MemPageData &memPageData);

protected:
	HANDLE processHandle;
};
