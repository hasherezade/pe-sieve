#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_data.h"

#include "../utils/util.h"

class WorkingSetScanReport : public ModuleScanReport
{
public:
	WorkingSetScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status)
		: ModuleScanReport(processHandle, _module, _moduleSize, status)
	{
		 is_executable = false;
		 is_listed_module = false;
		 protection = 0;
		 has_pe = false; //not a PE file
		 has_shellcode = true;
		 is_doppel = false;
	}

	const virtual bool toJSON(std::stringstream &outs,size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"workingset_scan\" : {\n");
		fieldsToJSON(outs, level + 1);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}

	const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		ModuleScanReport::toJSON(outs, level);
		outs << ",\n";
		OUT_PADDED(outs, level, "\"has_pe\" : ");
		outs << std::dec << has_pe;
		outs << ",\n";
		OUT_PADDED(outs, level, "\"has_shellcode\" : ");
		outs << std::dec << has_shellcode;
		if (!is_executable) {
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is_executable\" : ");
			outs << std::dec << is_executable;
		}
		if (is_doppel) {
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is_doppel\" : ");
			outs << std::dec << is_doppel;
		}
		outs << ",\n";
		OUT_PADDED(outs, level, "\"is_listed_module\" : ");
		outs << std::dec << is_listed_module;
		outs << ",\n";
		OUT_PADDED(outs, level, "\"protection\" : ");
		outs << std::dec << protection;
	}

	bool is_executable;
	bool is_listed_module;
	bool has_pe;
	bool has_shellcode;
	bool is_doppel;
	DWORD protection;
};

class WorkingSetScanner {
public:
	WorkingSetScanner(HANDLE _procHndl, MemPageData &_memPageDatal, bool _detectShellcode)
		: processHandle(_procHndl), memPage(_memPageDatal),
		detectShellcode(_detectShellcode),
		isDeepScan(true)
	{
	}
	virtual ~WorkingSetScanner() {}

	virtual WorkingSetScanReport* scanRemote();

protected:
	bool isExecutable(MemPageData &memPageData);
	bool isCode(MemPageData &memPageData);
	WorkingSetScanReport* scanExecutableArea(MemPageData &memPageData);

	bool isDeepScan;
	bool detectShellcode; // is shellcode detection enabled
	HANDLE processHandle;
	MemPageData &memPage;
};
