#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_data.h"

class MemPageScanReport : public ModuleScanReport
{
public:
	MemPageScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status)
		: ModuleScanReport(processHandle, _module, _moduleSize, status)
	{
		 is_executable = false;
		 is_manually_loaded = false;
		 protection = 0;
		 is_shellcode = false; //PE file
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"workingset_scan\" : ";
		outs << "{\n";
		fieldsToJSON(outs);
		outs << "\n}";
		return true;
	}

	const virtual void fieldsToJSON(std::stringstream &outs)
	{
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"is_shellcode\" : ";
		outs << std::dec << is_shellcode;
		if (!is_executable) {
			outs << ",\n";
			outs << "\"is_executable\" : ";
			outs << std::dec << is_executable;
		}
		outs << ",\n";
		outs << "\"is_manually_loaded\" : ";
		outs << std::dec << is_manually_loaded;
		outs << ",\n";
		outs << "\"protection\" : ";
		outs << std::dec << protection;
	}

	bool is_executable;
	bool is_manually_loaded;
	bool is_shellcode;
	DWORD protection;
};

class MemPageScanner {
public:
	MemPageScanner(HANDLE _procHndl, MemPageData &_memPageDatal, bool _detectShellcode)
		: processHandle(_procHndl), memPage(_memPageDatal),
		detectShellcode(_detectShellcode),
		isDeepScan(true)
	{
	}
	virtual ~MemPageScanner() {}

	virtual MemPageScanReport* scanRemote();

protected:
	bool isCode(MemPageData &memPageData);
	MemPageScanReport* scanShellcode(MemPageData &memPageData);

	bool isDeepScan;
	bool detectShellcode; // is shellcode detection enabled
	HANDLE processHandle;
	MemPageData &memPage;
};
