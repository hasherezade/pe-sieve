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
		 is_listed_module = false;
		 protection = 0;
		 has_pe = false; //not a PE file
		 has_shellcode = true;
		 is_doppel = false;
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
		outs << "\"has_pe\" : ";
		outs << std::dec << has_pe;
		outs << ",\n";
		outs << "\"has_shellcode\" : ";
		outs << std::dec << has_shellcode;
		if (!is_executable) {
			outs << ",\n";
			outs << "\"is_executable\" : ";
			outs << std::dec << is_executable;
		}
		if (is_doppel) {
			outs << ",\n";
			outs << "\"is_doppel\" : ";
			outs << std::dec << is_doppel;
		}
		outs << ",\n";
		outs << "\"is_listed_module\" : ";
		outs << std::dec << is_listed_module;
		outs << ",\n";
		outs << "\"protection\" : ";
		outs << std::dec << protection;
	}

	bool is_executable;
	bool is_listed_module;
	bool has_pe;
	bool has_shellcode;
	bool is_doppel;
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
