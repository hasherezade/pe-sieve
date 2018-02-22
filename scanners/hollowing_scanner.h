#pragma once

#include <Windows.h>

#include "scanner.h"

class HeadersScanReport : public ModuleScanReport
{
public:
	HeadersScanReport(HANDLE processHandle, HMODULE _module)
		: ModuleScanReport(processHandle, _module),
		epModified(false) { }

	const virtual bool toJSON(std::stringstream& outs)
	{
		outs << "\"headers_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"ep_modified\" : " ;
		outs << epModified;
		outs << "\n";
		outs << "}";
		return true;
	}
	bool epModified;
};

class HollowingScanner : public ModuleScanner {
public:
	HollowingScanner(HANDLE hProc)
		: ModuleScanner(hProc)
	{
	}

	virtual HeadersScanReport* scanRemote(ModuleData &moduleData);

private:
	bool zero_unused_fields(PBYTE hdr_buffer, size_t hdrs_size);
};
