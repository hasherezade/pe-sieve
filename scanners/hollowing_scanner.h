#pragma once

#include <Windows.h>

#include "module_scanner.h"

class HeadersScanReport : public ModuleScanReport
{
public:
	HeadersScanReport(HANDLE processHandle, HMODULE _module)
		: ModuleScanReport(processHandle, _module),
		epModified(false), archMismatch(false), is64(false) { }

	const virtual bool toJSON(std::stringstream& outs)
	{
		outs << "\"headers_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << ",\n";
		outs << "\"ep_modified\" : " ;
		outs << epModified;
		outs << ",\n";
		outs << "\"arch_mismatch\" : " ;
		outs << archMismatch;
		outs << ",\n";
		outs << "\"is64b\" : " ;
		outs << is64;
		outs << "\n";
		outs << "}";
		return true;
	}
	bool epModified;
	bool archMismatch; // the loaded module is of different architecture than the module read from the corresponding path
	DWORD is64; // is the remote module 64bit
};

class HollowingScanner : public ModuleScanner {
public:
	HollowingScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
		: ModuleScanner(hProc, moduleData, remoteModData)
	{
	}

	virtual HeadersScanReport* scanRemote();

private:
	bool zero_unused_fields(PBYTE hdr_buffer, size_t hdrs_size);
};
