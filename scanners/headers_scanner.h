#pragma once

#include <Windows.h>

#include "module_scanner.h"

class HeadersScanReport : public ModuleScanReport
{
public:
	HeadersScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize),
		epModified(false), archMismatch(false), is64(false) { }


	const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		ModuleScanReport::toJSON(outs, level);
		outs << ",\n";
		OUT_PADDED(outs, level, "\"ep_modified\" : ");
		outs << epModified;
		outs << ",\n";
		OUT_PADDED(outs, level, "\"sec_hdr_modified\" : ");
		outs << secHdrModified;
		if (archMismatch) {
			outs << ",\n";
			OUT_PADDED(outs, level, "\"arch_mismatch\" : ");
			outs << archMismatch;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is64b\" : ");
			outs << is64;
		}
	}

	const virtual bool toJSON(std::stringstream& outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"headers_scan\" : {\n");
		fieldsToJSON(outs, level + 1);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}

	bool epModified;
	bool secHdrModified;
	bool archMismatch; // the loaded module is of different architecture than the module read from the corresponding path
	DWORD is64; // is the remote module 64bit
};

class HeadersScanner : public ModuleScanner {
public:
	HeadersScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
		: ModuleScanner(hProc, moduleData, remoteModData)
	{
	}

	virtual HeadersScanReport* scanRemote();

private:
	bool zeroUnusedFields(PBYTE hdr_buffer, size_t hdrs_size);
	bool isSecHdrModified(PBYTE hdr_buffer1, PBYTE hdr_buffer2, size_t hdrs_size);
};
