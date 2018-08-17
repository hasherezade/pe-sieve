#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pe_sieve_types.h"
#include "peconv.h"

#include "../utils/util.h"

typedef enum module_scan_status {
	SCAN_ERROR = -1,
	SCAN_NOT_SUSPICIOUS = 0,
	SCAN_SUSPICIOUS = 1
} t_scan_status;

class ModuleScanReport
{
public:
	static const size_t JSON_LEVEL = 1;

	static t_scan_status get_scan_status(const ModuleScanReport *report)
	{
		if (report == nullptr) {
			return SCAN_ERROR;
		}
		return report->status;
	}

	ModuleScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status _status)
	{
		this->pid = GetProcessId(processHandle);
		this->module = _module;
		this->moduleSize = _moduleSize;
		this->status = _status;
		this->isDotNetModule = false;
	}

	ModuleScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
	{
		this->pid = GetProcessId(processHandle);
		this->module = _module;
		this->moduleSize = _moduleSize;
		this->isDotNetModule = false;
		this->status = SCAN_NOT_SUSPICIOUS;
	}

	virtual ~ModuleScanReport() {}

	const virtual bool toJSON(std::stringstream &outs, size_t level= JSON_LEVEL)
	{
		//outs << "\"pid\" : ";
		//outs << std::hex << pid << ",\n";
		OUT_PADDED(outs, level, "\"module\" : ");
		//outs << "\"module\" : ";
		outs << "\"" << std::hex << (ULONGLONG) module << "\"" << ",\n";
		OUT_PADDED(outs, level, "\"status\" : ");
		//outs << "\"status\" : " ;
		outs << std::dec << status;
		if (isDotNetModule) {
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is_dot_net\" : \"");
			outs << isDotNetModule << "\"";
		}
		return true;
	}

	virtual size_t generateTags(std::string reportPath) { return 0; }

	HMODULE module;
	size_t moduleSize;
	DWORD pid;
	bool isDotNetModule;

	t_scan_status status;
};

class UnreachableModuleReport : public ModuleScanReport
{
public:
	UnreachableModuleReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize, SCAN_SUSPICIOUS)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"unreachable_scan\" : ");
		outs << "{\n";
		ModuleScanReport::toJSON(outs, level);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}
};

class SkippedModuleReport : public ModuleScanReport
{
public:
	SkippedModuleReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize, SCAN_NOT_SUSPICIOUS)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"skipped_scan\" : ");
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}
};


class MalformedHeaderReport : public ModuleScanReport
{
public:
	MalformedHeaderReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize, SCAN_SUSPICIOUS)
	{
	}

	const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
	{
		OUT_PADDED(outs, level, "\"malformed_header\" : ");
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << "\n";
		OUT_PADDED(outs, level, "}");
		return true;
	}
};

