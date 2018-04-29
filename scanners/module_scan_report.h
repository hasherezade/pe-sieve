#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "pe_sieve_types.h"
#include "peconv.h"

typedef enum module_scan_status {
	SCAN_ERROR = -1,
	SCAN_NOT_SUSPICIOUS = 0,
	SCAN_SUSPICIOUS = 1
} t_scan_status;

class ModuleScanReport
{
public:
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
	}

	ModuleScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
	{
		this->pid = GetProcessId(processHandle);
		this->module = _module;
		this->moduleSize = _moduleSize;
		this->status = SCAN_NOT_SUSPICIOUS;
	}

	virtual ~ModuleScanReport() {}

	const virtual bool toJSON(std::stringstream &outs)
	{
		//outs << "\"pid\" : ";
		//outs << std::hex << pid << ",\n";
		outs << "\"module\" : ";
		outs << "\"" << std::hex << (ULONGLONG) module << "\"" << ",\n";
		outs << "\"module_size\" : ";
		outs << "\"" << std::hex << moduleSize << "\"" << ",\n";
		outs << "\"status\" : " ;
		outs << std::dec << status;
		return true;
	}

	virtual size_t generateTags(std::string reportPath) { return 0; }

	HMODULE module;
	size_t moduleSize;
	DWORD pid;
	t_scan_status status;
};

class UnreachableModuleReport : public ModuleScanReport
{
public:
	UnreachableModuleReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
		: ModuleScanReport(processHandle, _module, _moduleSize, SCAN_SUSPICIOUS)
	{
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"unreachable_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << "\n}";
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

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"skipped_scan\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << "\n}";
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

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"malformed_header\" : ";
		outs << "{\n";
		ModuleScanReport::toJSON(outs);
		outs << "\n}";
		return true;
	}
};

