#pragma once

#include <Windows.h>

#include <iostream>
#include <sstream>
#include <string>

typedef enum module_scan_status {
	SCAN_ERROR = -1,
	SCAN_NOT_MODIFIED = 0,
	SCAN_MODIFIED = 1
} t_scan_status;

class ModuleScanReport
{
public:
	ModuleScanReport(HANDLE processHandle, HMODULE _module)
	{
		this->pid = GetProcessId(processHandle);
		this->module = _module;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"pid\" : ";
		outs << std::hex << pid << ",\n";
		outs << "\"module\" : ";
		outs << std::hex << (ULONGLONG) module << ",\n";
		outs << "\"status\" : " ;
		outs << status;
		return true;
	}

	virtual ~ModuleScanReport() {}

	HMODULE module;
	DWORD pid;
	t_scan_status status;
};
