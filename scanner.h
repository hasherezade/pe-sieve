#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>

typedef enum module_scan_status {
	SCAN_ERROR = -1,
	SCAN_NOT_MODIFIED = 0,
	SCAN_MODIFIED = 1
} t_scan_status;

std::string make_module_path(MODULEENTRY32 &module_entry, std::string directory, bool is_dll);

class Scanner {
public:
	Scanner(HANDLE procHndl, std::string dir)
		: processHandle(procHndl), directory(dir)
	{
	}

	virtual t_scan_status scanModule(MODULEENTRY32 &module_entry, PBYTE original_module, size_t module_size) = 0;

protected:
	std::string directory;
	HANDLE processHandle;
};


