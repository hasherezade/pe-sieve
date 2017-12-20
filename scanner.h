#pragma once

#include <Windows.h>

#include <iostream>

typedef enum module_scan_status {
	SCAN_ERROR = -1,
	SCAN_NOT_MODIFIED = 0,
	SCAN_MODIFIED = 1
} t_scan_status;

std::string make_module_path(ULONGLONG modAddr, std::string directory);

class Scanner {
public:
	Scanner(HANDLE procHndl, std::string dir)
		: processHandle(procHndl), directory(dir)
	{
	}

    virtual t_scan_status scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size) = 0;

protected:
	std::string directory;
	HANDLE processHandle;
};


