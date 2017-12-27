#pragma once

#include <Windows.h>

#include "scanner.h"

class HollowingScanner : public ModuleScanner {
public:
	HollowingScanner(HANDLE hProc)
		: ModuleScanner(hProc)
	{
	}

	virtual t_scan_status scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size);

private:
	bool zero_unused_fields(PBYTE hdr_buffer, size_t hdrs_size);
};
