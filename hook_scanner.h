#pragma once
#include <Windows.h>
#include <TlHelp32.h>

#include "scanner.h"

class HookScanner : public Scanner {
public:
	HookScanner(HANDLE hProc, std::string dir)
		: Scanner(hProc, dir), delimiter(';')
	{
	}

	virtual t_scan_status scanModule(MODULEENTRY32 &module_entry, PBYTE original_module, size_t module_size);

private:
	size_t reportPatches(const std::string file_name, DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size);
	
	bool clearIAT(PIMAGE_SECTION_HEADER section_hdr, PBYTE original_module, PBYTE loaded_code);

	const char delimiter;
};
