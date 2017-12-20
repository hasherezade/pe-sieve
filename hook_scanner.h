#pragma once
#include <Windows.h>
#include <vector>

#include "scanner.h"

class HookScanner : public ModuleScanner {
public:
	HookScanner(HANDLE hProc, std::string dir)
		: ModuleScanner(hProc, dir),
		delimiter(';')
	{
	}

	virtual t_scan_status scanRemote(PBYTE remote_addr, PBYTE original_module, size_t module_size);

private:
	class Patch
	{
	public:
		Patch(size_t patch_id, DWORD start_rva)
			: id(patch_id), startRva(start_rva), endRva(start_rva)
		{
		}

	protected:
		size_t id;
		DWORD startRva;
		DWORD endRva;
	friend class HookScanner;
	};

	std::vector<Patch*> listPatches(DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size);

	bool reportPatch(std::ofstream &patch_report, Patch &patch);

	size_t reportPatches(const std::string file_name, DWORD rva, PBYTE orig_code, PBYTE patched_code, size_t code_size);
	
	bool clearIAT(PIMAGE_SECTION_HEADER section_hdr, PBYTE original_module, PBYTE loaded_code);

	const char delimiter;
};
