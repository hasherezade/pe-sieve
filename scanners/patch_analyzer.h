#pragma once

#include "module_data.h"
#include "patch_list.h"

class PatchAnalyzer
{
public:
	typedef enum {
		OP_JMP = 0xE9,
		OP_CALL_DWORD = 0xE8,
		OP_PUSH_DWORD = 0x68
	} t_hook_opcode;

	PatchAnalyzer(ModuleData &_moduleData,DWORD _sectionRVA, PBYTE patched_code, size_t code_size)
		: moduleData(_moduleData), sectionRVA(_sectionRVA), patchedCode(patched_code), codeSize(code_size)
	{
		isModule64bit = moduleData.is64bit();
	}

	size_t analyze(PatchList::Patch &patch);

protected:
	size_t parseJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
	size_t parseMovJmp(PatchList::Patch &patch, PBYTE patch_ptr,bool is_long);
	size_t parsePushRet(PatchList::Patch &patch, PBYTE patch_ptr);

	ULONGLONG getJmpDestAddr(ULONGLONG currVA, int instrLen, int lVal);

	bool is64Modifier(BYTE op);
	bool isLongModifier(BYTE op);

	bool isModule64bit;

	ModuleData &moduleData;
	DWORD sectionRVA;
	PBYTE patchedCode;
	size_t codeSize;
};
